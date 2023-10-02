use crate::invalid_bundles_fraud_proof::InvalidBundleProofVerifier;
use crate::invalid_state_transition_proof::{ExecutionProver, InvalidStateTransitionProofVerifier};
use crate::invalid_transaction_proof::InvalidTransactionProofVerifier;
use crate::verifier_api::VerifierApi;
use crate::ProofVerifier;
use codec::Encode;
use domain_block_builder::{BlockBuilder, RecordProof};
use domain_client_operator::aux_schema::InvalidBundlesMismatchType;
use domain_client_operator::fraud_proof::FraudProofGenerator;
use domain_runtime_primitives::opaque::Block as DomainBlock;
use domain_runtime_primitives::{DomainCoreApi, Hash};
use domain_test_service::domain::EvmDomainClient as DomainClient;
use domain_test_service::evm_domain_test_runtime::Header;
use domain_test_service::EcdsaKeyring::{Alice, Bob, Charlie, Dave};
use domain_test_service::Sr25519Keyring::{self, Ferdie};
use domain_test_service::GENESIS_DOMAIN_ID;
use frame_support::assert_ok;
use sc_client_api::{HeaderBackend, StorageProof};
use sc_service::{BasePath, Role};
use sp_api::ProvideRuntimeApi;
use sp_core::{Pair, H256};
use sp_domain_digests::AsPredigest;
use sp_domains::fraud_proof::{
    ExecutionPhase, FraudProof, InvalidBundlesFraudProof, InvalidStateTransitionProof,
    VerificationError,
};
use sp_domains::{DomainId, InvalidBundle, InvalidBundleType};
use sp_runtime::generic::{Digest, DigestItem};
use sp_runtime::traits::{BlakeTwo256, Header as HeaderT};
use std::sync::Arc;
use subspace_core_primitives::U256;
use subspace_runtime_primitives::opaque::Block;
use subspace_test_client::Client;
use subspace_test_runtime::test_runtime_extension::pallet_test_override;
use subspace_test_service::{produce_block_with, produce_blocks, MockConsensusNode};
use tempfile::TempDir;

struct TestVerifierClient {
    consensus_client: Arc<Client>,
    domain_client: Arc<DomainClient>,
}

impl TestVerifierClient {
    fn new(consensus_client: Arc<Client>, domain_client: Arc<DomainClient>) -> Self {
        Self {
            consensus_client,
            domain_client,
        }
    }
}

impl VerifierApi for TestVerifierClient {
    fn verify_pre_state_root(
        &self,
        _invalid_state_transition_proof: &InvalidStateTransitionProof,
    ) -> Result<(), VerificationError> {
        Ok(())
    }

    fn verify_post_state_root(
        &self,
        _invalid_state_transition_proof: &InvalidStateTransitionProof,
    ) -> Result<(), VerificationError> {
        Ok(())
    }

    fn primary_hash(
        &self,
        _domain_id: DomainId,
        domain_block_number: u32,
    ) -> Result<H256, VerificationError> {
        // TODO: remove this workaround impl once the following tests are improved/superseded by
        // something close to the real work flow in production.
        //
        // This is retrieved from the `PrimaryBlockHash` state on the parent chain in
        // production, we retrieve it from the primary chain client in test for simplicity.
        Ok(self
            .consensus_client
            .hash(domain_block_number)
            .unwrap()
            .unwrap())
    }

    fn state_root(
        &self,
        _domain_id: DomainId,
        _domain_block_number: u32,
        domain_block_hash: H256,
    ) -> Result<Hash, VerificationError> {
        Ok(*self
            .domain_client
            .header(domain_block_hash)
            .unwrap()
            .unwrap()
            .state_root())
    }
}

// Use the system domain id for testing
const TEST_DOMAIN_ID: DomainId = DomainId::new(3u32);

#[tokio::test(flavor = "multi_thread")]
async fn test_valid_bundle_proof_generation_and_verification() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    let change_tx_range = |new_range| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_test_override::Call::override_tx_range { new_range }.into(),
        )
        .into()
    };

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Produce 1 consensus block to initialize genesis domain
    ferdie.produce_block_with_slot(1.into()).await.unwrap();

    // Run Alice (a evm domain authority node)
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    let fraud_proof_generator = FraudProofGenerator::new(
        alice.client.clone(),
        ferdie.client.clone(),
        alice.backend.clone(),
        alice.code_executor.clone(),
    );
    let invalid_bundle_proof_verifier = InvalidBundleProofVerifier::<_, DomainBlock, _, _>::new(
        ferdie.client.clone(),
        alice.code_executor.clone(),
    );

    for i in 0..3 {
        let tx = alice.construct_extrinsic(
            alice.account_nonce() + i,
            pallet_balances::Call::transfer_allow_death {
                dest: Bob.to_account_id(),
                value: 1,
            },
        );
        alice
            .send_extrinsic(tx)
            .await
            .expect("Failed to send extrinsic");

        // Produce a bundle and submit to the tx pool of the consensus node
        let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        assert!(bundle.is_some());

        // In the last iteration, produce a consensus block which will included all the previous bundles
        if i == 2 {
            ferdie
                .submit_transaction(change_tx_range(U256::one()))
                .await
                .unwrap();

            produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
                .await
                .unwrap();
        }
    }

    let bundle_to_tx = |opaque_bundle| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        )
        .into()
    };

    // Produce a bundle that will include the reciept of the last 3 bundles and modified the receipt's
    // `valid_bundles` field to make it invalid
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());
    let bundle_index = 0;
    let (bad_receipt, valid_receipt, submit_bundle_tx_with_bad_receipt) = {
        let mut bundle = bundle.clone().unwrap();
        let valid_receipt = bundle.receipt().clone();
        assert_eq!(valid_receipt.valid_bundles.len(), 0);
        assert_eq!(valid_receipt.invalid_bundles.len(), 3);
        for invalid_bundle in valid_receipt.invalid_bundles.iter() {
            assert_eq!(
                invalid_bundle.invalid_bundle_type,
                InvalidBundleType::OutOfRangeTx
            );
        }

        bundle.sealed_header.header.receipt.invalid_bundles[0] = InvalidBundle {
            bundle_index: bundle.sealed_header.header.receipt.invalid_bundles[0].bundle_index,
            invalid_bundle_type: InvalidBundleType::IllegalTx,
        };

        bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(bundle.sealed_header.pre_hash().as_ref())
            .into();

        (
            bundle.receipt().clone(),
            valid_receipt,
            bundle_to_tx(bundle),
        )
    };
    // Replace `original_submit_bundle_tx` with `submit_bundle_tx_with_bad_receipt` in the tx pool
    ferdie
        .prune_tx_from_pool(&original_submit_bundle_tx)
        .await
        .unwrap();
    assert!(ferdie.get_bundle_from_tx_pool(slot.into()).is_none());
    ferdie
        .submit_transaction(submit_bundle_tx_with_bad_receipt)
        .await
        .unwrap();

    // Produce one more block to inlcude the bad receipt in the consensus chain
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // TODO: let the operator construct the valid bundle fraud proof by it own once the `valid_bundles`
    // fraud detection is implemented
    let invalid_bundle_proof = fraud_proof_generator
        .generate_invalid_bundle_field_proof(
            GENESIS_DOMAIN_ID,
            &valid_receipt,
            InvalidBundlesMismatchType::InvalidAsValid,
            bundle_index as u32,
            bad_receipt.hash(),
        )
        .unwrap();

    match invalid_bundle_proof {
        FraudProof::InvalidBundles(InvalidBundlesFraudProof::MissingInvalidBundleEntry(
            inner_proof,
        )) => {
            // If the fraud proof target a valid bundle it is considered invalid
            let mut bad_proof = inner_proof.clone();
            bad_proof.bundle_index = 1;
            assert!(invalid_bundle_proof_verifier
                .verify(&InvalidBundlesFraudProof::MissingInvalidBundleEntry(
                    bad_proof,
                ))
                .is_err());

            // If the fraud proof point to non-exist bundle then it is invalid
            let mut bad_proof = inner_proof.clone();
            bad_proof.opaque_bundle_with_proof.bundle.extrinsics = Default::default();
            assert!(invalid_bundle_proof_verifier
                .verify(&InvalidBundlesFraudProof::MissingInvalidBundleEntry(
                    bad_proof,
                ))
                .is_err());

            // The original fraud proof is valid
            assert_ok!(invalid_bundle_proof_verifier.verify(
                &InvalidBundlesFraudProof::MissingInvalidBundleEntry(inner_proof,)
            ));
        }
        _ => unreachable!("Unexpected fraud proof"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn execution_proof_creation_and_verification_should_work() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    // Run Bob (a evm domain full node)
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle,
        Bob,
        BasePath::new(directory.path().join("bob")),
    )
    .build_evm_node(Role::Full, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    // Bob is able to sync blocks.
    produce_blocks!(ferdie, alice, 1, bob).await.unwrap();

    let alice_nonce = alice.account_nonce();
    let transfer_to_charlie = alice.construct_extrinsic(
        alice_nonce,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 8,
        },
    );
    let transfer_to_dave = alice.construct_extrinsic(
        alice_nonce + 1,
        pallet_balances::Call::transfer_allow_death {
            dest: Dave.to_account_id(),
            value: 8,
        },
    );
    let transfer_to_charlie_again = alice.construct_extrinsic(
        alice_nonce + 2,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 88,
        },
    );

    let test_txs = vec![
        transfer_to_charlie.clone(),
        transfer_to_dave.clone(),
        transfer_to_charlie_again.clone(),
    ];

    for tx in test_txs.iter() {
        alice
            .send_extrinsic(tx.clone())
            .await
            .expect("Failed to send extrinsic");
    }

    // Produce a domain bundle to include the above test txs and wait for `alice`
    // to apply these txs
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert!(bundle.is_some());
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    let best_hash = alice.client.info().best_hash;
    let header = alice.client.header(best_hash).unwrap().unwrap();
    let parent_header = alice.client.header(*header.parent_hash()).unwrap().unwrap();

    let create_block_builder = || {
        let primary_hash = ferdie.client.hash(*header.number()).unwrap().unwrap();
        let digest = Digest {
            logs: vec![DigestItem::consensus_block_info((
                *header.number(),
                primary_hash,
            ))],
        };
        BlockBuilder::new(
            &*alice.client,
            parent_header.hash(),
            *parent_header.number(),
            RecordProof::No,
            digest,
            &*alice.backend,
            test_txs.clone().into_iter().map(Into::into).collect(),
        )
        .unwrap()
    };

    let intermediate_roots = alice
        .client
        .runtime_api()
        .intermediate_roots(best_hash)
        .expect("Get intermediate roots");

    if intermediate_roots.len() != test_txs.len() + 1 {
        panic!(
            "🐛 ERROR: runtime API `intermediate_roots()` obviously returned a wrong result, intermediate_roots: {:?}",
            intermediate_roots.into_iter().map(Hash::from).collect::<Vec<_>>(),
        );
    }

    let primary_hash = ferdie.client.hash(*header.number()).unwrap().unwrap();
    let new_header = Header::new(
        *header.number(),
        Default::default(),
        Default::default(),
        parent_header.hash(),
        Digest {
            logs: vec![DigestItem::consensus_block_info((
                *header.number(),
                primary_hash,
            ))],
        },
    );
    let execution_phase = ExecutionPhase::InitializeBlock {
        domain_parent_hash: parent_header.hash(),
    };
    let initialize_block_call_data = new_header.encode();

    let prover = ExecutionProver::new(alice.backend.clone(), alice.code_executor.clone());

    // Test `initialize_block`.
    let storage_proof = prover
        .prove_execution::<sp_trie::PrefixedMemoryDB<BlakeTwo256>>(
            parent_header.hash(),
            &execution_phase,
            &initialize_block_call_data,
            None,
        )
        .expect("Create `initialize_block` proof");

    // Test `initialize_block` verification.
    let execution_result = prover
        .check_execution_proof(
            parent_header.hash(),
            &execution_phase,
            &initialize_block_call_data,
            *parent_header.state_root(),
            storage_proof.clone(),
        )
        .expect("Check `initialize_block` proof");
    let post_execution_root = execution_phase
        .decode_execution_result::<Header>(execution_result)
        .unwrap();
    assert_eq!(post_execution_root, intermediate_roots[0].into());

    let invalid_state_transition_proof_verifier = InvalidStateTransitionProofVerifier::new(
        ferdie.client.clone(),
        ferdie.executor.clone(),
        TestVerifierClient::new(ferdie.client.clone(), alice.client.clone()),
    );

    let invalid_transaction_proof_verifier = InvalidTransactionProofVerifier::new(
        ferdie.client.clone(),
        Arc::new(ferdie.executor.clone()),
        TestVerifierClient::new(ferdie.client.clone(), alice.client.clone()),
    );

    let invalid_bundle_proof_verifier =
        InvalidBundleProofVerifier::new(ferdie.client.clone(), Arc::new(ferdie.executor.clone()));

    let proof_verifier = ProofVerifier::<Block, DomainBlock, _, _, _>::new(
        Arc::new(invalid_transaction_proof_verifier),
        Arc::new(invalid_state_transition_proof_verifier),
        Arc::new(invalid_bundle_proof_verifier),
    );

    let parent_number_alice = *parent_header.number();
    let consensus_parent_hash = ferdie.client.hash(parent_number_alice).unwrap().unwrap();

    let invalid_state_transition_proof = InvalidStateTransitionProof {
        domain_id: TEST_DOMAIN_ID,
        bad_receipt_hash: Hash::random(),
        parent_number: parent_number_alice,
        consensus_parent_hash,
        pre_state_root: *parent_header.state_root(),
        post_state_root: intermediate_roots[0].into(),
        proof: storage_proof,
        execution_phase,
    };
    let fraud_proof = FraudProof::InvalidStateTransition(invalid_state_transition_proof);
    assert!(proof_verifier.verify(&fraud_proof).is_ok());

    // Test extrinsic execution.
    for (target_extrinsic_index, xt) in test_txs.clone().into_iter().enumerate() {
        let storage_changes = create_block_builder()
            .prepare_storage_changes_before(target_extrinsic_index)
            .unwrap_or_else(|_| {
                panic!("Get StorageChanges before extrinsic #{target_extrinsic_index}")
            });

        let delta = storage_changes.transaction;
        let post_delta_root = storage_changes.transaction_storage_root;

        let execution_phase = ExecutionPhase::ApplyExtrinsic(target_extrinsic_index as u32);
        let apply_extrinsic_call_data = xt.encode();

        let storage_proof = prover
            .prove_execution(
                parent_header.hash(),
                &execution_phase,
                &apply_extrinsic_call_data,
                Some((delta, post_delta_root)),
            )
            .expect("Create extrinsic execution proof");

        let target_trace_root: Hash = intermediate_roots[target_extrinsic_index].into();
        assert_eq!(target_trace_root, post_delta_root);

        // Test `apply_extrinsic` verification.
        let execution_result = prover
            .check_execution_proof(
                parent_header.hash(),
                &execution_phase,
                &apply_extrinsic_call_data,
                post_delta_root,
                storage_proof.clone(),
            )
            .expect("Check extrinsic execution proof");
        let post_execution_root = execution_phase
            .decode_execution_result::<Header>(execution_result)
            .unwrap();
        assert_eq!(
            post_execution_root,
            intermediate_roots[target_extrinsic_index + 1].into()
        );

        let invalid_state_transition_proof = InvalidStateTransitionProof {
            domain_id: TEST_DOMAIN_ID,
            bad_receipt_hash: Hash::random(),
            parent_number: parent_number_alice,
            consensus_parent_hash,
            pre_state_root: intermediate_roots[target_extrinsic_index].into(),
            post_state_root: intermediate_roots[target_extrinsic_index + 1].into(),
            proof: storage_proof,
            execution_phase,
        };
        let fraud_proof = FraudProof::InvalidStateTransition(invalid_state_transition_proof);
        assert!(proof_verifier.verify(&fraud_proof).is_ok());
    }

    // Test `finalize_block`
    let storage_changes = create_block_builder()
        .prepare_storage_changes_before_finalize_block()
        .expect("Get StorageChanges before `finalize_block`");

    let delta = storage_changes.transaction;
    let post_delta_root = storage_changes.transaction_storage_root;

    assert_eq!(post_delta_root, intermediate_roots.last().unwrap().into());

    let execution_phase = ExecutionPhase::FinalizeBlock {
        total_extrinsics: test_txs.len() as u32,
    };
    let finalize_block_call_data = Vec::new();

    let storage_proof = prover
        .prove_execution(
            parent_header.hash(),
            &execution_phase,
            &finalize_block_call_data,
            Some((delta, post_delta_root)),
        )
        .expect("Create `finalize_block` proof");

    // Test `finalize_block` verification.
    let execution_result = prover
        .check_execution_proof(
            parent_header.hash(),
            &execution_phase,
            &finalize_block_call_data,
            post_delta_root,
            storage_proof.clone(),
        )
        .expect("Check `finalize_block` proof");
    let post_execution_root = execution_phase
        .decode_execution_result::<Header>(execution_result)
        .unwrap();
    assert_eq!(post_execution_root, *header.state_root());

    let invalid_state_transition_proof = InvalidStateTransitionProof {
        domain_id: TEST_DOMAIN_ID,
        bad_receipt_hash: Hash::random(),
        parent_number: parent_number_alice,
        consensus_parent_hash,
        pre_state_root: intermediate_roots.last().unwrap().into(),
        post_state_root: post_execution_root,
        proof: storage_proof,
        execution_phase,
    };
    let fraud_proof = FraudProof::InvalidStateTransition(invalid_state_transition_proof);
    assert!(proof_verifier.verify(&fraud_proof).is_ok());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn invalid_execution_proof_should_not_work() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    // Run Bob (a evm domain full node)
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle,
        Bob,
        BasePath::new(directory.path().join("bob")),
    )
    .build_evm_node(Role::Full, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    // Bob is able to sync blocks.
    produce_blocks!(ferdie, alice, 1, bob).await.unwrap();

    let alice_nonce = alice.account_nonce();
    let transfer_to_charlie = alice.construct_extrinsic(
        alice_nonce,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 8,
        },
    );
    let transfer_to_charlie_again = alice.construct_extrinsic(
        alice_nonce + 1,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 8,
        },
    );

    let test_txs = vec![
        transfer_to_charlie.clone(),
        transfer_to_charlie_again.clone(),
    ];

    for tx in test_txs.iter() {
        alice
            .send_extrinsic(tx.clone())
            .await
            .expect("Failed to send extrinsic");
    }

    // Produce a domain bundle to include the above test tx
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert!(bundle.is_some());

    // Wait for `alice` to apply these txs
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    let best_hash = alice.client.info().best_hash;
    let header = alice.client.header(best_hash).unwrap().unwrap();
    let parent_header = alice.client.header(*header.parent_hash()).unwrap().unwrap();

    let create_block_builder = || {
        BlockBuilder::new(
            &*alice.client,
            parent_header.hash(),
            *parent_header.number(),
            RecordProof::No,
            Digest {
                logs: vec![DigestItem::consensus_block_info((
                    *header.number(),
                    header.hash(),
                ))],
            },
            &*alice.backend,
            test_txs.clone().into_iter().map(Into::into).collect(),
        )
        .unwrap()
    };

    let prover = ExecutionProver::new(alice.backend.clone(), alice.code_executor.clone());

    let create_extrinsic_proof = |extrinsic_index: usize| {
        let storage_changes = create_block_builder()
            .prepare_storage_changes_before(extrinsic_index)
            .unwrap_or_else(|_| panic!("Get StorageChanges before extrinsic #{extrinsic_index}"));

        let delta = storage_changes.transaction;
        let post_delta_root = storage_changes.transaction_storage_root;

        let execution_phase = ExecutionPhase::ApplyExtrinsic(extrinsic_index as u32);
        let apply_extrinsic_call_data = test_txs[extrinsic_index].encode();

        let proof = prover
            .prove_execution(
                parent_header.hash(),
                &execution_phase,
                &apply_extrinsic_call_data,
                Some((delta, post_delta_root)),
            )
            .expect("Create extrinsic execution proof");

        (proof, post_delta_root, execution_phase)
    };

    let (proof0, post_delta_root0, execution_phase0) = create_extrinsic_proof(0);
    let (proof1, post_delta_root1, execution_phase1) = create_extrinsic_proof(1);

    let check_proof_executor = |post_delta_root: Hash, proof: StorageProof| {
        let execution_phase = ExecutionPhase::ApplyExtrinsic(1u32);
        let apply_extrinsic_call_data = transfer_to_charlie_again.encode();
        prover.check_execution_proof(
            parent_header.hash(),
            &execution_phase,
            &apply_extrinsic_call_data,
            post_delta_root,
            proof,
        )
    };

    assert!(check_proof_executor(post_delta_root1, proof0.clone()).is_err());
    assert!(check_proof_executor(post_delta_root0, proof1.clone()).is_err());
    assert!(check_proof_executor(post_delta_root0, proof0.clone()).is_ok());
    assert!(check_proof_executor(post_delta_root1, proof1.clone()).is_ok());

    let invalid_state_transition_proof_verifier = InvalidStateTransitionProofVerifier::new(
        ferdie.client.clone(),
        ferdie.executor.clone(),
        TestVerifierClient::new(ferdie.client.clone(), alice.client.clone()),
    );

    let invalid_transaction_proof_verifier = InvalidTransactionProofVerifier::new(
        ferdie.client.clone(),
        Arc::new(ferdie.executor.clone()),
        TestVerifierClient::new(ferdie.client.clone(), alice.client.clone()),
    );

    let invalid_bundle_proof_verifier =
        InvalidBundleProofVerifier::new(ferdie.client.clone(), Arc::new(ferdie.executor.clone()));

    let proof_verifier = ProofVerifier::<Block, DomainBlock, _, _, _>::new(
        Arc::new(invalid_transaction_proof_verifier),
        Arc::new(invalid_state_transition_proof_verifier),
        Arc::new(invalid_bundle_proof_verifier),
    );

    let parent_number_alice = *parent_header.number();
    let consensus_parent_hash = ferdie.client.hash(parent_number_alice).unwrap().unwrap();

    let invalid_state_transition_proof = InvalidStateTransitionProof {
        domain_id: TEST_DOMAIN_ID,
        bad_receipt_hash: Hash::random(),
        parent_number: parent_number_alice,
        consensus_parent_hash,
        pre_state_root: post_delta_root0,
        post_state_root: post_delta_root1,
        proof: proof1,
        execution_phase: execution_phase0.clone(),
    };
    let fraud_proof = FraudProof::InvalidStateTransition(invalid_state_transition_proof);
    assert!(proof_verifier.verify(&fraud_proof).is_err());

    let invalid_state_transition_proof = InvalidStateTransitionProof {
        domain_id: TEST_DOMAIN_ID,
        bad_receipt_hash: Hash::random(),
        parent_number: parent_number_alice,
        consensus_parent_hash,
        pre_state_root: post_delta_root0,
        post_state_root: post_delta_root1,
        proof: proof0.clone(),
        execution_phase: execution_phase1,
    };
    let fraud_proof = FraudProof::InvalidStateTransition(invalid_state_transition_proof);
    assert!(proof_verifier.verify(&fraud_proof).is_err());

    let invalid_state_transition_proof = InvalidStateTransitionProof {
        domain_id: TEST_DOMAIN_ID,
        bad_receipt_hash: Hash::random(),
        parent_number: parent_number_alice,
        consensus_parent_hash,
        pre_state_root: post_delta_root0,
        post_state_root: post_delta_root1,
        proof: proof0,
        execution_phase: execution_phase0,
    };
    let fraud_proof = FraudProof::InvalidStateTransition(invalid_state_transition_proof);
    assert!(proof_verifier.verify(&fraud_proof).is_ok());
}

// TODO: Unlock test when gossip message validator are supported in DecEx v2.
// #[tokio::test(flavor = "multi_thread")]
// async fn test_invalid_transaction_proof_creation_and_verification() {
//     let directory = TempDir::new().expect("Must be able to create temporary directory");

//     let mut builder = sc_cli::LoggerBuilder::new("runtime=debug");
//     builder.with_colors(false);
//     let _ = builder.init();

//     let tokio_handle = tokio::runtime::Handle::current();

//     // Start Ferdie
//     let mut ferdie = MockConsensusNode::run(
//         tokio_handle.clone(),
//         Ferdie,
//         BasePath::new(directory.path().join("ferdie")),
//     );

//     // Run Alice (a system domain authority node)
//     let mut alice = domain_test_service::DomainNodeBuilder::new(
//         tokio_handle.clone(),
//         Alice,
//         BasePath::new(directory.path().join("alice")),
//     )
//     .build_evm_node(Role::Authority, &mut ferdie)
//     .await;

//     produce_blocks!(ferdie, alice, 3).await.unwrap();

//     alice
//         .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
//             dest: domain_test_service::evm_domain_test_runtime::Address::Id(One.public().into()),
//             value: 500 + 1,
//         })
//         .await
//         .expect("Send an extrinsic to transfer some balance from Alice to One");

//     ferdie.produce_slot_and_wait_for_bundle_submission().await;

//     produce_blocks!(ferdie, alice, 1).await.unwrap();

//     let (_slot, maybe_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

//     produce_blocks!(ferdie, alice, 3).await.unwrap();

//     // This is an invalid transaction.
//     let transfer_from_one_to_bob = alice.construct_extrinsic_with_caller(
//         One,
//         pallet_balances::Call::transfer_allow_death {
//             dest: domain_test_service::evm_domain_test_runtime::Address::Id(Bob.public().into()),
//             value: 1000,
//         },
//     );

//     let mut bundle_with_bad_extrinsics = maybe_bundle.unwrap();
//     bundle_with_bad_extrinsics.extrinsics =
//         vec![OpaqueExtrinsic::from_bytes(&transfer_from_one_to_bob.encode()).unwrap()];
//     bundle_with_bad_extrinsics.sealed_header.signature = alice
//         .key
//         .pair()
//         .sign(bundle_with_bad_extrinsics.sealed_header.pre_hash().as_ref())
//         .into();

//     alice
//         .gossip_message_validator
//         .validate_gossiped_bundle(&bundle_with_bad_extrinsics)
//         .expect("Create an invalid transaction proof and submit to tx pool");

//     let extract_fraud_proof_from_tx_pool = || {
//         let ready_txs = ferdie
//             .transaction_pool
//             .pool()
//             .validated_pool()
//             .ready()
//             .collect::<Vec<_>>();

//         ready_txs
//             .into_iter()
//             .find_map(|ready_tx| {
//                 let uxt = subspace_test_runtime::UncheckedExtrinsic::decode(
//                     &mut ready_tx.data.encode().as_slice(),
//                 )
//                 .unwrap();
//                 match uxt.function {
//                     subspace_test_runtime::RuntimeCall::Domains(
//                         pallet_domains::Call::submit_fraud_proof { fraud_proof },
//                     ) => Some(fraud_proof),
//                     _ => None,
//                 }
//             })
//             .expect("Can not find submit_fraud_proof extrinsic")
//     };

//     let good_invalid_transaction_proof = extract_fraud_proof_from_tx_pool();

//     let invalid_state_transition_proof_verifier = InvalidStateTransitionProofVerifier::new(
//         ferdie.client.clone(),
//         ferdie.executor.clone(),
//         TestVerifierClient::new(ferdie.client.clone(), alice.client.clone()),
//     );

//     let invalid_transaction_proof_verifier = InvalidTransactionProofVerifier::new(
//         ferdie.client.clone(),
//         Arc::new(ferdie.executor.clone()),
//         TestVerifierClient::new(ferdie.client.clone(), alice.client.clone()),
//     );

//     let proof_verifier = ProofVerifier::<Block, _, _>::new(
//         Arc::new(invalid_transaction_proof_verifier),
//         Arc::new(invalid_state_transition_proof_verifier),
//     );

//     assert!(
//         proof_verifier
//             .verify(&good_invalid_transaction_proof)
//             .is_ok(),
//         "Valid proof must be accepeted"
//     );

//     ferdie
//         .produce_blocks(1)
//         .await
//         .expect("FraudProof verification in the block import pipeline is fine too");
// }

#![allow(unused_imports, unused_variables)]
use crate::invalid_state_transition_proof::SkipPreStateRootVerification;
use crate::{ExecutionProver, ProofVerifier};
use codec::Encode;
use domain_block_builder::{BlockBuilder, RecordProof};
use domain_runtime_primitives::{DomainCoreApi, Hash};
use domain_test_service::run_primary_chain_validator_node;
use domain_test_service::runtime::Header;
use domain_test_service::Keyring::{Alice, Bob, Charlie, Dave, Ferdie};
use sc_client_api::{HeaderBackend, StorageProof};
use sc_service::{BasePath, Role};
use sp_api::ProvideRuntimeApi;
use sp_domain_digests::AsPredigest;
use sp_domains::fraud_proof::{ExecutionPhase, FraudProof, InvalidStateTransitionProof};
use sp_domains::DomainId;
use sp_runtime::generic::{Digest, DigestItem};
use sp_runtime::traits::{BlakeTwo256, Header as HeaderT};
use subspace_runtime_primitives::opaque::Block;
use subspace_test_service::mock::MockPrimaryNode;
use tempfile::TempDir;

// Use the system domain id for testing
const TEST_DOMAIN_ID: DomainId = DomainId::SYSTEM;

#[substrate_test_utils::test(flavor = "multi_thread")]
#[ignore]
async fn execution_proof_creation_and_verification_should_work() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let (ferdie, ferdie_network_starter) = run_primary_chain_validator_node(
        tokio_handle.clone(),
        Ferdie,
        vec![],
        BasePath::new(directory.path().join("ferdie")),
    )
    .await;
    ferdie_network_starter.start_network();

    // Run Alice (a system domain authority node)
    let alice = domain_test_service::SystemDomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .connect_to_primary_chain_node(&ferdie)
    .build(Role::Authority, false, false)
    .await;

    // Run Bob (a system domain full node)
    let bob = domain_test_service::SystemDomainNodeBuilder::new(
        tokio_handle,
        Bob,
        BasePath::new(directory.path().join("bob")),
    )
    .connect_to_primary_chain_node(&ferdie)
    .build(Role::Full, false, false)
    .await;

    // Bob is able to sync blocks.
    futures::future::join(alice.wait_for_blocks(1), bob.wait_for_blocks(1)).await;

    let transfer_to_charlie = domain_test_service::construct_extrinsic(
        &alice.client,
        pallet_balances::Call::transfer {
            dest: domain_test_service::runtime::Address::Id(Charlie.public().into()),
            value: 8,
        },
        Alice,
        false,
        0,
    );
    let transfer_to_dave = domain_test_service::construct_extrinsic(
        &alice.client,
        pallet_balances::Call::transfer {
            dest: domain_test_service::runtime::Address::Id(Dave.public().into()),
            value: 8,
        },
        Alice,
        false,
        1,
    );
    let transfer_to_charlie_again = domain_test_service::construct_extrinsic(
        &alice.client,
        pallet_balances::Call::transfer {
            dest: domain_test_service::runtime::Address::Id(Charlie.public().into()),
            value: 88,
        },
        Alice,
        false,
        2,
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

    // Ideally we just need to wait one block and the test txs should be all included
    // in the next block, but the txs are probably unable to be included if the machine
    // is overloaded, hence we manually mock the bundles processing to avoid the occasional
    // test failure (https://github.com/subspace/subspace/runs/5663241460?check_suite_focus=true).
    //
    // alice.wait_for_blocks(1).await;

    let primary_info = (
        ferdie.client.info().best_hash,
        ferdie.client.info().best_number,
    );
    alice.executor.clone().process_bundles(primary_info).await;

    let best_hash = alice.client.info().best_hash;
    let header = alice.client.header(best_hash).unwrap().unwrap();
    let parent_header = alice.client.header(*header.parent_hash()).unwrap().unwrap();

    let create_block_builder = || {
        BlockBuilder::new(
            &*alice.client,
            parent_header.hash(),
            *parent_header.number(),
            RecordProof::No,
            Default::default(),
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

    let new_header = Header::new(
        *header.number(),
        Default::default(),
        Default::default(),
        parent_header.hash(),
        Default::default(),
    );
    let execution_phase = ExecutionPhase::InitializeBlock {
        domain_parent_hash: parent_header.hash(),
    };
    let initialize_block_call_data = new_header.encode();

    let prover = ExecutionProver::new(
        alice.backend.clone(),
        alice.code_executor.clone(),
        Box::new(alice.task_manager.spawn_handle()),
    );

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

    let proof_verifier = ProofVerifier::<Block, _, _, _, _, _, _>::new(
        ferdie.client.clone(),
        ferdie.executor.clone(),
        ferdie.task_manager.spawn_handle(),
        SkipPreStateRootVerification,
    );

    // Incorrect but it's fine for the test purpose.
    let parent_hash_alice = ferdie.client.info().best_hash;
    let parent_number_alice = ferdie.client.info().best_number;

    let invalid_state_transition_proof = InvalidStateTransitionProof {
        domain_id: TEST_DOMAIN_ID,
        bad_receipt_hash: Hash::random(),
        parent_number: parent_number_alice,
        primary_parent_hash: parent_hash_alice,
        pre_state_root: *parent_header.state_root(),
        post_state_root: intermediate_roots[0].into(),
        proof: storage_proof,
        execution_phase,
    };
    // TODO: re-enable when #1230 resolves
    // let fraud_proof = FraudProof::InvalidStateTransition(invalid_state_transition_proof);
    // assert!(proof_verifier.verify(&fraud_proof).is_ok());

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
            primary_parent_hash: parent_hash_alice,
            pre_state_root: intermediate_roots[target_extrinsic_index].into(),
            post_state_root: intermediate_roots[target_extrinsic_index + 1].into(),
            proof: storage_proof,
            execution_phase,
        };
        // TODO: re-enable when #1230 resolves
        // let fraud_proof = FraudProof::InvalidStateTransition(invalid_state_transition_proof);
        // assert!(proof_verifier.verify(&fraud_proof).is_ok());
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
        primary_parent_hash: parent_hash_alice,
        pre_state_root: intermediate_roots.last().unwrap().into(),
        post_state_root: post_execution_root,
        proof: storage_proof,
        execution_phase,
    };
    // TODO: re-enable when #1230 resolves
    // let fraud_proof = FraudProof::InvalidStateTransition(invalid_state_transition_proof);
    // assert!(proof_verifier.verify(&fraud_proof).is_ok());
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn invalid_execution_proof_should_not_work() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockPrimaryNode::run_mock_primary_node(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a system domain authority node)
    let alice = domain_test_service::SystemDomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_with_mock_primary_node(Role::Authority, &mut ferdie)
    .await;

    // Run Bob (a system domain full node)
    let bob = domain_test_service::SystemDomainNodeBuilder::new(
        tokio_handle,
        Bob,
        BasePath::new(directory.path().join("bob")),
    )
    .build_with_mock_primary_node(Role::Full, &mut ferdie)
    .await;

    // Bob is able to sync blocks.
    futures::join!(
        alice.wait_for_blocks(1),
        bob.wait_for_blocks(1),
        ferdie.produce_blocks(1),
    )
    .2
    .unwrap();

    let transfer_to_charlie = domain_test_service::construct_extrinsic(
        &alice.client,
        pallet_balances::Call::transfer {
            dest: domain_test_service::runtime::Address::Id(Charlie.public().into()),
            value: 8,
        },
        Alice,
        false,
        0,
    );

    let transfer_to_charlie_again = domain_test_service::construct_extrinsic(
        &alice.client,
        pallet_balances::Call::transfer {
            dest: domain_test_service::runtime::Address::Id(Charlie.public().into()),
            value: 8,
        },
        Alice,
        false,
        1,
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
    let slot = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert!(ferdie.is_bundle_present_in_tx_pool(slot.into(), alice.key));

    // Wait for `alice` to apply these txs
    futures::future::join(
        alice.wait_for_blocks(1),
        ferdie.produce_block_with_slot(slot),
    )
    .await
    .1
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
                logs: vec![DigestItem::primary_block_info((
                    *header.number(),
                    header.hash(),
                ))],
            },
            &*alice.backend,
            test_txs.clone().into_iter().map(Into::into).collect(),
        )
        .unwrap()
    };

    let prover = ExecutionProver::new(
        alice.backend.clone(),
        alice.code_executor.clone(),
        Box::new(alice.task_manager.spawn_handle()),
    );

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

    let proof_verifier = ProofVerifier::<Block, _, _, _, _, _, _>::new(
        ferdie.client.clone(),
        ferdie.executor.clone(),
        ferdie.task_manager.spawn_handle(),
        SkipPreStateRootVerification,
    );

    // Incorrect but it's fine for the test purpose.
    let parent_hash_alice = ferdie.client.info().best_hash;
    let parent_number_alice = ferdie.client.info().best_number;

    let invalid_state_transition_proof = InvalidStateTransitionProof {
        domain_id: TEST_DOMAIN_ID,
        bad_receipt_hash: Hash::random(),
        parent_number: parent_number_alice,
        primary_parent_hash: parent_hash_alice,
        pre_state_root: post_delta_root0,
        post_state_root: post_delta_root1,
        proof: proof1,
        execution_phase: execution_phase0.clone(),
    };
    // TODO: re-enable when #1230 resolves
    // let fraud_proof = FraudProof::InvalidStateTransition(invalid_state_transition_proof);
    // assert!(proof_verifier.verify(&fraud_proof).is_err());

    let invalid_state_transition_proof = InvalidStateTransitionProof {
        domain_id: TEST_DOMAIN_ID,
        bad_receipt_hash: Hash::random(),
        parent_number: parent_number_alice,
        primary_parent_hash: parent_hash_alice,
        pre_state_root: post_delta_root0,
        post_state_root: post_delta_root1,
        proof: proof0.clone(),
        execution_phase: execution_phase1,
    };
    // TODO: re-enable when #1230 resolves
    // let fraud_proof = FraudProof::InvalidStateTransition(invalid_state_transition_proof);
    // assert!(proof_verifier.verify(&fraud_proof).is_err());

    let invalid_state_transition_proof = InvalidStateTransitionProof {
        domain_id: TEST_DOMAIN_ID,
        bad_receipt_hash: Hash::random(),
        parent_number: parent_number_alice,
        primary_parent_hash: parent_hash_alice,
        pre_state_root: post_delta_root0,
        post_state_root: post_delta_root1,
        proof: proof0,
        execution_phase: execution_phase0,
    };
    // TODO: re-enable when #1230 resolves
    // let fraud_proof = FraudProof::InvalidStateTransition(invalid_state_transition_proof);
    // assert!(proof_verifier.verify(&fraud_proof).is_ok());
}

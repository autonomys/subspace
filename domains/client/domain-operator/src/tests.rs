use codec::{Decode, Encode};
use domain_runtime_primitives::{DomainCoreApi, Hash};
use domain_test_primitives::TimestampApi;
use domain_test_service::evm_domain_test_runtime::{Header, UncheckedExtrinsic};
use domain_test_service::EcdsaKeyring::{Alice, Bob};
use domain_test_service::Sr25519Keyring::{self, Ferdie};
use futures::StreamExt;
use sc_client_api::{Backend, BlockBackend, HeaderBackend};
use sc_service::{BasePath, Role};
use sc_transaction_pool_api::error::Error as TxPoolError;
use sc_transaction_pool_api::TransactionPool;
use sp_api::{AsTrieBackend, ProvideRuntimeApi};
use sp_consensus::SyncOracle;
use sp_core::traits::FetchRuntimeCode;
use sp_core::Pair;
use sp_domain_digests::AsPredigest;
use sp_domains::fraud_proof::{ExecutionPhase, FraudProof, InvalidStateTransitionProof};
use sp_domains::transaction::InvalidTransactionCode;
use sp_domains::{Bundle, DomainId, DomainsApi};
use sp_runtime::generic::{BlockId, Digest, DigestItem};
use sp_runtime::traits::{BlakeTwo256, Header as HeaderT};
use sp_runtime::OpaqueExtrinsic;
use subspace_fraud_proof::invalid_state_transition_proof::ExecutionProver;
use subspace_test_service::{
    produce_block_with, produce_blocks, produce_blocks_until, MockConsensusNode,
};
use tempfile::TempDir;

fn number_of(consensus_node: &MockConsensusNode, block_hash: Hash) -> u32 {
    consensus_node
        .client
        .number(block_hash)
        .unwrap_or_else(|err| panic!("Failed to fetch number for {block_hash}: {err}"))
        .unwrap_or_else(|| panic!("header {block_hash} not in the chain"))
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn test_domain_block_production() {
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
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, &mut ferdie)
    .await;

    for i in 0..50 {
        let (tx, slot) = if i % 2 == 0 {
            // Produce bundle and include it in the primary block hence produce a domain block
            let (slot, _) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
            // `None` means collect tx from the tx pool
            (None, slot)
        } else {
            // No bundle hence not produce domain block
            (Some(vec![]), ferdie.produce_slot())
        };
        ferdie
            .produce_block_with_slot_at(slot, ferdie.client.info().best_hash, tx)
            .await
            .unwrap();
    }
    // Domain block only produced when there is bundle contains in the primary block
    assert_eq!(ferdie.client.info().best_number, 50);
    assert_eq!(alice.client.info().best_number, 25);

    let consensus_block_hash = ferdie.client.info().best_hash;
    let domain_block_number = alice.client.info().best_number;
    let domain_block_hash = alice.client.info().best_hash;

    // Fork A
    // Produce 5 more primary blocks and producing domain block for every primary block
    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Record the block hashes for later use
    let mut fork_b_parent_hash = ferdie.client.info().best_hash;
    let fork_a_block_hash_3 = alice.client.info().best_hash;

    produce_blocks!(ferdie, alice, 2).await.unwrap();
    assert_eq!(alice.client.info().best_number, domain_block_number + 5);

    // Fork B
    // Produce 6 more primary blocks but only producing 3 domain blocks because there are
    // more primary block on fork B, it will become the best fork of the domain chain
    for _ in 0..3 {
        let slot = ferdie.produce_slot();
        fork_b_parent_hash = ferdie
            .produce_block_with_slot_at(slot, fork_b_parent_hash, Some(vec![]))
            .await
            .unwrap();
    }
    assert_eq!(alice.client.info().best_number, domain_block_number + 3);
    assert_eq!(alice.client.info().best_hash, fork_a_block_hash_3);

    // Fork C
    // Produce 10 more primary blocks and do not produce any domain block but because there are
    // more primary block on fork C, it will become the best fork of the domain chain
    let mut fork_c_parent_hash = consensus_block_hash;
    for _ in 0..10 {
        let slot = ferdie.produce_slot();
        fork_c_parent_hash = ferdie
            .produce_block_with_slot_at(slot, fork_c_parent_hash, Some(vec![]))
            .await
            .unwrap();
    }
    // The best block fall back to an ancestor block
    assert_eq!(alice.client.info().best_number, domain_block_number);
    assert_eq!(alice.client.info().best_hash, domain_block_hash);

    // Simply producing more block on fork C
    ferdie.clear_tx_pool().await.unwrap();
    produce_blocks!(ferdie, alice, 10).await.unwrap();
    assert_eq!(alice.client.info().best_number, domain_block_number + 10);
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn collected_receipts_should_be_on_the_same_branch_with_current_best_block() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut consensus_node = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, &mut consensus_node)
    .await;

    produce_blocks!(consensus_node, alice, 3)
        .await
        .expect("3 consensus blocks produced successfully");

    let best_consensus_hash = consensus_node.client.info().best_hash;
    let best_consensus_number = consensus_node.client.info().best_number;
    assert_eq!(best_consensus_number, 3);

    assert_eq!(alice.client.info().best_number, 3);
    let domain_block_2_hash = *alice
        .client
        .header(alice.client.info().best_hash)
        .unwrap()
        .unwrap()
        .parent_hash();

    let best_header = consensus_node
        .client
        .header(best_consensus_hash)
        .unwrap()
        .unwrap();

    let parent_hash = *best_header.parent_hash();

    // Consensus chain forks:
    //      3
    //   /
    // 2 -- 3a
    //   \
    //      3b -- 4
    let slot = consensus_node.produce_slot();
    let fork_block_hash_3a = consensus_node
        .produce_block_with_slot_at(slot, parent_hash, Some(vec![]))
        .await
        .expect("Produced first consensus fork block 3a at height #3");
    // A fork block 3a at #3 produced.
    assert_eq!(number_of(&consensus_node, fork_block_hash_3a), 3);
    assert_ne!(fork_block_hash_3a, best_consensus_hash);
    // Best hash unchanged due to the longest chain fork choice.
    assert_eq!(consensus_node.client.info().best_hash, best_consensus_hash);
    // Hash of block number #3 unchanged.
    assert_eq!(
        consensus_node.client.hash(3).unwrap().unwrap(),
        best_consensus_hash
    );

    let consensus_block_info =
        |best_header: Header| -> (u32, Hash) { (*best_header.number(), best_header.hash()) };
    let receipts_consensus_info =
        |bundle: Bundle<OpaqueExtrinsic, u32, sp_core::H256, u32, sp_core::H256>| {
            (
                bundle.receipt.consensus_block_number,
                bundle.receipt.consensus_block_hash,
            )
        };

    // Produce a bundle after the fork block #3a has been produced.
    let signed_bundle = consensus_node
        .notify_new_slot_and_wait_for_bundle(slot)
        .await;

    let expected_receipts_consensus_info = consensus_block_info(best_header.clone());

    // TODO: make MaximumReceiptDrift configurable in order to submit all the pending receipts at
    // once, now the max drift is 2, the receipts is limitted to [2, 3]. Once configurable, we
    // can make the assertation straightforward:
    // assert_eq!(receipts_consensus_info, expected_receipts_consensus_info).
    //
    // Receipts are always collected against the current best block.
    assert_eq!(
        receipts_consensus_info(signed_bundle.unwrap()),
        expected_receipts_consensus_info
    );

    let slot = consensus_node.produce_slot();
    let fork_block_hash_3b = consensus_node
        .produce_block_with_slot_at(slot, parent_hash, Some(vec![]))
        .await
        .expect("Produced second consensus fork block 3b at height #3");
    // Another fork block 3b at #3 produced,
    assert_eq!(number_of(&consensus_node, fork_block_hash_3b), 3);
    assert_ne!(fork_block_hash_3b, best_consensus_hash);
    // Best hash unchanged due to the longest chain fork choice.
    assert_eq!(consensus_node.client.info().best_hash, best_consensus_hash);
    // Hash of block number #3 unchanged.
    assert_eq!(
        consensus_node.client.hash(3).unwrap().unwrap(),
        best_consensus_hash
    );

    // Produce a bundle after the fork block #3b has been produced.
    let signed_bundle = consensus_node
        .notify_new_slot_and_wait_for_bundle(slot)
        .await;
    // Receipts are always collected against the current best block.
    assert_eq!(
        receipts_consensus_info(signed_bundle.unwrap()),
        expected_receipts_consensus_info
    );

    // Produce a new tip at #4.
    let slot = consensus_node.produce_slot();
    produce_block_with!(
        consensus_node.produce_block_with_slot_at(slot, fork_block_hash_3b, Some(vec![])),
        alice
    )
    .await
    .expect("Produce a new block on top of the second fork block at height #3");
    let new_best_hash = consensus_node.client.info().best_hash;
    let new_best_number = consensus_node.client.info().best_number;
    assert_eq!(new_best_number, 4);

    // The domain best block should be reverted to #2 because the primary block #3b and #4 do
    // not contains any bundles
    assert_eq!(alice.client.info().best_number, 2);
    assert_eq!(alice.client.info().best_hash, domain_block_2_hash);

    // Hash of block number #3 is updated to the second fork block 3b.
    assert_eq!(
        consensus_node.client.hash(3).unwrap().unwrap(),
        fork_block_hash_3b
    );

    let new_best_header = consensus_node
        .client
        .header(new_best_hash)
        .unwrap()
        .unwrap();

    assert_eq!(*new_best_header.parent_hash(), fork_block_hash_3b);

    // Produce a bundle after the new block #4 has been produced.
    let (_slot, signed_bundle) = consensus_node
        .produce_slot_and_wait_for_bundle_submission()
        .await;

    // In the new best fork, the receipt header number is 1 thus it produce the receipt
    // of next block namely block 2
    let hash_2 = consensus_node.client.hash(2).unwrap().unwrap();
    let header_2 = consensus_node.client.header(hash_2).unwrap().unwrap();
    assert_eq!(
        receipts_consensus_info(signed_bundle.unwrap()),
        consensus_block_info(header_2)
    );
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn test_domain_tx_propagate() {
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
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, &mut ferdie)
    .await;

    // Run Bob (a evm domain full node)
    let mut bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle,
        Bob,
        BasePath::new(directory.path().join("bob")),
    )
    .connect_to_domain_node(alice.addr.clone())
    .build_evm_node(Role::Full, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, bob, 5).await.unwrap();
    while alice.sync_service.is_major_syncing() || bob.sync_service.is_major_syncing() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let pre_alice_free_balance = alice.free_balance(alice.key.to_account_id());
    // Construct and send an extrinsic to bob, as bob is not a authoity node, the extrinsic has
    // to propagate to alice to get executed
    bob.construct_and_send_extrinsic(pallet_balances::Call::transfer {
        dest: Alice.to_account_id(),
        value: 123,
    })
    .await
    .expect("Failed to send extrinsic");

    produce_blocks_until!(ferdie, alice, bob, {
        alice.free_balance(alice.key.to_account_id()) == pre_alice_free_balance + 123
    })
    .await
    .unwrap();
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn test_executor_full_node_catching_up() {
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
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, &mut ferdie)
    .await;

    // Run Bob (a evm domain full node)
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle,
        Bob,
        BasePath::new(directory.path().join("bob")),
    )
    .build_evm_node(Role::Full, &mut ferdie)
    .await;

    // Bob is able to sync blocks.
    produce_blocks!(ferdie, alice, bob, 3).await.unwrap();

    let alice_block_hash = alice
        .client
        .expect_block_hash_from_id(&BlockId::Number(2))
        .unwrap();
    let bob_block_hash = bob
        .client
        .expect_block_hash_from_id(&BlockId::Number(2))
        .unwrap();
    assert_eq!(
        alice_block_hash, bob_block_hash,
        "Domain authority node and full node must have the same state"
    );
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn test_executor_inherent_timestamp_is_set() {
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
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, &mut ferdie)
    .await;

    // Run Bob who runs the authority node for core domain
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Bob,
        BasePath::new(directory.path().join("bob")),
    )
    .build_evm_node(Role::Authority, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, bob, 1).await.unwrap();

    let consensus_timestamp = ferdie
        .client
        .runtime_api()
        .timestamp(ferdie.client.info().best_hash)
        .unwrap();

    let domain_timestamp = bob
        .client
        .runtime_api()
        .timestamp(bob.client.info().best_hash)
        .unwrap();

    assert_eq!(
        consensus_timestamp, domain_timestamp,
        "Timestamp should be preset on domain and must match Consensus runtime timestamp"
    );
}

#[substrate_test_utils::test(flavor = "multi_thread")]
#[ignore]
async fn test_initialize_block_proof_creation_and_verification_should_work() {
    test_invalid_state_transition_proof_creation_and_verification(0).await
}

#[substrate_test_utils::test(flavor = "multi_thread")]
#[ignore]
async fn test_apply_extrinsic_proof_creation_and_verification_should_work() {
    test_invalid_state_transition_proof_creation_and_verification(1).await
}

// TODO: the test is ignored due to the invalid receipt can not pass the state root check
// in the runtime now, thus can't construct `finalize_block` fraud proof, find a way to
// bypass the check
#[substrate_test_utils::test(flavor = "multi_thread")]
#[ignore]
async fn test_finalize_block_proof_creation_and_verification_should_work() {
    test_invalid_state_transition_proof_creation_and_verification(2).await
}

/// This test will create and verify a invalid state transition proof that targets the receipt of
/// a bundle that contains 1 extrinsic, thus there are 3 trace roots and the `mismatch_trace_index`
/// should be in the range of [0..2]
async fn test_invalid_state_transition_proof_creation_and_verification(
    mismatch_trace_index: usize,
) {
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
    .build_evm_node(Role::Authority, &mut ferdie)
    .await;

    let bundle_to_tx = |opaque_bundle| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        )
        .into()
    };

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let target_bundle = bundle.unwrap();
    assert_eq!(target_bundle.extrinsics.len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    // Manually remove the target bundle from tx pool in case resubmit it by accident
    ferdie
        .prune_tx_from_pool(&bundle_to_tx(target_bundle.clone()))
        .await
        .unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());
    let bad_submit_bundle_tx = {
        let mut opaque_bundle = bundle.unwrap();
        let receipt = &mut opaque_bundle.receipt;
        assert_eq!(
            receipt.consensus_block_number,
            target_bundle.sealed_header.header.consensus_block_number + 1
        );
        assert_eq!(receipt.trace.len(), 3);

        receipt.trace[mismatch_trace_index] = Default::default();
        opaque_bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
            .into();
        bundle_to_tx(opaque_bundle)
    };

    // Replace `original_submit_bundle_tx` with `bad_submit_bundle_tx` in the tx pool
    ferdie
        .prune_tx_from_pool(&original_submit_bundle_tx)
        .await
        .unwrap();
    assert!(ferdie.get_bundle_from_tx_pool(slot.into()).is_none());

    ferdie
        .submit_transaction(bad_submit_bundle_tx)
        .await
        .unwrap();

    // Produce a consensus block that contains the `bad_submit_bundle_tx`
    let mut import_tx_stream = ferdie.transaction_pool.import_notification_stream();
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // When the system domain node process the primary block that contains the `bad_submit_bundle_tx`,
    // it will generate and submit a fraud proof
    while let Some(ready_tx_hash) = import_tx_stream.next().await {
        let ready_tx = ferdie
            .transaction_pool
            .ready_transaction(&ready_tx_hash)
            .unwrap();
        let ext = subspace_test_runtime::UncheckedExtrinsic::decode(
            &mut ready_tx.data.encode().as_slice(),
        )
        .unwrap();
        if let subspace_test_runtime::RuntimeCall::Domains(
            pallet_domains::Call::submit_fraud_proof {
                fraud_proof: FraudProof::InvalidStateTransition(proof),
            },
        ) = ext.function
        {
            match mismatch_trace_index {
                0 => assert!(matches!(
                    proof.execution_phase,
                    ExecutionPhase::InitializeBlock { .. }
                )),
                1 => assert!(matches!(
                    proof.execution_phase,
                    ExecutionPhase::ApplyExtrinsic(_)
                )),
                2 => assert!(matches!(
                    proof.execution_phase,
                    ExecutionPhase::FinalizeBlock { .. }
                )),
                _ => unreachable!(),
            }
            break;
        }
    }

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // in the block import pipeline
    ferdie.produce_blocks(1).await.unwrap();
}

#[substrate_test_utils::test(flavor = "multi_thread")]
#[ignore]
async fn fraud_proof_verification_in_tx_pool_should_work() {
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
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, &mut ferdie)
    .await;

    // TODO: test the `initialize_block` fraud proof of block 1 with `wait_for_blocks(1)`
    // after https://github.com/subspace/subspace/issues/1301 is resolved.
    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Get a bundle from the txn pool and change its receipt to an invalid one
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let bad_bundle = {
        let mut opaque_bundle = bundle.unwrap();
        opaque_bundle.receipt.trace[0] = Default::default();
        opaque_bundle
    };
    let bad_receipt = bad_bundle.receipt.clone();
    let bad_receipt_number = bad_receipt.consensus_block_number;
    assert_ne!(bad_receipt_number, 1);

    // Submit the bad receipt to the consensus chain
    let submit_bundle_tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
        pallet_domains::Call::submit_bundle {
            opaque_bundle: bad_bundle,
        }
        .into(),
    );
    produce_block_with!(
        ferdie.produce_block_with_extrinsics(vec![submit_bundle_tx.into()]),
        alice
    )
    .await
    .unwrap();

    let header = alice
        .client
        .header(alice.client.hash(bad_receipt_number).unwrap().unwrap())
        .unwrap()
        .unwrap();
    let parent_header = alice.client.header(*header.parent_hash()).unwrap().unwrap();

    let intermediate_roots = alice
        .client
        .runtime_api()
        .intermediate_roots(header.hash())
        .expect("Get intermediate roots");

    let prover = ExecutionProver::new(alice.backend.clone(), alice.code_executor.clone());

    let digest = {
        Digest {
            logs: vec![DigestItem::primary_block_info((
                bad_receipt_number,
                ferdie.client.hash(bad_receipt_number).unwrap().unwrap(),
            ))],
        }
    };

    let new_header = Header::new(
        *header.number(),
        header.hash(),
        *header.state_root(),
        parent_header.hash(),
        digest,
    );
    let execution_phase = ExecutionPhase::InitializeBlock {
        domain_parent_hash: parent_header.hash(),
    };
    let initialize_block_call_data = new_header.encode();

    let storage_proof = prover
        .prove_execution::<sp_trie::PrefixedMemoryDB<BlakeTwo256>>(
            parent_header.hash(),
            &execution_phase,
            &initialize_block_call_data,
            None,
        )
        .expect("Create `initialize_block` proof");

    let header_ferdie = ferdie
        .client
        .header(ferdie.client.hash(bad_receipt_number).unwrap().unwrap())
        .unwrap()
        .unwrap();
    let parent_header_ferdie = ferdie
        .client
        .header(*header_ferdie.parent_hash())
        .unwrap()
        .unwrap();
    let parent_hash_ferdie = parent_header_ferdie.hash();
    let parent_number_ferdie = *parent_header_ferdie.number();

    let good_invalid_state_transition_proof = InvalidStateTransitionProof {
        domain_id: DomainId::new(3u32),
        bad_receipt_hash: bad_receipt.hash(),
        parent_number: parent_number_ferdie,
        consensus_parent_hash: parent_hash_ferdie,
        pre_state_root: *parent_header.state_root(),
        post_state_root: intermediate_roots[0].into(),
        proof: storage_proof,
        execution_phase,
    };
    let valid_fraud_proof =
        FraudProof::InvalidStateTransition(good_invalid_state_transition_proof.clone());

    let tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
        pallet_domains::Call::submit_fraud_proof {
            fraud_proof: valid_fraud_proof.clone(),
        }
        .into(),
    )
    .into();

    // The exact same fraud proof should be submitted to tx pool already
    match ferdie.submit_transaction(tx).await.unwrap_err() {
        sc_transaction_pool::error::Error::Pool(
            sc_transaction_pool_api::error::Error::AlreadyImported(_),
        ) => {}
        e => panic!("Unexpected error while submitting fraud proof: {e}"),
    }
    // Produce one more block to verify the fraud proof in the block import pipeline
    ferdie.produce_blocks(1).await.unwrap();

    let bad_invalid_state_transition_proof = InvalidStateTransitionProof {
        post_state_root: Hash::random(),
        ..good_invalid_state_transition_proof
    };
    let invalid_fraud_proof =
        FraudProof::InvalidStateTransition(bad_invalid_state_transition_proof);

    let tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
        pallet_domains::Call::submit_fraud_proof {
            fraud_proof: invalid_fraud_proof,
        }
        .into(),
    );

    match ferdie.submit_transaction(tx.into()).await.unwrap_err() {
        sc_transaction_pool::error::Error::Pool(
            sc_transaction_pool_api::error::Error::InvalidTransaction(invalid_tx),
        ) => assert_eq!(invalid_tx, InvalidTransactionCode::FraudProof.into()),
        e => panic!("Unexpected error while submitting an invalid fraud proof: {e}"),
    }
}

// TODO: Add a new test which simulates a situation that an executor produces a fraud proof
// when an invalid receipt is received.

// TODO: construct a minimal consensus runtime code and use the `set_code` extrinsic to actually
// cover the case that the new domain runtime are updated accordingly upon the new consensus runtime.
#[substrate_test_utils::test(flavor = "multi_thread")]
#[ignore]
async fn set_new_code_should_work() {
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
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 1).await.unwrap();

    let new_runtime_wasm_blob = b"new_runtime_wasm_blob".to_vec();

    let best_number = alice.client.info().best_number;
    let consensus_block_number = best_number + 1;
    // Although we're processing the bundle manually, the original bundle processor still works in
    // the meanwhile, it's possible the executor alice already processed this consensus block, expecting next
    // consensus block, in which case we use a dummy consensus hash instead.
    //
    // Nice to disable the built-in bundle processor and have a full control of the executor block
    // production manually.
    let consensus_block_hash = ferdie
        .client
        .hash(consensus_block_number)
        .unwrap()
        .unwrap_or_else(Hash::random);
    alice
        .operator
        .clone()
        .process_bundles((consensus_block_hash, consensus_block_number, true))
        .await;

    let best_hash = alice.client.info().best_hash;
    let state = alice.backend.state_at(best_hash).expect("Get state");
    let trie_backend = state.as_trie_backend();
    let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(trie_backend);
    let runtime_code = state_runtime_code.fetch_runtime_code().unwrap();
    let logs = alice.client.header(best_hash).unwrap().unwrap().digest.logs;
    if logs != vec![DigestItem::RuntimeEnvironmentUpdated] {
        let extrinsics = alice
            .client
            .block_body(best_hash)
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|encoded_extrinsic| {
                UncheckedExtrinsic::decode(&mut encoded_extrinsic.encode().as_slice()).unwrap()
            })
            .collect::<Vec<_>>();
        panic!("`set_code` not executed, extrinsics in the block: {extrinsics:?}")
    }
    assert_eq!(runtime_code, new_runtime_wasm_blob);
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn pallet_domains_unsigned_extrinsics_should_work() {
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
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, &mut ferdie)
    .await;

    // Run Bob (a evm domain full node)
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle,
        Bob,
        BasePath::new(directory.path().join("bob")),
    )
    .build_evm_node(Role::Full, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // Get a bundle from alice's tx pool and used as bundle template.
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let _bundle_template = bundle.unwrap();
    let _alice_key = alice.key;
    // Drop alice in order to control the execution chain by submitting the receipts manually later.
    drop(alice);

    produce_block_with!(ferdie.produce_block_with_slot(slot), bob)
        .await
        .unwrap();

    // let ferdie_client = ferdie.client.clone();
    // let create_submit_bundle = |consensus_block_number: BlockNumber| {
    // let consensus_block_hash = ferdie_client.hash(consensus_block_number).unwrap().unwrap();
    // let execution_receipt =
    // crate::aux_schema::load_execution_receipt(&*bob.backend, consensus_block_hash)
    // .expect("Failed to load execution receipt from the local aux_db")
    // .unwrap_or_else(|| {
    // panic!(
    // "The requested execution receipt for block {consensus_block_number} does not exist"
    // )
    // });

    // let mut opaque_bundle = bundle_template.clone();
    // opaque_bundle.sealed_header.header.consensus_block_number = consensus_block_number;
    // opaque_bundle.sealed_header.header.consensus_block_hash = consensus_block_hash;
    // opaque_bundle.sealed_header.signature = alice_key
    // .pair()
    // .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
    // .into();
    // opaque_bundle.receipt = execution_receipt;

    //     subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
    //         pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
    //     )
    //     .into()
    // };

    // TODO: Unlock once `head_receipt_number` API is usable.
    // let ferdie_client = ferdie.client.clone();
    // let head_receipt_number = || {
    //     let best_hash = ferdie_client.info().best_hash;
    //     ferdie_client
    //         .runtime_api()
    //         .head_receipt_number(best_hash, DomainId::SYSTEM)
    //         .expect("Failed to get head receipt number")
    // };

    // ferdie
    //     .submit_transaction(create_submit_bundle(1))
    //     .await
    //     .unwrap();
    // produce_blocks!(ferdie, bob, 1).await.unwrap();
    // ferdie
    //     .submit_transaction(create_submit_bundle(2))
    //     .await
    //     .unwrap();
    // produce_blocks!(ferdie, bob, 1).await.unwrap();
    // assert_eq!(head_receipt_number(), 2);
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn duplicated_and_stale_bundle_should_be_rejected() {
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
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 1).await.unwrap();

    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let submit_bundle_tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
        pallet_domains::Call::submit_bundle {
            opaque_bundle: bundle.unwrap(),
        }
        .into(),
    )
    .into();

    // Wait for one block to ensure the bundle is stored onchain and then manually remove it from tx pool.
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    ferdie.prune_tx_from_pool(&submit_bundle_tx).await.unwrap();

    // Bundle is rejected because it is duplicated.
    match ferdie
        .submit_transaction(submit_bundle_tx.clone())
        .await
        .unwrap_err()
    {
        sc_transaction_pool::error::Error::Pool(err) => {
            // Compare the error message of `TxPoolError::ImmediatelyDropped` here because
            // `TxPoolError` didn't drive `PartialEq`
            assert_eq!(
                &err.to_string(),
                "Transaction couldn't enter the pool because of the limit"
            );
        }
        e => panic!("Unexpected error: {e}"),
    }

    // Wait for confirmation depth K blocks which is 100 in test
    produce_blocks!(ferdie, alice, 100).await.unwrap();

    // Bundle is now rejected because it is stale.
    match ferdie
        .submit_transaction(submit_bundle_tx)
        .await
        .unwrap_err()
    {
        sc_transaction_pool::error::Error::Pool(TxPoolError::InvalidTransaction(invalid_tx)) => {
            assert_eq!(invalid_tx, InvalidTransactionCode::Bundle.into())
        }
        e => panic!("Unexpected error: {e}"),
    }
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn existing_bundle_can_be_resubmitted_to_new_fork() {
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
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let mut parent_hash = ferdie.client.info().best_hash;

    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let submit_bundle_tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
        pallet_domains::Call::submit_bundle {
            opaque_bundle: bundle.unwrap(),
        }
        .into(),
    )
    .into();

    // Wait one block to ensure the bundle is stored on this fork
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // Create fork and build one more blocks on it to make it the new best fork
    parent_hash = ferdie
        .produce_block_with_slot_at(slot, parent_hash, Some(vec![]))
        .await
        .unwrap();
    ferdie
        .produce_block_with_slot_at(slot + 1, parent_hash, Some(vec![]))
        .await
        .unwrap();

    // Manually remove the retracted block's `submit_bundle_tx` from tx pool
    ferdie.prune_tx_from_pool(&submit_bundle_tx).await.unwrap();

    // Bundle can be successfully submitted to the new fork, or it is also possible
    // that the `submit_bundle_tx` in the retracted block has been resubmitted to the
    // tx pool in the background by the `txpool-notifications` worker just after the above
    // `prune_tx_from_pool` call.
    match ferdie.submit_transaction(submit_bundle_tx).await {
        Ok(_) | Err(sc_transaction_pool::error::Error::Pool(TxPoolError::AlreadyImported(_))) => {}
        Err(err) => panic!("Unexpected error: {err}"),
    }
}

// TODO: Unlock test when multiple domains are supported in DecEx v2.
// #[substrate_test_utils::test(flavor = "multi_thread")]
// async fn test_cross_domains_message_should_work() {
//     let directory = TempDir::new().expect("Must be able to create temporary directory");
//
//     let mut builder = sc_cli::LoggerBuilder::new("");
//     builder.with_colors(false);
//     let _ = builder.init();
//
//     let tokio_handle = tokio::runtime::Handle::current();
//
//     // Start Ferdie
//     let mut ferdie = MockConsensusNode::run(
//         tokio_handle.clone(),
//         Ferdie,
//         BasePath::new(directory.path().join("ferdie")),
//     );
//
//     // Run Alice (a system domain authority node)
//     let mut alice = domain_test_service::DomainNodeBuilder::new(
//         tokio_handle.clone(),
//         Alice,
//         BasePath::new(directory.path().join("alice")),
//     )
//     .run_relayer()
//     .build_evm_node(Role::Authority, &mut ferdie)
//     .await;
//
//     // Run Bob (a core payments domain authority node)
//     let mut bob = domain_test_service::DomainNodeBuilder::new(
//         tokio_handle.clone(),
//         Bob,
//         BasePath::new(directory.path().join("bob")),
//     )
//     .run_relayer()
//     .build_core_payments_node(Role::Authority, &mut ferdie, &alice)
//     .await;
//
//     // Run Charlie (a core eth relay domain authority node)
//     let mut charlie = domain_test_service::DomainNodeBuilder::new(
//         tokio_handle.clone(),
//         Charlie,
//         BasePath::new(directory.path().join("charlie")),
//     )
//     .run_relayer()
//     .build_core_eth_relay_node(Role::Authority, &mut ferdie, &alice)
//     .await;
//
//     // Run the cross domain gossip message worker
//     ferdie.start_cross_domain_gossip_message_worker();
//
//     produce_blocks!(ferdie, alice, bob, charlie, 3)
//         .await
//         .unwrap();
//
//     // Open channel between the system domain and the core payments domain
//     let fee_model = FeeModel {
//         outbox_fee: ExecutionFee {
//             relayer_pool_fee: 2,
//             compute_fee: 0,
//         },
//         inbox_fee: ExecutionFee {
//             relayer_pool_fee: 0,
//             compute_fee: 5,
//         },
//     };
//     bob.construct_and_send_extrinsic(pallet_sudo::Call::sudo {
//         call: Box::new(core_payments_domain_test_runtime::RuntimeCall::Messenger(
//             pallet_messenger::Call::initiate_channel {
//                 dst_domain_id: DomainId::SYSTEM,
//                 params: InitiateChannelParams {
//                     max_outgoing_messages: 100,
//                     fee_model,
//                 },
//             },
//         )),
//     })
//     .await
//     .expect("Failed to construct and send extrinsic");
//     // Wait until channel open
//     produce_blocks_until!(ferdie, alice, bob, {
//         alice
//             .get_open_channel_for_domain(DomainId::CORE_PAYMENTS)
//             .is_some()
//             && bob.get_open_channel_for_domain(DomainId::SYSTEM).is_some()
//     })
//     .await
//     .unwrap();
//
//     // Transfer balance cross the system domain and the core payments domain
//     let pre_alice_free_balance = alice.free_balance(alice.key.to_account_id());
//     let pre_bob_free_balance = bob.free_balance(bob.key.to_account_id());
//     let transfer_amount = 10;
//     alice
//         .construct_and_send_extrinsic(pallet_transporter::Call::transfer {
//             dst_location: pallet_transporter::Location {
//                 domain_id: DomainId::CORE_PAYMENTS,
//                 account_id: AccountIdConverter::convert(Bob.into()),
//             },
//             amount: transfer_amount,
//         })
//         .await
//         .expect("Failed to construct and send extrinsic");
//     // Wait until transfer succeed
//     produce_blocks_until!(ferdie, alice, bob, charlie, {
//         let post_alice_free_balance = alice.free_balance(alice.key.to_account_id());
//         let post_bob_free_balance = bob.free_balance(bob.key.to_account_id());
//
//         post_alice_free_balance
//             == pre_alice_free_balance
//                 - transfer_amount
//                 - fee_model.outbox_fee().unwrap()
//                 - fee_model.inbox_fee().unwrap()
//             && post_bob_free_balance == pre_bob_free_balance + transfer_amount
//     })
//     .await
//     .unwrap();
//
//     // Open channel between the core payments domain and the core eth relay domain
//     let fee_model = FeeModel {
//         outbox_fee: ExecutionFee {
//             relayer_pool_fee: 1,
//             compute_fee: 5,
//         },
//         inbox_fee: ExecutionFee {
//             relayer_pool_fee: 2,
//             compute_fee: 3,
//         },
//     };
//     charlie
//         .construct_and_send_extrinsic(pallet_sudo::Call::sudo {
//             call: Box::new(core_eth_relay_domain_test_runtime::RuntimeCall::Messenger(
//                 pallet_messenger::Call::initiate_channel {
//                     dst_domain_id: DomainId::CORE_PAYMENTS,
//                     params: InitiateChannelParams {
//                         max_outgoing_messages: 100,
//                         fee_model,
//                     },
//                 },
//             )),
//         })
//         .await
//         .expect("Failed to construct and send extrinsic");
//     // Wait until channel open
//     produce_blocks_until!(ferdie, alice, bob, charlie, {
//         bob.get_open_channel_for_domain(DomainId::CORE_ETH_RELAY)
//             .is_some()
//             && charlie
//                 .get_open_channel_for_domain(DomainId::CORE_PAYMENTS)
//                 .is_some()
//     })
//     .await
//     .unwrap();
//
//     // Transfer balance cross the core payments domain and the core eth relay domain
//     let pre_bob_free_balance = bob.free_balance(bob.key.to_account_id());
//     let pre_charlie_free_balance = charlie.free_balance(charlie.key.to_account_id());
//     let transfer_amount = 10;
//     bob.construct_and_send_extrinsic(pallet_transporter::Call::transfer {
//         dst_location: pallet_transporter::Location {
//             domain_id: DomainId::CORE_ETH_RELAY,
//             account_id: AccountIdConverter::convert(Charlie.into()),
//         },
//         amount: transfer_amount,
//     })
//     .await
//     .expect("Failed to construct and send extrinsic");
//     // Wait until transfer succeed
//     produce_blocks_until!(ferdie, alice, bob, charlie, {
//         let post_bob_free_balance = bob.free_balance(bob.key.to_account_id());
//         let post_charlie_free_balance = charlie.free_balance(charlie.key.to_account_id());
//
//         post_bob_free_balance
//             == pre_bob_free_balance
//                 - transfer_amount
//                 - fee_model.outbox_fee().unwrap()
//                 - fee_model.inbox_fee().unwrap()
//             && post_charlie_free_balance == pre_charlie_free_balance + transfer_amount
//     })
//     .await
//     .unwrap();
// }

// TODO: Unlock test when multiple domains are supported in DecEx v2.
// #[substrate_test_utils::test(flavor = "multi_thread")]
// async fn test_unordered_cross_domains_message_should_work() {
// let directory = TempDir::new().expect("Must be able to create temporary directory");

// let mut builder = sc_cli::LoggerBuilder::new("");
// builder.with_colors(false);
// let _ = builder.init();

// let tokio_handle = tokio::runtime::Handle::current();

// // Start Ferdie
// let mut ferdie = MockConsensusNode::run(
// tokio_handle.clone(),
// Ferdie,
// BasePath::new(directory.path().join("ferdie")),
// );

// // Run Alice (a system domain authority node)
// let mut alice = domain_test_service::DomainNodeBuilder::new(
// tokio_handle.clone(),
// Alice,
// BasePath::new(directory.path().join("alice")),
// )
// .run_relayer()
// .build_evm_node(Role::Authority, &mut ferdie)
// .await;

// // Run Bob (a core payments domain authority node)
// let mut bob = domain_test_service::DomainNodeBuilder::new(
// tokio_handle.clone(),
// Bob,
// BasePath::new(directory.path().join("bob")),
// )
// .run_relayer()
// .build_core_payments_node(Role::Authority, &mut ferdie, &alice)
// .await;

// // Run Charlie (a core eth relay domain full node) and don't its relayer worker
// let charlie = domain_test_service::DomainNodeBuilder::new(
// tokio_handle.clone(),
// Charlie,
// BasePath::new(directory.path().join("charlie")),
// )
// .build_core_payments_node(Role::Full, &mut ferdie, &alice)
// .await;
// let gossip_msg_sink = ferdie.xdm_gossip_worker_builder().gossip_msg_sink();

// // Run the cross domain gossip message worker
// ferdie.start_cross_domain_gossip_message_worker();

// produce_blocks!(ferdie, alice, bob, 3).await.unwrap();

// // Open channel between the system domain and the core payments domain
// let fee_model = FeeModel {
// outbox_fee: ExecutionFee {
// relayer_pool_fee: 2,
// compute_fee: 0,
// },
// inbox_fee: ExecutionFee {
// relayer_pool_fee: 0,
// compute_fee: 5,
// },
// };
// bob.construct_and_send_extrinsic(pallet_sudo::Call::sudo {
// call: Box::new(core_payments_domain_test_runtime::RuntimeCall::Messenger(
// pallet_messenger::Call::initiate_channel {
// dst_domain_id: DomainId::SYSTEM,
// params: InitiateChannelParams {
// max_outgoing_messages: 1000,
// fee_model,
// },
// },
// )),
// })
// .await
// .expect("Failed to construct and send extrinsic");
// // Wait until channel open
// produce_blocks_until!(ferdie, alice, bob, charlie, {
// alice
// .get_open_channel_for_domain(DomainId::CORE_PAYMENTS)
// .is_some()
// && bob.get_open_channel_for_domain(DomainId::SYSTEM).is_some()
// })
// .await
// .unwrap();

// // Register `charlie` as relayer such that message will assign to it, but as its relayer
// // is not started these massage won't be relayed.
// bob.construct_and_send_extrinsic(pallet_messenger::Call::join_relayer_set {
// relayer_id: Charlie.into(),
// })
// .await
// .expect("Failed to construct and send extrinsic");
// produce_blocks!(ferdie, alice, bob, charlie, 3)
// .await
// .unwrap();

// // Create cross domain message, only message assigned to `alice` and `bob` will be relayed
// // and send to tx pool, and these message is unordered because the message assigned to `charlie`
// // is not relayed.
// let relayer_id: AccountId = Charlie.into();
// let alice_transfer_amount = 1;
// let bob_transfer_amount = 2;
// let pre_alice_free_balance = alice.free_balance(alice.key.to_account_id());
// let pre_bob_free_balance = bob.free_balance(bob.key.to_account_id());
// let mut alice_account_nonce = alice.account_nonce();
// let mut bob_account_nonce = bob.account_nonce();
// // Assigne `inbox_response` message to `charlie`
// for _ in 0..10 {
// let tx = alice.construct_extrinsic(
// alice_account_nonce,
// pallet_transporter::Call::transfer {
// dst_location: pallet_transporter::Location {
// domain_id: DomainId::CORE_PAYMENTS,
// account_id: AccountIdConverter::convert(Bob.into()),
// },
// amount: alice_transfer_amount,
// },
// );
// alice
// .send_extrinsic(tx)
// .await
// .expect("Failed to send extrinsic");
// alice_account_nonce += 1;

// produce_blocks!(ferdie, alice, bob, charlie, 1)
// .await
// .unwrap();
// }
// // Assigne `outbox` message to `charlie`
// for _ in 0..10 {
// let tx = bob.construct_extrinsic(
// bob_account_nonce,
// pallet_transporter::Call::transfer {
// dst_location: pallet_transporter::Location {
// domain_id: DomainId::SYSTEM,
// account_id: AccountIdConverter::convert(Alice.into()),
// },
// amount: bob_transfer_amount,
// },
// );
// bob.send_extrinsic(tx)
// .await
// .expect("Failed to send extrinsic");
// bob_account_nonce += 1;

// produce_blocks!(ferdie, alice, bob, charlie, 1)
// .await
// .unwrap();
// }

// // Run charlie's relayer worker, the message assigned to `charlie` will be relayed
// // and send to tx pool now
// let relayer_worker = domain_client_message_relayer::worker::relay_core_domain_messages::<
// _,
// _,
// PBlock,
// _,
// _,
// _,
// _,
// _,
// >(
// relayer_id,
// charlie.client.clone(),
// alice.client.clone(),
// alice.sync_service.clone(),
// charlie.sync_service.clone(),
// gossip_msg_sink,
// );
// bob.task_manager
// .spawn_essential_handle()
// .spawn_essential_blocking(
// "core-domain-relayer-charlie",
// None,
// Box::pin(relayer_worker),
// );

// // Wait until all message are relayed and handled
// let fee = fee_model.outbox_fee().unwrap() + fee_model.inbox_fee().unwrap();
// produce_blocks_until!(ferdie, alice, bob, {
// let post_alice_free_balance = alice.free_balance(alice.key.to_account_id());
// let post_bob_free_balance = bob.free_balance(bob.key.to_account_id());

// post_alice_free_balance
// == pre_alice_free_balance - alice_transfer_amount * 10 + bob_transfer_amount * 10
// - fee * 10
// && post_bob_free_balance
// == pre_bob_free_balance - bob_transfer_amount * 10 + alice_transfer_amount * 10
// - fee * 10
// })
// .await
// .unwrap();
// }

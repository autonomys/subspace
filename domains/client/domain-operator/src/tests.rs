use crate::domain_block_processor::{DomainBlockProcessor, PendingConsensusBlocks};
use crate::domain_bundle_producer::DomainBundleProducer;
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::utils::OperatorSlotInfo;
use codec::{Decode, Encode};
use domain_runtime_primitives::Hash;
use domain_test_primitives::TimestampApi;
use domain_test_service::evm_domain_test_runtime::{Header, UncheckedExtrinsic};
use domain_test_service::EcdsaKeyring::{Alice, Bob, Charlie};
use domain_test_service::Sr25519Keyring::{self, Ferdie};
use domain_test_service::GENESIS_DOMAIN_ID;
use futures::StreamExt;
use sc_client_api::{Backend, BlockBackend, BlockchainEvents, HeaderBackend};
use sc_consensus::SharedBlockImport;
use sc_service::{BasePath, Role};
use sc_transaction_pool_api::error::Error as TxPoolError;
use sc_transaction_pool_api::TransactionPool;
use sp_api::{AsTrieBackend, HashT, ProvideRuntimeApi};
use sp_consensus::SyncOracle;
use sp_core::storage::StateVersion;
use sp_core::traits::FetchRuntimeCode;
use sp_core::{Pair, H256};
use sp_domain_digests::AsPredigest;
use sp_domains::merkle_tree::MerkleTree;
use sp_domains::{
    Bundle, BundleValidity, DomainsApi, HeaderHashingFor, InboxedBundle, InvalidBundleType,
};
use sp_domains_fraud_proof::fraud_proof::{
    ExecutionPhase, FraudProof, InvalidDomainBlockHashProof, InvalidExtrinsicsRootProof,
    InvalidTotalRewardsProof,
};
use sp_domains_fraud_proof::InvalidTransactionCode;
use sp_runtime::generic::{BlockId, DigestItem};
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Header as HeaderT};
use sp_runtime::OpaqueExtrinsic;
use std::sync::Arc;
use subspace_core_primitives::Randomness;
use subspace_runtime_primitives::opaque::Block as CBlock;
use subspace_runtime_primitives::Balance;
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

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_instance_bootstrapper() {
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

    let expected_genesis_state_root = ferdie
        .client
        .runtime_api()
        .genesis_state_root(ferdie.client.info().best_hash, GENESIS_DOMAIN_ID)
        .unwrap()
        .unwrap();

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    let genesis_state_root = *alice
        .client
        .header(alice.client.info().genesis_hash)
        .unwrap()
        .unwrap()
        .state_root();

    assert_eq!(expected_genesis_state_root, genesis_state_root);

    produce_blocks!(ferdie, alice, 3)
        .await
        .expect("3 consensus blocks produced successfully");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_chain_fork_choice() {
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();
    assert_eq!(alice.client.info().best_number, 3);

    let domain_hash_3 = alice.client.info().best_hash;
    let common_consensus_hash = ferdie.client.info().best_hash;

    // Fork A produce a consenus block that contains no bundle
    let slot = ferdie.produce_slot();
    let fork_a_block_hash = ferdie
        .produce_block_with_slot_at(slot, common_consensus_hash, Some(vec![]))
        .await
        .unwrap();

    let mut alice_import_notification_stream = alice.client.every_import_notification_stream();

    // Fork B produce a consenus block that contains bundles
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert!(bundle.is_some());
    let fork_b_block_hash = ferdie
        .produce_block_with_slot_at(slot, common_consensus_hash, None)
        .await
        .unwrap();

    // Fork B is still in the non-canonical fork thus the consensus block and bundle
    // won't be processed
    assert!(alice_import_notification_stream.try_recv().is_err());

    // The consensus fork A is still the best fork, because fork A don't derive any new
    // domain block thus the best domain block is still #3
    assert_eq!(ferdie.client.info().best_hash, fork_a_block_hash);
    assert_eq!(alice.client.info().best_number, 3);
    assert_eq!(alice.client.info().best_hash, domain_hash_3);

    // Produce one more consensus block on fork B to make it the best fork
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert!(bundle.is_some());
    let fork_b_block_hash = ferdie
        .produce_block_with_slot_at(slot, fork_b_block_hash, Some(vec![]))
        .await
        .unwrap();
    assert_eq!(ferdie.client.info().best_hash, fork_b_block_hash);

    // It should also trigger the operator to processe consensus blocks at fork B
    // thus produce more domain blocks
    let domain_block_4 = alice_import_notification_stream.next().await.unwrap();
    assert_eq!(*domain_block_4.header.number(), 4);
    assert_eq!(alice.client.info().best_number, 4);
    assert_eq!(alice.client.info().best_hash, domain_block_4.header.hash());
}

#[tokio::test(flavor = "multi_thread")]
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
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
    for _ in 0..10 {
        let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        let tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle {
                opaque_bundle: bundle.unwrap(),
            }
            .into(),
        )
        .into();
        // Produce consensus block that only contains the `submit_bundle` extrinsic instead of
        // any extrinsic in the tx pool, because the background worker `txpool-notifications` may
        // submit extrinsic from the retracted blocks of other fork to the tx pool and these tx
        // is invalid in the fork C
        ferdie
            .produce_block_with_slot_at(slot, ferdie.client.info().best_hash, Some(vec![tx]))
            .await
            .unwrap();
    }
    assert_eq!(alice.client.info().best_number, domain_block_number + 10);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_processing_empty_consensus_block() {
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    let domain_block_processor = DomainBlockProcessor {
        domain_id: alice.domain_id,
        domain_created_at: 1,
        client: alice.client.clone(),
        consensus_client: ferdie.client.clone(),
        backend: alice.backend.clone(),
        domain_confirmation_depth: 256u32,
        block_import: SharedBlockImport::new(alice.client.clone()),
        import_notification_sinks: Default::default(),
        consensus_network_sync_oracle: ferdie.sync_service.clone(),
    };

    let domain_genesis_hash = alice.client.info().best_hash;
    for _ in 0..10 {
        // Produce consensus block with no tx thus no bundle
        ferdie.produce_block_with_extrinsics(vec![]).await.unwrap();

        let consensus_best_hash = ferdie.client.info().best_hash;
        let consensus_best_number = ferdie.client.info().best_number;
        let res = domain_block_processor
            .pending_imported_consensus_blocks(consensus_best_hash, consensus_best_number);
        match res {
            // The consensus block is processed in the above `produce_block_with_extrinsics` call,
            // thus calling `pending_imported_consensus_blocks` again will result in an `Ok(None)`
            Ok(None) => {
                // The `latest_consensus_block` that mapped to the genesis domain block must be updated
                let latest_consensus_block: Hash =
                    crate::aux_schema::latest_consensus_block_hash_for(
                        &*alice.backend,
                        &domain_genesis_hash,
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(latest_consensus_block, consensus_best_hash);
            }
            // For consensus block at `domain_created_at + 1` (namely block #2), `pending_imported_consensus_blocks`
            // will return `PendingConsensusBlocks` directly
            Ok(Some(PendingConsensusBlocks {
                initial_parent,
                consensus_imports,
            })) if consensus_best_number == 2 => {
                assert_eq!(initial_parent.0, domain_genesis_hash);
                assert_eq!(consensus_imports.len(), 1);
                assert_eq!(consensus_imports[0].hash, consensus_best_hash,);
            }
            _ => panic!("unexpected result: {res:?}"),
        }
    }
    // The domain chain is not progressed as all the consensus blocks are empty
    assert_eq!(ferdie.client.info().best_number, 10);
    assert_eq!(alice.client.info().best_number, 0);

    // To process non-empty consensus blocks and produce domain blocks
    produce_blocks!(ferdie, alice, 3).await.unwrap();
    assert_eq!(alice.client.info().best_number, 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_block_deriving_from_multiple_bundles() {
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

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let pre_bob_free_balance = alice.free_balance(Bob.to_account_id());
    let alice_account_nonce = alice.account_nonce();
    for i in 0..3 {
        let tx = alice.construct_extrinsic(
            alice_account_nonce + i,
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

        // In the last iteration, produce a consensus block which will included all the bundles
        // and drive the corresponding domain block
        if i == 2 {
            produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
                .await
                .unwrap();
        }
    }
    assert_eq!(
        alice.free_balance(Bob.to_account_id()),
        pre_bob_free_balance + 3
    );
    let domain_block_number = alice.client.info().best_number;

    // Produce one more bundle to submit the receipt of the above 3 bundles
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // The receipt should be submitted successfully thus head receipt number
    // is updated
    let head_receipt_number = ferdie
        .client
        .runtime_api()
        .head_receipt_number(ferdie.client.info().best_hash, 0u32.into())
        .unwrap();
    assert_eq!(domain_block_number, head_receipt_number);
}

#[tokio::test(flavor = "multi_thread")]
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut consensus_node)
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
        |bundle: Bundle<OpaqueExtrinsic, u32, sp_core::H256, Header, Balance>| {
            (
                bundle.receipt().consensus_block_number,
                bundle.receipt().consensus_block_hash,
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

#[tokio::test(flavor = "multi_thread")]
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    // Run Bob (a evm domain full node)
    let mut bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle,
        Bob,
        BasePath::new(directory.path().join("bob")),
    )
    .connect_to_domain_node(alice.addr.clone())
    .build_evm_node(Role::Full, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5, bob).await.unwrap();
    while alice.sync_service.is_major_syncing() || bob.sync_service.is_major_syncing() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let pre_bob_free_balance = alice.free_balance(bob.key.to_account_id());
    // Construct and send an extrinsic to bob, as bob is not a authority node, the extrinsic has
    // to propagate to alice to get executed
    bob.construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
        dest: Alice.to_account_id(),
        value: 123,
    })
    .await
    .expect("Failed to send extrinsic");

    produce_blocks_until!(
        ferdie,
        alice,
        {
            // ensure bob has reduced balance since alice might submit other transactions which cost
            // and so exact balance check is not feasible
            alice.free_balance(bob.key.to_account_id()) <= pre_bob_free_balance - 123
        },
        bob
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
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
    // Produce 5 consensus block to initialize genesis domain
    //
    // This also make the first consensus block being processed by the alice's domain
    // block processor be block #5, to ensure it can correctly handle the consensus
    // block even it is out of order.
    for _ in 0..5 {
        let slot = ferdie.produce_slot();
        ferdie.produce_block_with_slot(slot).await.unwrap();
    }

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
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
    produce_blocks!(ferdie, alice, 3, bob).await.unwrap();

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

#[tokio::test(flavor = "multi_thread")]
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    // Run Bob who runs the authority node for core domain
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Bob,
        BasePath::new(directory.path().join("bob")),
    )
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 1, bob).await.unwrap();

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

#[tokio::test(flavor = "multi_thread")]
async fn test_initialize_block_proof_creation_and_verification_should_work() {
    test_invalid_state_transition_proof_creation_and_verification(0).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_apply_extrinsic_proof_creation_and_verification_should_work() {
    test_invalid_state_transition_proof_creation_and_verification(2).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_finalize_block_proof_creation_and_verification_should_work() {
    test_invalid_state_transition_proof_creation_and_verification(3).await
}

/// This test will create and verify a invalid state transition proof that targets the receipt of
/// a bundle that contains 2 extrinsic (including 1 inherent timestamp extrinsic), thus there are
/// 4 trace roots in total, passing the `mismatch_trace_index` as:
/// - 0 to test the `initialize_block` invalid state transition
/// - 1 to test the `apply_extrinsic` invalid state transition with the inherent timestamp extrinsic
/// - 2 to test the `apply_extrinsic` invalid state transition with regular domain extrinsic
/// - 3 to test the `finalize_block` invalid state transition
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    let bundle_to_tx = |opaque_bundle| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        )
        .into()
    };

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
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

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let mut opaque_bundle = bundle.unwrap();
        let receipt = &mut opaque_bundle.sealed_header.header.receipt;
        assert_eq!(receipt.execution_trace.len(), 4);

        receipt.execution_trace[mismatch_trace_index] = Default::default();
        receipt.execution_trace_root = {
            let trace: Vec<_> = receipt
                .execution_trace
                .iter()
                .map(|t| t.encode().try_into().unwrap())
                .collect();
            MerkleTree::from_leaves(trace.as_slice())
                .root()
                .unwrap()
                .into()
        };
        opaque_bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
            .into();
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(opaque_bundle),
        )
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

    // Wait for the fraud proof that target the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProof::InvalidStateTransition(proof) = fp {
            match mismatch_trace_index {
                0 => assert!(matches!(
                    proof.execution_phase,
                    ExecutionPhase::InitializeBlock
                )),
                // 1 for the inherent timestamp extrinsic, 2 for the above `transfer_allow_death` extrinsic
                1 | 2 => assert!(matches!(
                    proof.execution_phase,
                    ExecutionPhase::ApplyExtrinsic { .. }
                )),
                3 => assert!(matches!(
                    proof.execution_phase,
                    ExecutionPhase::FinalizeBlock
                )),
                _ => unreachable!(),
            }
            true
        } else {
            false
        }
    });

    // Produce a consensus block that contains the `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    // When the system domain node process the primary block that contains the `bad_submit_bundle_tx`,
    // it will generate and submit a fraud proof
    let _ = wait_for_fraud_proof_fut.await;

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, thus pruned the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_true_invalid_bundles_inherent_extrinsic_proof_creation_and_verification() {
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

    let bundle_to_tx = |opaque_bundle| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        )
        .into()
    };

    let inherent_extrinsic = || {
        let now = 1234;
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_timestamp::Call::set { now }.into(),
        )
        .into()
    };

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
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

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());
    let extrinsics: Vec<Vec<u8>>;
    let bundle_extrinsic_root;
    let bad_submit_bundle_tx = {
        let mut opaque_bundle = bundle.unwrap();
        opaque_bundle.extrinsics.push(inherent_extrinsic());
        extrinsics = opaque_bundle
            .extrinsics
            .clone()
            .into_iter()
            .map(|ext| ext.encode())
            .collect();
        bundle_extrinsic_root =
            BlakeTwo256::ordered_trie_root(extrinsics.clone(), StateVersion::V1);
        opaque_bundle.sealed_header.header.bundle_extrinsics_root = bundle_extrinsic_root;
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

    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // produce another bundle that marks the previous extrinsic as invalid.
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let mut opaque_bundle = bundle.unwrap();
        let bad_receipt = &mut opaque_bundle.sealed_header.header.receipt;
        // bad receipt marks this particular bundle as valid even though bundle contains inherent extrinsic
        bad_receipt.inboxed_bundles =
            vec![InboxedBundle::valid(H256::random(), bundle_extrinsic_root)];

        opaque_bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
            .into();
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(opaque_bundle),
        )
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

    // Wait for the fraud proof that target the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProof::InvalidBundles(proof) = fp {
            if let InvalidBundleType::InherentExtrinsic(_) = proof.invalid_bundle_type {
                assert!(proof.is_true_invalid_fraud_proof);
                return true;
            }
        }
        false
    });

    // Produce a consensus block that contains the `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let _ = wait_for_fraud_proof_fut.await;

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, thus pruned the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_false_invalid_bundles_inherent_extrinsic_proof_creation_and_verification() {
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

    let bundle_to_tx = |opaque_bundle| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        )
        .into()
    };

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let target_bundle = bundle.unwrap();
    assert_eq!(target_bundle.extrinsics.len(), 1);
    let extrinsics: Vec<Vec<u8>> = target_bundle
        .extrinsics
        .clone()
        .into_iter()
        .map(|ext| ext.encode())
        .collect();
    let bundle_extrinsic_root =
        BlakeTwo256::ordered_trie_root(extrinsics.clone(), StateVersion::V1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // produce another bundle that marks the previous valid extrinsic as invalid.
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let mut opaque_bundle = bundle.unwrap();
        let bad_receipt = &mut opaque_bundle.sealed_header.header.receipt;
        // bad receipt marks this particular bundle as invalid even though bundle does not contain
        // inherent extrinsic
        bad_receipt.inboxed_bundles = vec![InboxedBundle::invalid(
            InvalidBundleType::InherentExtrinsic(0),
            bundle_extrinsic_root,
        )];

        opaque_bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
            .into();
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(opaque_bundle),
        )
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

    // Wait for the fraud proof that target the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProof::InvalidBundles(proof) = fp {
            if let InvalidBundleType::InherentExtrinsic(_) = proof.invalid_bundle_type {
                assert!(!proof.is_true_invalid_fraud_proof);
                return true;
            }
        }
        false
    });

    // Produce a consensus block that contains the `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let _ = wait_for_fraud_proof_fut.await;

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, thus pruned the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_true_invalid_bundles_illegal_extrinsic_proof_creation_and_verification() {
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

    let bundle_to_tx = |opaque_bundle| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        )
        .into()
    };

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let target_bundle = bundle.unwrap();
    assert_eq!(target_bundle.extrinsics.len(), 0);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());

    let alice_balance = alice.free_balance(Alice.to_account_id());
    let mut alice_nonce = alice.account_nonce();
    let transfer_to_charlie_with_big_tip_1 = alice.construct_extrinsic_with_tip(
        alice_nonce,
        alice_balance / 3,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 1,
        },
    );
    alice_nonce += 1;

    let transfer_to_charlie_with_big_tip_2 = alice.construct_extrinsic_with_tip(
        alice_nonce,
        alice_balance / 3,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 1,
        },
    );
    alice_nonce += 1;

    // This would be illegal
    let transfer_to_charlie_with_big_tip_3 = alice.construct_extrinsic_with_tip(
        alice_nonce,
        alice_balance / 3,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 1,
        },
    );

    let extrinsics: Vec<Vec<u8>>;
    let bundle_extrinsic_root;
    let bad_submit_bundle_tx = {
        let mut opaque_bundle = bundle.unwrap();
        opaque_bundle.extrinsics = vec![
            transfer_to_charlie_with_big_tip_1.into(),
            transfer_to_charlie_with_big_tip_2.into(),
            transfer_to_charlie_with_big_tip_3.into(),
        ];
        extrinsics = opaque_bundle
            .extrinsics
            .clone()
            .into_iter()
            .map(|ext| ext.encode())
            .collect();
        bundle_extrinsic_root =
            BlakeTwo256::ordered_trie_root(extrinsics.clone(), StateVersion::V1);
        opaque_bundle.sealed_header.header.bundle_extrinsics_root = bundle_extrinsic_root;
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

    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // produce another bundle that marks the previous extrinsic as invalid.
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let mut opaque_bundle = bundle.unwrap();
        let bad_receipt = &mut opaque_bundle.sealed_header.header.receipt;
        // bad receipt marks this particular bundle as valid even though bundle contains illegal extrinsic
        bad_receipt.inboxed_bundles =
            vec![InboxedBundle::valid(H256::random(), bundle_extrinsic_root)];

        opaque_bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
            .into();
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(opaque_bundle),
        )
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

    // Wait for the fraud proof that target the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProof::InvalidBundles(proof) = fp {
            if let InvalidBundleType::IllegalTx(extrinsic_index) = proof.invalid_bundle_type {
                assert!(proof.is_true_invalid_fraud_proof);
                assert_eq!(extrinsic_index, 2);
                return true;
            }
        }
        false
    });

    // Produce a consensus block that contains the `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let _ = wait_for_fraud_proof_fut.await;

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, thus pruned the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_false_invalid_bundles_illegal_extrinsic_proof_creation_and_verification() {
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

    let bundle_to_tx = |opaque_bundle| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        )
        .into()
    };

    // transfer most of the alice's balance
    let alice_balance = alice.free_balance(Alice.to_account_id());

    let mut alice_nonce = alice.account_nonce();

    let transfer_to_charlie_with_big_tip_1 = alice.construct_extrinsic_with_tip(
        alice_nonce,
        alice_balance / 3,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 1,
        },
    );
    alice_nonce += 1;

    let transfer_to_charlie_with_big_tip_2 = alice.construct_extrinsic_with_tip(
        alice_nonce,
        alice_balance / 3,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 1,
        },
    );

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .send_extrinsic(transfer_to_charlie_with_big_tip_1.clone())
        .await
        .expect("Failed to send extrinsic");

    alice
        .send_extrinsic(transfer_to_charlie_with_big_tip_2.clone())
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let target_bundle = bundle.unwrap();
    assert_eq!(target_bundle.extrinsics.len(), 2);
    let bundle_extrinsic_root = target_bundle.extrinsics_root();
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // produce another bundle that marks the previous valid extrinsic as invalid.
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let mut opaque_bundle = bundle.unwrap();
        let bad_receipt = &mut opaque_bundle.sealed_header.header.receipt;
        // bad receipt marks this particular bundle as invalid even though bundle does not contain
        // illegal tx
        bad_receipt.inboxed_bundles = vec![InboxedBundle::invalid(
            InvalidBundleType::IllegalTx(1),
            bundle_extrinsic_root,
        )];

        opaque_bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
            .into();
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(opaque_bundle),
        )
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

    // Wait for the fraud proof that target the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProof::InvalidBundles(proof) = fp {
            if let InvalidBundleType::IllegalTx(extrinsic_index) = proof.invalid_bundle_type {
                assert!(!proof.is_true_invalid_fraud_proof);
                assert_eq!(extrinsic_index, 1);
                return true;
            }
        }
        false
    });

    // Produce a consensus block that contains the `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let _ = wait_for_fraud_proof_fut.await;

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, thus pruned the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_total_rewards_proof_creation() {
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

    let bundle_to_tx = |opaque_bundle| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        )
        .into()
    };

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
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

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let mut opaque_bundle = bundle.unwrap();
        let receipt = &mut opaque_bundle.sealed_header.header.receipt;
        receipt.total_rewards = Default::default();
        opaque_bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
            .into();
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(opaque_bundle),
        )
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

    // Wait for the fraud proof that target the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        matches!(
            fp,
            FraudProof::InvalidTotalRewards(InvalidTotalRewardsProof { .. })
        )
    });

    // Produce a consensus block that contains the `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    // When the domain node operator process the primary block that contains the `bad_submit_bundle_tx`,
    // it will generate and submit a fraud proof
    let _ = wait_for_fraud_proof_fut.await;

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, thus pruned the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_domain_block_hash_proof_creation() {
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

    let bundle_to_tx = |opaque_bundle| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        )
        .into()
    };

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
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

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let mut opaque_bundle = bundle.unwrap();
        let receipt = &mut opaque_bundle.sealed_header.header.receipt;
        receipt.domain_block_hash = Default::default();
        opaque_bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
            .into();
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(opaque_bundle),
        )
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

    // Wait for the fraud proof that target the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        matches!(
            fp,
            FraudProof::InvalidDomainBlockHash(InvalidDomainBlockHashProof { .. })
        )
    });

    // Produce a consensus block that contains the `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    // When the domain node operator process the primary block that contains the `bad_submit_bundle_tx`,
    // it will generate and submit a fraud proof
    let _ = wait_for_fraud_proof_fut.await;

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, thus pruned the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_domain_extrinsics_root_proof_creation() {
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

    let bundle_to_tx = |opaque_bundle| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        )
        .into()
    };

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
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

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let mut opaque_bundle = bundle.unwrap();
        let receipt = &mut opaque_bundle.sealed_header.header.receipt;
        receipt.domain_block_extrinsic_root = Default::default();
        opaque_bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
            .into();
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(opaque_bundle),
        )
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

    // Wait for the fraud proof that target the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        matches!(
            fp,
            FraudProof::InvalidExtrinsicsRoot(InvalidExtrinsicsRootProof { .. })
        )
    });

    // Produce a consensus block that contains the `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    // When the domain node operator process the primary block that contains the `bad_submit_bundle_tx`,
    // it will generate and submit a fraud proof
    let _ = wait_for_fraud_proof_fut.await;

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, thus pruned the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bundle_equivocation_fraud_proof() {
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let bundle_to_tx = |opaque_bundle| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        )
        .into()
    };

    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());

    // Remove the original bundle submission and resubmit it again.
    // This is done since when the bundle is submitted through offchain transaction submission
    // the validation is skipped for local transactions and this bundle slot is not stored in the Aux storage
    // so when we resubmit the transaction through `submit_transaction`, it will go through validation
    // process and the first bundle after validating will go through the validation and Aux storage
    // updated. When the equivocated bundle is submitted next, the Aux storage is used to check equivocation.
    //
    // In the production behaviour will not cause any issues, since we trust the local transactions
    // and will only check equivocations for the transactions coming from the network.
    ferdie
        .prune_tx_from_pool(&original_submit_bundle_tx)
        .await
        .unwrap();
    assert!(ferdie.get_bundle_from_tx_pool(slot.into()).is_none());

    ferdie
        .submit_transaction(original_submit_bundle_tx)
        .await
        .unwrap();

    // change the bundle contents such that we derive a new bundle
    // with same slot and proof of election such that this leads to bundle equivocation.
    let equivocated_bundle_tx = {
        let mut opaque_bundle = bundle.unwrap();
        let receipt = &mut opaque_bundle.sealed_header.header.receipt;
        receipt.domain_block_extrinsic_root = Default::default();
        opaque_bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
            .into();
        bundle_to_tx(opaque_bundle)
    };

    let wait_for_fraud_proof_fut =
        ferdie.wait_for_fraud_proof(move |fp| matches!(fp, FraudProof::BundleEquivocation(_)));

    match ferdie
        .submit_transaction(equivocated_bundle_tx)
        .await
        .unwrap_err()
    {
        sc_transaction_pool::error::Error::Pool(
            sc_transaction_pool_api::error::Error::InvalidTransaction(_),
        ) => {}
        e => panic!("Unexpected error while submitting fraud proof: {e}"),
    }

    let _ = wait_for_fraud_proof_fut.await;

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified on
    // on the runtime itself
    ferdie.produce_blocks(1).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_block_builder_include_ext_with_failed_execution() {
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
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // produce a transfer from alice to bob
    // we send two transactions, first one must succeed, while second one will fail
    // second extrinsic fails due to not enough balance but should still be included in the domain
    // block body
    let pre_alice_free_balance = alice.free_balance(Alice.to_account_id());
    let alice_account_nonce = alice.account_nonce();

    // first ext that must succeed
    let tx = alice.construct_extrinsic(
        alice_account_nonce,
        pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            // we send half of alice balance to bob
            value: pre_alice_free_balance / 2,
        },
    );
    alice
        .send_extrinsic(tx)
        .await
        .expect("Failed to send extrinsic");

    // second ext that will fail due to balance restrictions.
    let tx = alice.construct_extrinsic(
        alice_account_nonce + 1,
        pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            // try to send value that is more than what alice has
            value: pre_alice_free_balance,
        },
    );
    alice
        .send_extrinsic(tx)
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle and submit to the tx pool of the consensus node
    let (_slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert!(bundle.is_some());
    let bundle = bundle.unwrap();
    assert_eq!(bundle.extrinsics.len(), 2);

    // produce block and import domain block
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // domain block body should have 3 extrinsics
    // timestamp inherent, successful transfer, failed transfer
    let best_hash = alice.client.info().best_hash;
    let domain_block_extrinsics = alice.client.block_body(best_hash).unwrap();
    assert_eq!(domain_block_extrinsics.unwrap().len(), 3);

    // next bundle should have er which should a total of 5 trace roots
    // pre_timestamp_root + pre_success_ext_root + pre_failed_ext_root + pre_finalize_block_root
    // + post_finalize_block_root
    let (_slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert!(bundle.is_some());
    let bundle = bundle.unwrap();
    let er = bundle.receipt();
    assert_eq!(er.execution_trace.len(), 5);
    assert_eq!(er.execution_trace[4], er.final_state_root);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_block_builder_include_ext_with_failed_predispatch() {
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
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // produce a transfer from alice to bob in one bundle, which should succeed
    let pre_alice_free_balance = alice.free_balance(Alice.to_account_id());
    let alice_account_nonce = alice.account_nonce();

    let tx = alice.construct_extrinsic(
        alice_account_nonce,
        pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            // we send half of alice balance to bob
            value: pre_alice_free_balance / 2,
        },
    );
    alice
        .send_extrinsic(tx)
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle and submit to the tx pool of the consensus node
    let (_slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert!(bundle.is_some());
    let bundle = bundle.unwrap();
    assert_eq!(bundle.extrinsics.len(), 1);

    // we produce another bundle with similar transaction
    // second one will fail at pre dispatch since we use same nonce
    // we change the value to something else so that ext is different
    // send the tip so that previous ext is replaced with current in Domain tx pool
    let tip = 1000000;
    let tx = alice.construct_extrinsic_with_tip(
        // use the same nonce
        alice_account_nonce,
        tip,
        pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: pre_alice_free_balance / 3,
        },
    );
    alice
        .send_extrinsic(tx)
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle and submit to the tx pool of the consensus node
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert!(bundle.is_some());
    let bundle = bundle.unwrap();
    assert_eq!(bundle.extrinsics.len(), 1);

    // produce block and import domain block
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // domain block body should have 3 extrinsics
    // timestamp inherent, successful transfer, failed transfer
    let best_hash = alice.client.info().best_hash;
    let domain_block_extrinsics = alice.client.block_body(best_hash).unwrap();
    assert_eq!(domain_block_extrinsics.clone().unwrap().len(), 3);

    // next bundle should have er which should a total of 5 trace roots
    // pre_timestamp_root + pre_success_ext_root + pre_failed_ext_root + pre_finalize_block_root
    // + post_finalize_block_root
    let (_slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert!(bundle.is_some());
    let bundle = bundle.unwrap();
    let er = bundle.sealed_header.header.receipt;

    assert_eq!(er.execution_trace.len(), 5);
    assert_eq!(er.execution_trace[4], er.final_state_root);

    let header = alice.client.header(best_hash).unwrap().unwrap();
    assert_eq!(
        *header.extrinsics_root(),
        BlakeTwo256::ordered_trie_root(
            domain_block_extrinsics
                .unwrap()
                .iter()
                .map(Encode::encode)
                .collect(),
            sp_core::storage::StateVersion::V1
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_valid_bundle_proof_generation_and_verification() {
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
    let proof_to_tx = |proof| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_fraud_proof {
                fraud_proof: Box::new(FraudProof::ValidBundle(proof)),
            }
            .into(),
        )
        .into()
    };

    // Produce a bundle that will include the reciept of the last 3 bundles and modified the receipt's
    // `inboxed_bundles` field to make it invalid
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());
    let bundle_index = 1;
    let (bad_receipt, submit_bundle_tx_with_bad_receipt) = {
        let mut bundle = bundle.unwrap();
        assert_eq!(bundle.receipt().inboxed_bundles.len(), 3);

        bundle.sealed_header.header.receipt.inboxed_bundles[bundle_index].bundle =
            BundleValidity::Valid(H256::random());
        bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(bundle.sealed_header.pre_hash().as_ref())
            .into();

        (bundle.receipt().clone(), bundle_to_tx(bundle))
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

    // Produce a consensus block that contains the `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    let mut import_tx_stream = ferdie.transaction_pool.import_notification_stream();
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert!(ferdie
        .does_receipt_exist(bad_receipt.hash::<BlakeTwo256>())
        .unwrap());

    // When the domain node operator process the primary block that contains the `bad_submit_bundle_tx`,
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
            pallet_domains::Call::submit_fraud_proof { fraud_proof },
        ) = ext.function
        {
            if let FraudProof::ValidBundle(proof) = *fraud_proof {
                // The fraud proof is targetting the `bad_receipt`
                assert_eq!(
                    proof.bad_receipt_hash,
                    bad_receipt.hash::<HeaderHashingFor<Header>>()
                );

                // If the fraud proof target a non-exist receipt then it is invalid
                let mut bad_proof = proof.clone();
                bad_proof.bad_receipt_hash = H256::random();
                assert!(ferdie
                    .submit_transaction(proof_to_tx(bad_proof))
                    .await
                    .is_err());

                // If the fraud proof point to non-exist bundle then it is invalid
                let mut bad_proof = proof.clone();
                bad_proof.bundle_index = u32::MAX;
                assert!(ferdie
                    .submit_transaction(proof_to_tx(bad_proof))
                    .await
                    .is_err());

                break;
            }
        }
    }

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, thus pruned the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie
        .does_receipt_exist(bad_receipt.hash::<BlakeTwo256>())
        .unwrap());
}

// TODO: Add a new test which simulates a situation that an executor produces a fraud proof
// when an invalid receipt is received.

// TODO: construct a minimal consensus runtime code and use the `set_code` extrinsic to actually
// cover the case that the new domain runtime are updated accordingly upon the new consensus runtime.
#[tokio::test(flavor = "multi_thread")]
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
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

#[tokio::test(flavor = "multi_thread")]
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

#[tokio::test(flavor = "multi_thread")]
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 1).await.unwrap();

    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let submit_bundle_tx: OpaqueExtrinsic =
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle {
                opaque_bundle: bundle.unwrap(),
            }
            .into(),
        )
        .into();

    // Wait for one block to ensure the bundle is stored onchain.
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // Bundle is rejected because it is duplicated.
    match ferdie
        .submit_transaction(submit_bundle_tx.clone())
        .await
        .unwrap_err()
    {
        sc_transaction_pool::error::Error::Pool(TxPoolError::InvalidTransaction(invalid_tx)) => {
            assert_eq!(invalid_tx, InvalidTransactionCode::Bundle.into())
        }
        e => panic!("Unexpected error: {e}"),
    }

    // Wait for `BlockTreePruningDepth + 1` blocks which is 16 + 1 in test
    produce_blocks!(ferdie, alice, 17).await.unwrap();

    // Bundle is now rejected because its receipt is pruned.
    match ferdie
        .submit_transaction(submit_bundle_tx)
        .await
        .unwrap_err()
    {
        sc_transaction_pool::error::Error::Pool(TxPoolError::InvalidTransaction(invalid_tx)) => {
            assert_eq!(invalid_tx, InvalidTransactionCode::ExecutionReceipt.into())
        }
        e => panic!("Unexpected error: {e}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
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

    // Bundle can be successfully submitted to the new fork, or it is also possible
    // that the `submit_bundle_tx` in the retracted block has been resubmitted to the
    // tx pool in the background by the `txpool-notifications` worker.
    match ferdie.submit_transaction(submit_bundle_tx).await {
        Ok(_) | Err(sc_transaction_pool::error::Error::Pool(TxPoolError::AlreadyImported(_))) => {}
        Err(err) => panic!("Unexpected error: {err}"),
    }
}

// TODO: Unlock test when multiple domains are supported in DecEx v2.
// #[tokio::test(flavor = "multi_thread")]
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
//     .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
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
// #[tokio::test(flavor = "multi_thread")]
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
// .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
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

#[tokio::test(flavor = "multi_thread")]
// TODO: https://github.com/subspace/subspace/pull/1954 broke this on Windows, we suspect the test
//  is racy, but didn't find why and why it only fails on Windows. This needs to be fixed and test
//  un-ignored on Windows.
#[cfg_attr(windows, ignore)]
async fn test_restart_domain_operator() {
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();
    let next_slot = ferdie.next_slot();

    // Stop Ferdie and Alice and delete their database lock files
    drop(ferdie);
    drop(alice);
    std::fs::remove_file(directory.path().join("ferdie/paritydb/lock")).unwrap();
    std::fs::remove_file(
        directory
            .path()
            .join(format!("alice/domain-{GENESIS_DOMAIN_ID:?}"))
            .as_path()
            .join("paritydb/lock"),
    )
    .unwrap();

    // Restart Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );
    ferdie.set_next_slot(next_slot);

    // Restart Alice
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    // Chain should progress base on previous run
    assert_eq!(ferdie.client.info().best_number, 10);
    assert_eq!(alice.client.info().best_number, 10);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_transaction_fee_and_operator_reward() {
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

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Construct and submit an extrinsic with tip
    let pre_alice_free_balance = alice.free_balance(Alice.to_account_id());
    let tip = 123456;
    let tx = alice.construct_extrinsic_with_tip(
        alice.account_nonce(),
        tip,
        frame_system::Call::remark { remark: vec![] },
    );
    alice
        .send_extrinsic(tx)
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the just sent extrinsic
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.unwrap().extrinsics.len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contains the ER of the previous bundle
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.unwrap().into_receipt();
    assert_eq!(receipt.consensus_block_hash, consensus_block_hash);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // Transaction fee (including the tip) is deducted from alice's account
    let alice_free_balance_changes =
        pre_alice_free_balance - alice.free_balance(Alice.to_account_id());
    assert!(alice_free_balance_changes >= tip);

    // All the transaction fee is collected as operator reward
    assert_eq!(alice_free_balance_changes, receipt.total_rewards);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_consensus_blocks_derive_similar_domain_block() {
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();
    let common_block_hash = ferdie.client.info().best_hash;
    let bundle_to_tx = |opaque_bundle| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        )
        .into()
    };

    // Fork A
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    // Include one more extrinsic in fork A such that we can have a different consensus block
    let remark_tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
        frame_system::Call::remark { remark: vec![0; 8] }.into(),
    )
    .into();
    let consensus_block_hash_fork_a = ferdie
        .produce_block_with_slot_at(
            slot,
            common_block_hash,
            Some(vec![bundle_to_tx(bundle.clone().unwrap()), remark_tx]),
        )
        .await
        .unwrap();

    // Fork B
    let consensus_block_hash_fork_b = ferdie
        .produce_block_with_slot_at(
            slot,
            common_block_hash,
            Some(vec![bundle_to_tx(bundle.unwrap())]),
        )
        .await
        .unwrap();
    // Produce one more consensus block to make fork B the best fork and trigger processing
    // on fork B
    let slot = ferdie.produce_slot();
    ferdie
        .produce_block_with_slot_at(slot, consensus_block_hash_fork_b, Some(vec![]))
        .await
        .unwrap();

    assert_ne!(consensus_block_hash_fork_a, consensus_block_hash_fork_b);

    // Both consensus block from fork A and B should derive a corresponding domain block
    let domain_block_hash_fork_a =
        crate::aux_schema::best_domain_hash_for(&*alice.client, &consensus_block_hash_fork_a)
            .unwrap()
            .unwrap();
    let domain_block_hash_fork_b =
        crate::aux_schema::best_domain_hash_for(&*alice.client, &consensus_block_hash_fork_b)
            .unwrap()
            .unwrap();
    assert_ne!(domain_block_hash_fork_a, domain_block_hash_fork_b);

    // The domain block header should contains digest that point to the consensus block, which
    // devrive the domain block
    let get_header = |hash| alice.client.header(hash).unwrap().unwrap();
    let get_digest_consensus_block_hash = |header: &Header| -> <CBlock as BlockT>::Hash {
        header
            .digest()
            .convert_first(DigestItem::as_consensus_block_info)
            .unwrap()
    };
    let domain_block_header_fork_a = get_header(domain_block_hash_fork_a);
    let domain_block_header_fork_b = get_header(domain_block_hash_fork_b);
    let digest_consensus_block_hash_fork_a =
        get_digest_consensus_block_hash(&domain_block_header_fork_a);
    assert_eq!(
        digest_consensus_block_hash_fork_a,
        consensus_block_hash_fork_a
    );
    let digest_consensus_block_hash_fork_b =
        get_digest_consensus_block_hash(&domain_block_header_fork_b);
    assert_eq!(
        digest_consensus_block_hash_fork_b,
        consensus_block_hash_fork_b
    );

    // The domain block headers should have the same `parent_hash` and `extrinsics_root`
    // but different digest and `state_root` (because digest is stored on chain)
    assert_eq!(
        domain_block_header_fork_a.parent_hash(),
        domain_block_header_fork_b.parent_hash()
    );
    assert_eq!(
        domain_block_header_fork_a.extrinsics_root(),
        domain_block_header_fork_b.extrinsics_root()
    );
    assert_ne!(
        domain_block_header_fork_a.digest(),
        domain_block_header_fork_b.digest()
    );
    assert_ne!(
        domain_block_header_fork_a.state_root(),
        domain_block_header_fork_b.state_root()
    );

    // Simply produce more block
    produce_blocks!(ferdie, alice, 3).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_skip_empty_bundle_production() {
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

    // Run Alice (a evm domain authority node) with `skip_empty_bundle_production` set to `true`
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .skip_empty_bundle()
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    // Wait for `BlockTreePruningDepth + 1` blocks which is 16 + 1 in test
    // to enure the genesis ER is confirmed
    produce_blocks!(ferdie, alice, 17).await.unwrap();
    let consensus_block_number = ferdie.client.info().best_number;
    let domain_block_number = alice.client.info().best_number;

    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    ferdie.produce_block_with_slot(slot).await.unwrap();

    // Alice will skip producing bundle since there is no domain extrinsic
    assert!(bundle.is_none());
    assert_eq!(ferdie.client.info().best_number, consensus_block_number + 1);
    assert_eq!(alice.client.info().best_number, domain_block_number);

    // Send a domain extrinsic, Alice will start producing bundle
    alice.send_system_remark().await;
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert!(bundle.is_some());
    assert_eq!(ferdie.client.info().best_number, consensus_block_number + 2);
    assert_eq!(alice.client.info().best_number, domain_block_number + 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bad_receipt_chain() {
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
    .build_evm_node(Role::Authority, GENESIS_DOMAIN_ID, &mut ferdie)
    .await;

    let bundle_to_tx = |opaque_bundle| {
        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
        )
        .into()
    };

    let bundle_producer = {
        let domain_bundle_proposer = DomainBundleProposer::new(
            GENESIS_DOMAIN_ID,
            alice.client.clone(),
            ferdie.client.clone(),
            alice.operator.transaction_pool.clone(),
        );
        let (bundle_sender, _bundle_receiver) =
            sc_utils::mpsc::tracing_unbounded("domain_bundle_stream", 100);
        DomainBundleProducer::new(
            GENESIS_DOMAIN_ID,
            ferdie.client.clone(),
            alice.client.clone(),
            domain_bundle_proposer,
            Arc::new(bundle_sender),
            alice.operator.keystore.clone(),
            false,
        )
    };

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let original_submit_bundle_tx = bundle_to_tx(bundle.clone().unwrap());
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let mut opaque_bundle = bundle.unwrap();
        let receipt = &mut opaque_bundle.sealed_header.header.receipt;
        receipt.total_rewards = 100;
        opaque_bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
            .into();
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(opaque_bundle),
        )
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

    // Produce a consensus block that contains the `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    // Remove the fraud proof from tx pool
    ferdie.clear_tx_pool().await.unwrap();

    // Produce a bundle with another bad ER that use previous bad ER as parent
    let parent_bad_receipt_hash = bad_receipt_hash;
    let slot = ferdie.produce_slot();
    let bundle = {
        let consensus_block_info = sp_blockchain::HashAndNumber {
            number: ferdie.client.info().best_number,
            hash: ferdie.client.info().best_hash,
        };
        bundle_producer
            .clone()
            .produce_bundle(
                0,
                consensus_block_info,
                OperatorSlotInfo {
                    slot,
                    global_randomness: Randomness::from(Hash::random().to_fixed_bytes()),
                },
            )
            .await
            .expect("produce bundle must success")
            .expect("must win the challenge")
    };
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let mut opaque_bundle = bundle;
        let receipt = &mut opaque_bundle.sealed_header.header.receipt;
        receipt.parent_domain_block_receipt_hash = parent_bad_receipt_hash;
        receipt.total_rewards = 100;
        opaque_bundle.sealed_header.signature = Sr25519Keyring::Alice
            .pair()
            .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
            .into();
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(opaque_bundle),
        )
    };
    ferdie
        .submit_transaction(bad_submit_bundle_tx)
        .await
        .unwrap();

    // Wait for a fraud proof that target the first bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        matches!(
            fp,
            FraudProof::InvalidTotalRewards(InvalidTotalRewardsProof { .. })
        ) && fp.targeted_bad_receipt_hash() == Some(parent_bad_receipt_hash)
    });

    // Produce a consensus block that contains the bad receipt and it should
    // be added to the consensus chain block tree
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    // The fraud proof should be submitted
    let _ = wait_for_fraud_proof_fut.await;

    // Both bad ER should be pruned
    ferdie.produce_blocks(1).await.unwrap();
    for er_hash in [parent_bad_receipt_hash, bad_receipt_hash] {
        assert!(!ferdie.does_receipt_exist(er_hash).unwrap());
    }
}

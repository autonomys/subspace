use codec::{Decode, Encode};
use domain_runtime_primitives::{DomainCoreApi, Hash};
use domain_test_service::runtime::{Header, UncheckedExtrinsic};
use domain_test_service::Keyring::{Alice, Bob, Ferdie};
use sc_client_api::{Backend, BlockBackend, HeaderBackend};
use sc_executor_common::runtime_blob::RuntimeBlob;
use sc_service::{BasePath, Role};
use sc_transaction_pool_api::error::Error as TxPoolError;
use sp_api::{AsTrieBackend, ProvideRuntimeApi};
use sp_core::traits::FetchRuntimeCode;
use sp_core::Pair;
use sp_domain_digests::AsPredigest;
use sp_domains::fraud_proof::{ExecutionPhase, FraudProof, InvalidStateTransitionProof};
use sp_domains::transaction::InvalidTransactionCode;
use sp_domains::{DomainId, ExecutionReceipt, ExecutorApi, SignedBundle};
use sp_runtime::generic::{BlockId, Digest, DigestItem};
use sp_runtime::traits::{BlakeTwo256, Hash as HashT, Header as HeaderT};
use sp_runtime::OpaqueExtrinsic;
use subspace_core_primitives::BlockNumber;
use subspace_fraud_proof::invalid_state_transition_proof::ExecutionProver;
use subspace_test_service::mock::MockPrimaryNode;
use subspace_wasm_tools::read_core_domain_runtime_blob;
use tempfile::TempDir;

fn number_of(primary_node: &MockPrimaryNode, block_hash: Hash) -> u32 {
    primary_node
        .client
        .number(block_hash)
        .unwrap_or_else(|err| panic!("Failed to fetch number for {block_hash}: {err}"))
        .unwrap_or_else(|| panic!("header {block_hash} not in the chain"))
}

/// Returns a list of (block_number, block_hash) ranging from head_receipt_number(exclusive) to best_header(inclusive).
fn number_hash_mappings_from_head_receipt_number_to_best_header(
    primary_node: &MockPrimaryNode,
    best_header: Header,
) -> Vec<(u32, Hash)> {
    let head_receipt_number = primary_node
        .client
        .runtime_api()
        .head_receipt_number(best_header.hash())
        .unwrap();

    let mut current_best = best_header;
    let mut mappings = vec![];
    while *current_best.number() > head_receipt_number {
        mappings.push((*current_best.number(), current_best.hash()));
        current_best = primary_node
            .client
            .header(*current_best.parent_hash())
            .unwrap()
            .unwrap();
    }

    mappings.reverse();

    mappings
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn collected_receipts_should_be_on_the_same_branch_with_current_best_block() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");
    let _ = sc_cli::LoggerBuilder::new("runtime=debug").init();
    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut primary_node = MockPrimaryNode::run_mock_primary_node(
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
    .build_with_mock_primary_node(Role::Authority, &mut primary_node)
    .await;

    futures::join!(alice.wait_for_blocks(3), primary_node.produce_blocks(3))
        .1
        .expect("3 primary blocks produced successfully");

    let best_primary_hash = primary_node.client.info().best_hash;
    let best_primary_number = primary_node.client.info().best_number;
    assert_eq!(best_primary_number, 3);

    let best_header = primary_node
        .client
        .header(best_primary_hash)
        .unwrap()
        .unwrap();

    let parent_hash = *best_header.parent_hash();

    let load_receipt = |primary_hash| -> Option<ExecutionReceipt<BlockNumber, Hash, Hash>> {
        crate::aux_schema::load_execution_receipt::<_, _, BlockNumber, _>(
            &*alice.backend,
            primary_hash,
        )
        .unwrap_or_else(|err| panic!("Error occurred when loading execution receipt: {err}"))
    };

    // There is a chance that the receipt for #3 is not available at this point because
    // writing the receipt happens in the background concurrently after the domain block #3
    // notification is out.
    //
    // NOTE: There is a distinction between the domain block and regular block pipeline.
    // - Regular block: fully imported to the blockchain database (block notification is fired at
    //                  this point).
    // - Domain block: fully imported to the blockchain database and the domain block
    //                 post-hook (writing the receipt, etc) is finished.
    //
    // This difference should be okay in practice, we'll see if we need to take some actions in
    // future and only take it into account in the tests for now.
    let mut retries = 0;
    loop {
        if retries >= 10 || load_receipt(best_primary_hash).is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        retries += 1;
    }

    assert!(
        load_receipt(best_primary_hash).is_some(),
        "Executor failed to process and generate the receipt of last primary block in 50ms"
    );

    // Primary chain forks:
    //      3
    //   /
    // 2 -- 3a
    //   \
    //      3b -- 4
    let slot = primary_node.produce_slot();
    let fork_block_hash_3a = primary_node
        .produce_block_with_slot_at(slot, parent_hash, Some(vec![]))
        .await
        .expect("Produced first primary fork block 3a at height #3");
    // A fork block 3a at #3 produced.
    assert_eq!(number_of(&primary_node, fork_block_hash_3a), 3);
    assert_ne!(fork_block_hash_3a, best_primary_hash);
    // Best hash unchanged due to the longest chain fork choice.
    assert_eq!(primary_node.client.info().best_hash, best_primary_hash);
    // Hash of block number #3 unchanged.
    assert_eq!(
        primary_node.client.hash(3).unwrap().unwrap(),
        best_primary_hash
    );

    let receipts_primary_info =
        |signed_bundle: SignedBundle<OpaqueExtrinsic, u32, sp_core::H256, sp_core::H256>| {
            signed_bundle
                .bundle
                .receipts
                .iter()
                .map(|receipt| (receipt.primary_number, receipt.primary_hash))
                .collect::<Vec<_>>()
        };

    // Produce a bundle after the fork block #3a has been produced.
    let signed_bundle = primary_node.notify_new_slot_and_wait_for_bundle(slot).await;

    let expected_receipts_primary_info =
        number_hash_mappings_from_head_receipt_number_to_best_header(
            &primary_node,
            best_header.clone(),
        );

    // TODO: make MaximumReceiptDrift configurable in order to submit all the pending receipts at
    // once, now the max drift is 2, the receipts is limitted to [2, 3]. Once configurable, we
    // can make the assertation straightforward:
    // assert_eq!(receipts_primary_info, expected_receipts_primary_info).
    //
    // Receipts are always collected against the current best block.
    receipts_primary_info(signed_bundle.unwrap())
        .into_iter()
        .zip(expected_receipts_primary_info.clone())
        .for_each(|(a, b)| assert_eq!(a, b));

    let slot = primary_node.produce_slot();
    let fork_block_hash_3b = primary_node
        .produce_block_with_slot_at(slot, parent_hash, Some(vec![]))
        .await
        .expect("Produced second primary fork block 3b at height #3");
    // Another fork block 3b at #3 produced,
    assert_eq!(number_of(&primary_node, fork_block_hash_3b), 3);
    assert_ne!(fork_block_hash_3b, best_primary_hash);
    // Best hash unchanged due to the longest chain fork choice.
    assert_eq!(primary_node.client.info().best_hash, best_primary_hash);
    // Hash of block number #3 unchanged.
    assert_eq!(
        primary_node.client.hash(3).unwrap().unwrap(),
        best_primary_hash
    );

    // Produce a bundle after the fork block #3b has been produced.
    let signed_bundle = primary_node.notify_new_slot_and_wait_for_bundle(slot).await;
    // Receipts are always collected against the current best block.
    receipts_primary_info(signed_bundle.unwrap())
        .into_iter()
        .zip(expected_receipts_primary_info)
        .for_each(|(a, b)| assert_eq!(a, b));

    // Produce a new tip at #4.
    let slot = primary_node.produce_slot();
    futures::join!(
        alice.wait_for_blocks(1),
        primary_node.produce_block_with_slot_at(slot, fork_block_hash_3b, Some(vec![])),
    )
    .1
    .expect("Produce a new block on top of the second fork block at height #3");
    let new_best_hash = primary_node.client.info().best_hash;
    let new_best_number = primary_node.client.info().best_number;
    assert_eq!(new_best_number, 4);
    assert_eq!(alice.client.info().best_number, 4);

    // Hash of block number #3 is updated to the second fork block 3b.
    assert_eq!(
        primary_node.client.hash(3).unwrap().unwrap(),
        fork_block_hash_3b
    );

    let new_best_header = primary_node.client.header(new_best_hash).unwrap().unwrap();

    assert_eq!(*new_best_header.parent_hash(), fork_block_hash_3b);

    // Produce a bundle after the new block #4 has been produced.
    let (_slot, signed_bundle) = primary_node
        .produce_slot_and_wait_for_bundle_submission()
        .await;

    let expected_receipts_primary_info =
        number_hash_mappings_from_head_receipt_number_to_best_header(
            &primary_node,
            new_best_header,
        );

    // Receipts are always collected against the current best block.
    receipts_primary_info(signed_bundle.unwrap())
        .into_iter()
        .zip(expected_receipts_primary_info)
        .for_each(|(a, b)| assert_eq!(a, b));
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn test_executor_full_node_catching_up() {
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
        alice.wait_for_blocks(3),
        bob.wait_for_blocks(3),
        ferdie.produce_blocks(3),
    )
    .2
    .unwrap();

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
        "Executor authority node and full node must have the same state"
    );
}

// TODO: enable the test after we can fetch call_data from the original primary block, currently the test
// will fail due to `panicked at 'Bad input data provided to initialize_block_with_post_state_root: Codec error'`
#[substrate_test_utils::test(flavor = "multi_thread")]
#[ignore]
async fn fraud_proof_verification_in_tx_pool_should_work() {
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

    // TODO: test the `initialize_block` fraud proof of block 1 with `wait_for_blocks(1)`
    // after https://github.com/subspace/subspace/issues/1301 is resolved.
    futures::join!(alice.wait_for_blocks(2), ferdie.produce_blocks(2))
        .1
        .unwrap();

    // Get a bundle from the txn pool and change its receipt to an invalid one
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let bad_bundle = {
        let mut signed_opaque_bundle = bundle.unwrap();
        signed_opaque_bundle.bundle.receipts[0].trace[0] = Default::default();
        signed_opaque_bundle
    };
    let bad_receipt = bad_bundle.bundle.receipts[0].clone();
    let bad_receipt_number = bad_receipt.primary_number;

    // Submit the bad receipt to the primary chain
    let submit_bundle_tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
        pallet_domains::Call::submit_bundle {
            signed_opaque_bundle: bad_bundle,
        }
        .into(),
    );
    futures::join!(
        alice.wait_for_blocks(1),
        ferdie.produce_block_with_extrinsics(vec![submit_bundle_tx.into()]),
    )
    .1
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

    let prover = ExecutionProver::new(
        alice.backend.clone(),
        alice.code_executor.clone(),
        Box::new(alice.task_manager.spawn_handle()),
    );

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
        domain_id: DomainId::SYSTEM,
        bad_receipt_hash: bad_receipt.hash(),
        parent_number: parent_number_ferdie,
        primary_parent_hash: parent_hash_ferdie,
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
    );

    let expected_tx_hash = tx.using_encoded(BlakeTwo256::hash);
    let tx_hash = ferdie
        .submit_transaction(tx.into())
        .await
        .expect("Error at submitting a valid fraud proof");
    assert_eq!(tx_hash, expected_tx_hash);

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

// TODO: construct a minimal primary runtime code and use the `set_code` extrinsic to actually
// cover the case that the new domain runtime are updated accordingly upon the new primary runtime.
#[substrate_test_utils::test(flavor = "multi_thread")]
#[ignore]
async fn set_new_code_should_work() {
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

    futures::join!(alice.wait_for_blocks(1), ferdie.produce_blocks(1))
        .1
        .unwrap();

    let new_runtime_wasm_blob = b"new_runtime_wasm_blob".to_vec();

    let best_number = alice.client.info().best_number;
    let primary_number = best_number + 1;
    // Although we're processing the bundle manually, the original bundle processor still works in
    // the meanwhile, it's possible the executor alice already processed this primary block, expecting next
    // primary block, in which case we use a dummy primary hash instead.
    //
    // Nice to disable the built-in bundle processor and have a full control of the executor block
    // production manually.
    let primary_hash = ferdie
        .client
        .hash(primary_number)
        .unwrap()
        .unwrap_or_else(Hash::random);
    alice
        .executor
        .clone()
        .process_bundles((primary_hash, primary_number))
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
async fn extract_core_domain_wasm_bundle_in_system_domain_runtime_should_work() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let ferdie = MockPrimaryNode::run_mock_primary_node(
        tokio_handle,
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    let system_domain_bundle = ferdie
        .client
        .runtime_api()
        .system_domain_wasm_bundle(ferdie.client.info().best_hash)
        .unwrap();

    let core_payments_runtime_blob =
        read_core_domain_runtime_blob(system_domain_bundle.as_ref(), DomainId::CORE_PAYMENTS)
            .unwrap();

    let core_payments_blob = RuntimeBlob::new(&core_payments_runtime_blob).unwrap();
    let core_payments_version = sc_executor::read_embedded_version(&core_payments_blob)
        .unwrap()
        .unwrap();

    assert_eq!(core_payments_version, core_payments_domain_runtime::VERSION);
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn pallet_domains_unsigned_extrinsics_should_work() {
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

    futures::join!(alice.wait_for_blocks(1), ferdie.produce_blocks(1))
        .1
        .unwrap();

    // Get a bundle from alice's tx pool and used as bundle template.
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let bundle_template = bundle.unwrap();
    let alice_key = alice.key;
    // Drop alice in order to control the execution chain by submitting the receipts manually later.
    drop(alice);

    // Wait for 5 blocks to make sure the execution receipts of block 2,3,4,5 are
    // able to be written to the database.
    futures::join!(bob.wait_for_blocks(5), ferdie.produce_blocks(5))
        .1
        .unwrap();

    let ferdie_client = ferdie.client.clone();
    let create_submit_bundle = |primary_number: BlockNumber| {
        let primary_hash = ferdie_client.hash(primary_number).unwrap().unwrap();
        let execution_receipt =
            crate::aux_schema::load_execution_receipt(&*bob.backend, primary_hash)
                .expect("Failed to load execution receipt from the local aux_db")
                .unwrap_or_else(|| {
                    panic!(
                        "The requested execution receipt for block {primary_number} does not exist"
                    )
                });

        let mut bundle = bundle_template.bundle.clone();
        bundle.header.primary_number = primary_number;
        bundle.header.primary_hash = primary_hash;
        bundle.receipts = vec![execution_receipt];

        let signature = alice_key.pair().sign(bundle.hash().as_ref()).into();

        let signed_opaque_bundle = SignedBundle {
            bundle,
            bundle_solution: bundle_template.bundle_solution.clone(),
            signature,
        };

        subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle {
                signed_opaque_bundle,
            }
            .into(),
        )
        .into()
    };

    let ferdie_client = ferdie.client.clone();
    let head_receipt_number = || {
        let best_hash = ferdie_client.info().best_hash;
        ferdie_client
            .runtime_api()
            .head_receipt_number(best_hash)
            .expect("Failed to get head receipt number")
    };

    ferdie
        .submit_transaction(create_submit_bundle(1))
        .await
        .unwrap();
    ferdie
        .submit_transaction(create_submit_bundle(2))
        .await
        .unwrap();
    futures::join!(bob.wait_for_blocks(1), ferdie.produce_blocks(1),)
        .1
        .unwrap();
    assert_eq!(head_receipt_number(), 2);

    // max drift is 2, hence the max allowed receipt number is 2 + 2, 5 will be rejected as being
    // too far.
    match ferdie
        .submit_transaction(create_submit_bundle(5))
        .await
        .unwrap_err()
    {
        sc_transaction_pool::error::Error::Pool(
            sc_transaction_pool_api::error::Error::InvalidTransaction(invalid_tx),
        ) => assert_eq!(invalid_tx, InvalidTransactionCode::ExecutionReceipt.into()),
        e => panic!("Unexpected error while submitting execution receipt: {e}"),
    }

    // The 4 is able to submit to tx pool but will fail to execute due to the receipt of 3 is missing.
    let submit_bundle_4 = create_submit_bundle(4);
    ferdie
        .submit_transaction(submit_bundle_4.clone())
        .await
        .unwrap();
    assert!(ferdie.produce_blocks(1).await.is_err());
    assert_eq!(head_receipt_number(), 2);

    // Re-submit 4 after 3, this time it will successfully execute and update the head receipt number.
    ferdie.remove_tx_from_tx_pool(&submit_bundle_4).unwrap();
    ferdie
        .submit_transaction(create_submit_bundle(3))
        .await
        .unwrap();
    ferdie
        .submit_transaction(create_submit_bundle(4))
        .await
        .unwrap();
    futures::join!(bob.wait_for_blocks(1), ferdie.produce_blocks(1),)
        .1
        .unwrap();
    assert_eq!(head_receipt_number(), 4);
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn duplicated_and_stale_bundle_should_be_rejected() {
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

    futures::join!(alice.wait_for_blocks(1), ferdie.produce_blocks(1))
        .1
        .unwrap();

    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let submit_bundle_tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
        pallet_domains::Call::submit_bundle {
            signed_opaque_bundle: bundle.unwrap(),
        }
        .into(),
    )
    .into();

    // Wait one block to ensure the bundle is stored onchain and manually remove it from tx pool
    futures::join!(
        alice.wait_for_blocks(1),
        ferdie.produce_block_with_slot(slot)
    )
    .1
    .unwrap();
    ferdie.remove_tx_from_tx_pool(&submit_bundle_tx).unwrap();

    // Bundle is rejected due to it is duplicated
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
    futures::join!(alice.wait_for_blocks(100), ferdie.produce_blocks(100))
        .1
        .unwrap();

    // Bundle is now rejected due to it is stale
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

    futures::join!(alice.wait_for_blocks(3), ferdie.produce_blocks(3))
        .1
        .unwrap();

    let mut parent_hash = ferdie.client.info().best_hash;

    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let submit_bundle_tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
        pallet_domains::Call::submit_bundle {
            signed_opaque_bundle: bundle.unwrap(),
        }
        .into(),
    )
    .into();

    // Wait one block to ensure the bundle is stored on this fork
    futures::join!(
        alice.wait_for_blocks(1),
        ferdie.produce_block_with_slot(slot)
    )
    .1
    .unwrap();

    // Create fork and build one more blocks on it to make it the new best fork
    parent_hash = ferdie
        .produce_block_with_slot_at(slot, parent_hash, Some(vec![]))
        .await
        .unwrap();
    futures::join!(
        alice.wait_for_blocks(1),
        ferdie.produce_block_with_slot_at(slot + 1, parent_hash, Some(vec![]))
    )
    .1
    .unwrap();

    // Manually remove the retracted block's `submit_bundle_tx` from tx pool
    ferdie.remove_tx_from_tx_pool(&submit_bundle_tx).unwrap();

    // Bundle can be successfully submitted to the new fork
    ferdie.submit_transaction(submit_bundle_tx).await.unwrap();
}

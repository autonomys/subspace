use codec::{Decode, Encode};
use domain_runtime_primitives::{DomainCoreApi, Hash};
use domain_test_service::run_primary_chain_validator_node;
use domain_test_service::runtime::{Header, UncheckedExtrinsic};
use domain_test_service::Keyring::{Alice, Bob, Ferdie};
use sc_client_api::{Backend, BlockBackend, HeaderBackend};
use sc_executor_common::runtime_blob::RuntimeBlob;
use sc_service::{BasePath, Role};
use sc_transaction_pool_api::TransactionSource;
use sp_api::{AsTrieBackend, ProvideRuntimeApi};
use sp_core::traits::FetchRuntimeCode;
use sp_core::Pair;
use sp_domain_digests::AsPredigest;
use sp_domains::fraud_proof::{ExecutionPhase, FraudProof, InvalidStateTransitionProof};
use sp_domains::transaction::InvalidTransactionCode;
use sp_domains::{
    Bundle, BundleHeader, BundleSolution, DomainId, ExecutorApi, ExecutorPair, ProofOfElection,
    SignedBundle,
};
use sp_runtime::generic::{BlockId, Digest, DigestItem};
use sp_runtime::traits::{BlakeTwo256, Hash as HashT, Header as HeaderT};
use std::collections::HashSet;
use subspace_core_primitives::BlockNumber;
use subspace_test_service::mock::MockPrimaryNode;
use subspace_wasm_tools::read_core_domain_runtime_blob;
use tempfile::TempDir;

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

// TODO: This test fails if running all the tests in this crate
// with `cargo test -- --ignored`, but passes if running individually, `cargo nextest run` also
// passes.
#[substrate_test_utils::test(flavor = "multi_thread")]
#[ignore]
async fn fraud_proof_verification_in_tx_pool_should_work() {
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
    .build(Role::Authority, false, true)
    .await;

    alice.wait_for_blocks(3).await;

    let header = alice
        .client
        .header(alice.client.hash(1).unwrap().unwrap())
        .unwrap()
        .unwrap();
    let parent_header = alice.client.header(*header.parent_hash()).unwrap().unwrap();

    let intermediate_roots = alice
        .client
        .runtime_api()
        .intermediate_roots(header.hash())
        .expect("Get intermediate roots");

    let prover = subspace_fraud_proof::ExecutionProver::new(
        alice.backend.clone(),
        alice.code_executor.clone(),
        Box::new(alice.task_manager.spawn_handle()),
    );

    let digest = {
        let primary_block_info =
            DigestItem::primary_block_info((1, ferdie.client.hash(1).unwrap().unwrap()));

        Digest {
            logs: vec![primary_block_info],
        }
    };

    let new_header = Header::new(
        *header.number(),
        header.hash(),
        Default::default(),
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
        .header(ferdie.client.hash(1).unwrap().unwrap())
        .unwrap()
        .unwrap();
    let parent_hash_ferdie = header_ferdie.hash();
    let parent_number_ferdie = *header_ferdie.number();

    let good_invalid_state_transition_proof = InvalidStateTransitionProof {
        domain_id: DomainId::SYSTEM,
        bad_receipt_hash: Hash::random(),
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
        .transaction_pool
        .pool()
        .submit_one(
            &BlockId::Hash(ferdie.client.info().best_hash),
            TransactionSource::External,
            tx.into(),
        )
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

    let submit_invalid_fraud_proof_result = ferdie
        .transaction_pool
        .pool()
        .submit_one(
            &BlockId::Hash(ferdie.client.info().best_hash),
            TransactionSource::External,
            tx.into(),
        )
        .await;

    match submit_invalid_fraud_proof_result.unwrap_err() {
        sc_transaction_pool::error::Error::Pool(
            sc_transaction_pool_api::error::Error::InvalidTransaction(invalid_tx),
        ) => assert_eq!(invalid_tx, InvalidTransactionCode::FraudProof.into()),
        e => panic!("Unexpected error while submitting an invalid fraud proof: {e}"),
    }
}

// TODO: Add a new test which simulates a situation that an executor produces a fraud proof
// when an invalid receipt is received.

#[substrate_test_utils::test(flavor = "multi_thread")]
#[ignore]
async fn set_new_code_should_work() {
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

    ferdie.wait_for_blocks(1).await;

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
    let (ferdie, _ferdie_network_starter) = run_primary_chain_validator_node(
        tokio_handle.clone(),
        Ferdie,
        vec![],
        BasePath::new(directory.path().join("ferdie")),
    )
    .await;

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
#[ignore]
async fn pallet_domains_unsigned_extrinsics_should_work() {
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

    // Run Alice (a system domain full node)
    // Run a full node deliberately in order to control the execution chain by
    // submitting the receipts manually later.
    let alice = domain_test_service::SystemDomainNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .connect_to_primary_chain_node(&ferdie)
    .build(Role::Full, false, false)
    .await;

    alice.wait_for_blocks(2).await;

    // Wait for one more block to make sure the execution receipts of block 1,2 are
    // able to be written to the database.
    alice.wait_for_blocks(1).await;

    let create_and_send_submit_bundle = |primary_number: BlockNumber| {
        let execution_receipt = crate::aux_schema::load_execution_receipt(
            &*alice.backend,
            alice.client.hash(primary_number).unwrap().unwrap(),
        )
        .expect("Failed to load execution receipt from the local aux_db")
        .unwrap_or_else(|| {
            panic!("The requested execution receipt for block {primary_number} does not exist")
        });

        let bundle = Bundle {
            header: BundleHeader {
                primary_number,
                primary_hash: ferdie.client.hash(primary_number).unwrap().unwrap(),
                slot_number: (std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .expect("Current time is always after unix epoch; qed")
                    .as_millis()
                    / 2000) as u64,
                extrinsics_root: Default::default(),
            },
            receipts: vec![execution_receipt],
            extrinsics: Vec::<UncheckedExtrinsic>::new(),
        };

        let pair = ExecutorPair::from_string("//Alice", None).unwrap();
        let signature = pair.sign(bundle.hash().as_ref());

        let signed_opaque_bundle = SignedBundle {
            bundle,
            bundle_solution: BundleSolution::System {
                authority_stake_weight: Default::default(),
                authority_witness: Default::default(),
                proof_of_election: ProofOfElection::dummy(DomainId::SYSTEM, pair.public()),
            }, // TODO: mock ProofOfElection properly
            signature,
        }
        .into_signed_opaque_bundle();

        let tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
            pallet_domains::Call::submit_bundle {
                signed_opaque_bundle,
            }
            .into(),
        );

        let pool = ferdie.transaction_pool.pool();
        let ferdie_best_hash = ferdie.client.info().best_hash;

        async move {
            pool.submit_one(
                &BlockId::Hash(ferdie_best_hash),
                TransactionSource::External,
                tx.into(),
            )
            .await
        }
    };

    let ready_txs = || {
        ferdie
            .transaction_pool
            .pool()
            .validated_pool()
            .ready()
            .map(|tx| tx.hash)
            .collect::<Vec<_>>()
    };

    let (tx1, tx2) = futures::join!(
        create_and_send_submit_bundle(1),
        create_and_send_submit_bundle(2),
    );
    assert_eq!(vec![tx1.unwrap(), tx2.unwrap()], ready_txs());

    // Wait for up to 5 blocks to ensure the ready txs can be consumed.
    for _ in 0..5 {
        alice.wait_for_blocks(1).await;
        if ready_txs().is_empty() {
            break;
        }
    }
    assert!(ready_txs().is_empty());

    alice.wait_for_blocks(2).await;

    let future_txs = || {
        ferdie
            .transaction_pool
            .pool()
            .validated_pool()
            .futures()
            .into_iter()
            .map(|(tx_hash, _)| tx_hash)
            .collect::<HashSet<_>>()
    };
    // best execution chain number is 2, receipt for #4 will be put into the futures queue.
    let tx4 = create_and_send_submit_bundle(4)
        .await
        .expect("Submit a future receipt successfully");
    assert_eq!(HashSet::from([tx4]), future_txs());

    // max drift is 2, hence the max allowed receipt number is 2 + 2, 5 will be rejected as being
    // too far.
    match create_and_send_submit_bundle(5).await.unwrap_err() {
        sc_transaction_pool::error::Error::Pool(
            sc_transaction_pool_api::error::Error::InvalidTransaction(invalid_tx),
        ) => assert_eq!(invalid_tx, InvalidTransactionCode::ExecutionReceipt.into()),
        e => panic!("Unexpected error while submitting execution receipt: {e}"),
    }

    let tx3 = create_and_send_submit_bundle(3)
        .await
        .expect("Submit receipt 3 successfully");
    // All future txs become ready once the required tx is ready.
    assert_eq!(vec![tx3, tx4], ready_txs());
    assert!(future_txs().is_empty());

    // Wait for up to 5 blocks to ensure the ready txs can be consumed.
    for _ in 0..5 {
        alice.wait_for_blocks(1).await;
        if ready_txs().is_empty() {
            break;
        }
    }
    assert!(ready_txs().is_empty());
}

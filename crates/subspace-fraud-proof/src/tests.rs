use crate::{ExecutionProver, ProofVerifier};
use codec::Encode;
use domain_block_builder::{BlockBuilder, RecordProof};
use domain_test_service::run_primary_chain_validator_node;
use domain_test_service::runtime::Header;
use domain_test_service::Keyring::{Alice, Bob, Charlie, Dave, Ferdie};
use sc_client_api::{HeaderBackend, StorageProof};
use sc_consensus::ForkChoiceStrategy;
use sc_service::{BasePath, Role};
use sp_api::ProvideRuntimeApi;
use sp_domains::{BundleHeader, ExecutionPhase, ExecutionReceipt, FraudProof, OpaqueBundle};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{BlakeTwo256, Hash as HashT, Header as HeaderT};
use sp_runtime::OpaqueExtrinsic;
use system_runtime_primitives::{Hash, SystemDomainApi};
use tempfile::TempDir;

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

    // Run Alice (a secondary chain authority node)
    let alice = domain_test_service::TestNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .connect_to_primary_chain_node(&ferdie)
    .build(Role::Authority, false, false)
    .await;

    // Run Bob (a secondary chain full node)
    let bob = domain_test_service::TestNodeBuilder::new(
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

    let dummy_receipt = ExecutionReceipt {
        primary_number: ferdie.client.info().best_number,
        primary_hash: ferdie.client.info().best_hash,
        secondary_hash: alice.client.info().best_hash,
        trace: Vec::new(),
        trace_root: Default::default(),
    };

    let bundles = vec![OpaqueBundle {
        header: BundleHeader {
            primary_hash: ferdie.client.info().best_hash,
            slot_number: Default::default(),
            extrinsics_root: Default::default(),
        },
        extrinsics: test_txs
            .iter()
            .map(|xt| OpaqueExtrinsic::from_bytes(&xt.encode()).unwrap())
            .collect(),
        receipts: vec![dummy_receipt],
    }];

    let primary_info = if alice.client.info().best_number == ferdie.client.info().best_number {
        // The executor might have already imported the latest primary block, make a fake future block to
        // bypass the check of `latest_primary_number = old_best_secondary_number + 1` in `process_bundles`.
        //
        // This invalid primary hash does not affect the test result.
        (
            Hash::random(),
            ferdie.client.info().best_number + 1,
            ForkChoiceStrategy::LongestChain,
        )
    } else {
        (
            ferdie.client.info().best_hash,
            ferdie.client.info().best_number,
            ForkChoiceStrategy::LongestChain,
        )
    };
    alice
        .executor
        .clone()
        .process_bundles(
            primary_info,
            bundles,
            BlakeTwo256::hash_of(&[1u8; 64]).into(),
            None,
        )
        .await;

    let best_hash = alice.client.info().best_hash;
    let header = alice
        .client
        .header(&BlockId::Hash(best_hash))
        .unwrap()
        .unwrap();
    let parent_header = alice
        .client
        .header(&BlockId::Hash(*header.parent_hash()))
        .unwrap()
        .unwrap();

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
        .intermediate_roots(&BlockId::Hash(best_hash))
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
        call_data: new_header.encode(),
    };

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
            None,
        )
        .expect("Create `initialize_block` proof");

    // Test `initialize_block` verification.
    let execution_result = prover
        .check_execution_proof(
            parent_header.hash(),
            &execution_phase,
            *parent_header.state_root(),
            storage_proof.clone(),
        )
        .expect("Check `initialize_block` proof");
    let post_execution_root = execution_phase
        .decode_execution_result::<Header>(execution_result)
        .unwrap();
    assert_eq!(post_execution_root, intermediate_roots[0].into());

    let proof_verifier = ProofVerifier::new(
        ferdie.client.clone(),
        ferdie.backend.clone(),
        ferdie.executor.clone(),
        ferdie.task_manager.spawn_handle(),
    );

    // Incorrect but it's fine for the test purpose.
    let parent_hash_alice = ferdie.client.info().best_hash;
    let parent_number_alice = ferdie.client.info().best_number;

    let fraud_proof = FraudProof {
        bad_signed_bundle_hash: Hash::random(),
        parent_number: parent_number_alice,
        parent_hash: parent_hash_alice,
        pre_state_root: *parent_header.state_root(),
        post_state_root: intermediate_roots[0].into(),
        proof: storage_proof,
        execution_phase,
    };
    assert!(proof_verifier.verify(&fraud_proof).is_ok());

    // Test extrinsic execution.
    for (target_extrinsic_index, xt) in test_txs.clone().into_iter().enumerate() {
        let storage_changes = create_block_builder()
            .prepare_storage_changes_before(target_extrinsic_index)
            .unwrap_or_else(|_| {
                panic!(
                    "Get StorageChanges before extrinsic #{}",
                    target_extrinsic_index
                )
            });

        let delta = storage_changes.transaction;
        let post_delta_root = storage_changes.transaction_storage_root;

        let execution_phase = ExecutionPhase::ApplyExtrinsic {
            call_data: xt.encode(),
        };

        let storage_proof = prover
            .prove_execution(
                parent_header.hash(),
                &execution_phase,
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

        let fraud_proof = FraudProof {
            bad_signed_bundle_hash: Hash::random(),
            parent_number: parent_number_alice,
            parent_hash: parent_hash_alice,
            pre_state_root: intermediate_roots[target_extrinsic_index].into(),
            post_state_root: intermediate_roots[target_extrinsic_index + 1].into(),
            proof: storage_proof,
            execution_phase,
        };
        assert!(proof_verifier.verify(&fraud_proof).is_ok());
    }

    // Test `finalize_block`
    let storage_changes = create_block_builder()
        .prepare_storage_changes_before_finalize_block()
        .expect("Get StorageChanges before `finalize_block`");

    let delta = storage_changes.transaction;
    let post_delta_root = storage_changes.transaction_storage_root;

    assert_eq!(post_delta_root, intermediate_roots.last().unwrap().into());

    let execution_phase = ExecutionPhase::FinalizeBlock;

    let storage_proof = prover
        .prove_execution(
            parent_header.hash(),
            &execution_phase,
            Some((delta, post_delta_root)),
        )
        .expect("Create `finalize_block` proof");

    // Test `finalize_block` verification.
    let execution_result = prover
        .check_execution_proof(
            parent_header.hash(),
            &execution_phase,
            post_delta_root,
            storage_proof.clone(),
        )
        .expect("Check `finalize_block` proof");
    let post_execution_root = execution_phase
        .decode_execution_result::<Header>(execution_result)
        .unwrap();
    assert_eq!(post_execution_root, *header.state_root());

    let fraud_proof = FraudProof {
        bad_signed_bundle_hash: Hash::random(),
        parent_number: parent_number_alice,
        parent_hash: parent_hash_alice,
        pre_state_root: intermediate_roots.last().unwrap().into(),
        post_state_root: post_execution_root,
        proof: storage_proof,
        execution_phase,
    };
    assert!(proof_verifier.verify(&fraud_proof).is_ok());
}

#[substrate_test_utils::test(flavor = "multi_thread")]
#[ignore]
async fn invalid_execution_proof_should_not_work() {
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

    // Run Alice (a secondary chain authority node)
    let alice = domain_test_service::TestNodeBuilder::new(
        tokio_handle.clone(),
        Alice,
        BasePath::new(directory.path().join("alice")),
    )
    .connect_to_primary_chain_node(&ferdie)
    .build(Role::Authority, false, false)
    .await;

    // Run Bob (a secondary chain full node)
    let bob = domain_test_service::TestNodeBuilder::new(
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

    // Wait until the test txs are included in the next block.
    alice.wait_for_blocks(1).await;

    let best_hash = alice.client.info().best_hash;
    let header = alice
        .client
        .header(&BlockId::Hash(best_hash))
        .unwrap()
        .unwrap();
    let parent_header = alice
        .client
        .header(&BlockId::Hash(*header.parent_hash()))
        .unwrap()
        .unwrap();

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

    let prover = ExecutionProver::new(
        alice.backend.clone(),
        alice.code_executor.clone(),
        Box::new(alice.task_manager.spawn_handle()),
    );

    let create_extrinsic_proof = |extrinsic_index: usize| {
        let storage_changes = create_block_builder()
            .prepare_storage_changes_before(extrinsic_index)
            .unwrap_or_else(|_| panic!("Get StorageChanges before extrinsic #{}", extrinsic_index));

        let delta = storage_changes.transaction;
        let post_delta_root = storage_changes.transaction_storage_root;

        let execution_phase = ExecutionPhase::ApplyExtrinsic {
            call_data: test_txs[extrinsic_index].encode(),
        };

        let proof = prover
            .prove_execution(
                parent_header.hash(),
                &execution_phase,
                Some((delta, post_delta_root)),
            )
            .expect("Create extrinsic execution proof");

        (proof, post_delta_root, execution_phase)
    };

    let (proof0, post_delta_root0, execution_phase0) = create_extrinsic_proof(0);
    let (proof1, post_delta_root1, execution_phase1) = create_extrinsic_proof(1);

    let check_proof_executor = |post_delta_root: Hash, proof: StorageProof| {
        let execution_phase = ExecutionPhase::ApplyExtrinsic {
            call_data: transfer_to_charlie_again.encode(),
        };
        prover.check_execution_proof(
            parent_header.hash(),
            &execution_phase,
            post_delta_root,
            proof,
        )
    };

    assert!(check_proof_executor(post_delta_root1, proof0.clone()).is_err());
    assert!(check_proof_executor(post_delta_root0, proof1.clone()).is_err());
    assert!(check_proof_executor(post_delta_root0, proof0.clone()).is_ok());
    assert!(check_proof_executor(post_delta_root1, proof1.clone()).is_ok());

    let proof_verifier = ProofVerifier::new(
        ferdie.client.clone(),
        ferdie.backend.clone(),
        ferdie.executor.clone(),
        ferdie.task_manager.spawn_handle(),
    );

    // Incorrect but it's fine for the test purpose.
    let parent_hash_alice = ferdie.client.info().best_hash;
    let parent_number_alice = ferdie.client.info().best_number;

    let fraud_proof = FraudProof {
        bad_signed_bundle_hash: Hash::random(),
        parent_number: parent_number_alice,
        parent_hash: parent_hash_alice,
        pre_state_root: post_delta_root0,
        post_state_root: post_delta_root1,
        proof: proof1,
        execution_phase: execution_phase0.clone(),
    };
    assert!(proof_verifier.verify(&fraud_proof).is_err());

    let fraud_proof = FraudProof {
        bad_signed_bundle_hash: Hash::random(),
        parent_number: parent_number_alice,
        parent_hash: parent_hash_alice,
        pre_state_root: post_delta_root0,
        post_state_root: post_delta_root1,
        proof: proof0.clone(),
        execution_phase: execution_phase1,
    };
    assert!(proof_verifier.verify(&fraud_proof).is_err());

    let fraud_proof = FraudProof {
        bad_signed_bundle_hash: Hash::random(),
        parent_number: parent_number_alice,
        parent_hash: parent_hash_alice,
        pre_state_root: post_delta_root0,
        post_state_root: post_delta_root1,
        proof: proof0,
        execution_phase: execution_phase0,
    };
    assert!(proof_verifier.verify(&fraud_proof).is_ok());
}

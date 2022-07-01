use cirrus_block_builder::{BlockBuilder, RecordProof};
use cirrus_primitives::{BlockNumber, Hash, SecondaryApi};
use cirrus_test_service::{
	run_primary_chain_validator_node,
	runtime::Header,
	Keyring::{Alice, Bob, Charlie, Dave, Ferdie},
};
use codec::Encode;
use sc_client_api::{Backend, HeaderBackend, StateBackend, StorageProof};
use sc_service::Role;
use sc_transaction_pool_api::TransactionSource;
use sp_api::ProvideRuntimeApi;
use sp_core::{traits::FetchRuntimeCode, Pair};
use sp_executor::{
	BundleHeader, ExecutionPhase, ExecutorPair, FraudProof, OpaqueBundle, SignedExecutionReceipt,
};
use sp_runtime::{
	generic::{BlockId, DigestItem},
	traits::{BlakeTwo256, Hash as HashT, Header as HeaderT},
	OpaqueExtrinsic,
};
use std::collections::HashSet;

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn test_executor_full_node_catching_up() {
	let mut builder = sc_cli::LoggerBuilder::new("");
	builder.with_colors(false);
	let _ = builder.init();

	let tokio_handle = tokio::runtime::Handle::current();

	// Start Ferdie
	let (ferdie, ferdie_network_starter) =
		run_primary_chain_validator_node(tokio_handle.clone(), Ferdie, vec![]).await;
	ferdie_network_starter.start_network();

	// Run Alice (a secondary chain authority node)
	let alice = cirrus_test_service::TestNodeBuilder::new(tokio_handle.clone(), Alice)
		.connect_to_primary_chain_node(&ferdie)
		.build(Role::Authority)
		.await;

	// Run Bob (a secondary chain full node)
	let bob = cirrus_test_service::TestNodeBuilder::new(tokio_handle, Bob)
		.connect_to_primary_chain_node(&ferdie)
		.build(Role::Full)
		.await;

	// Bob is able to sync blocks.
	futures::future::join(alice.wait_for_blocks(10), bob.wait_for_blocks(10)).await;

	assert_eq!(
		ferdie.client.info().best_number,
		alice.client.info().best_number,
		"Primary chain and secondary chain must be on the same best height"
	);

	let alice_block_hash = alice.client.expect_block_hash_from_id(&BlockId::Number(8)).unwrap();
	let bob_block_hash = bob.client.expect_block_hash_from_id(&BlockId::Number(8)).unwrap();
	assert_eq!(
		alice_block_hash, bob_block_hash,
		"Executor authority node and full node must have the same state"
	);
}

// TODO: This is basically an unit test for the features provided by `subspace_fraud_proof`, move
// it there and add a new test which simulates a situation that an executor produces a fraud proof
// when an invalid receipt is received.
#[substrate_test_utils::test(flavor = "multi_thread")]
async fn execution_proof_creation_and_verification_should_work() {
	let mut builder = sc_cli::LoggerBuilder::new("");
	builder.with_colors(false);
	let _ = builder.init();

	let tokio_handle = tokio::runtime::Handle::current();

	// Start Ferdie
	let (ferdie, ferdie_network_starter) =
		run_primary_chain_validator_node(tokio_handle.clone(), Ferdie, vec![]).await;
	ferdie_network_starter.start_network();

	// Run Alice (a secondary chain authority node)
	let alice = cirrus_test_service::TestNodeBuilder::new(tokio_handle.clone(), Alice)
		.connect_to_primary_chain_node(&ferdie)
		.build(Role::Authority)
		.await;

	// Run Bob (a secondary chain full node)
	let bob = cirrus_test_service::TestNodeBuilder::new(tokio_handle, Bob)
		.connect_to_primary_chain_node(&ferdie)
		.build(Role::Full)
		.await;

	// Bob is able to sync blocks.
	futures::future::join(alice.wait_for_blocks(3), bob.wait_for_blocks(3)).await;

	let transfer_to_charlie = cirrus_test_service::construct_extrinsic(
		&alice.client,
		pallet_balances::Call::transfer {
			dest: cirrus_test_service::runtime::Address::Id(Charlie.public().into()),
			value: 8,
		},
		Alice,
		false,
		0,
	);
	let transfer_to_dave = cirrus_test_service::construct_extrinsic(
		&alice.client,
		pallet_balances::Call::transfer {
			dest: cirrus_test_service::runtime::Address::Id(Dave.public().into()),
			value: 8,
		},
		Alice,
		false,
		1,
	);
	let transfer_to_charlie_again = cirrus_test_service::construct_extrinsic(
		&alice.client,
		pallet_balances::Call::transfer {
			dest: cirrus_test_service::runtime::Address::Id(Charlie.public().into()),
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
		alice.send_extrinsic(tx.clone()).await.expect("Failed to send extrinsic");
	}

	// Ideally we just need to wait one block and the test txs should be all included
	// in the next block, but the txs are probably unable to be included if the machine
	// is overloaded, hence we manually mock the bundles processing to avoid the occasional
	// test failure (https://github.com/subspace/subspace/runs/5663241460?check_suite_focus=true).
	//
	// alice.wait_for_blocks(1).await;

	let bundles = vec![OpaqueBundle {
		header: BundleHeader {
			primary_hash: ferdie.client.info().best_hash,
			slot_number: Default::default(),
			extrinsics_root: Default::default(),
		},
		opaque_extrinsics: test_txs
			.iter()
			.map(|xt| OpaqueExtrinsic::from_bytes(&xt.encode()).unwrap())
			.collect(),
	}];

	let primary_info = if alice.client.info().best_number == ferdie.client.info().best_number {
		// The executor might have already imported the latest primary block, make a fake future block to
		// bypass the check of `latest_primary_number = old_best_secondary_number + 1` in `process_bundles`.
		//
		// This invalid primary hash does not affect the test result.
		(Hash::random(), ferdie.client.info().best_number + 1)
	} else {
		(ferdie.client.info().best_hash, ferdie.client.info().best_number)
	};
	alice
		.executor
		.clone()
		.process_bundles(primary_info, bundles, BlakeTwo256::hash_of(&[1u8; 64]).into(), None)
		.await;

	let best_hash = alice.client.info().best_hash;
	let header = alice.client.header(&BlockId::Hash(best_hash)).unwrap().unwrap();
	let parent_header =
		alice.client.header(&BlockId::Hash(*header.parent_hash())).unwrap().unwrap();

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
	println!(
		"intermediate_roots: {:?}",
		intermediate_roots.clone().into_iter().map(Hash::from).collect::<Vec<_>>()
	);

	assert_eq!(
		intermediate_roots.len(),
		test_txs.len() + 1,
		"🐛 ERROR: runtime API `intermediate_roots()` obviously returned a wrong result"
	);

	let new_header = Header::new(
		*header.number(),
		Default::default(),
		Default::default(),
		parent_header.hash(),
		Default::default(),
	);
	let execution_phase = ExecutionPhase::InitializeBlock { call_data: new_header.encode() };

	let prover = subspace_fraud_proof::ExecutionProver::new(
		alice.backend.clone(),
		alice.code_executor.clone(),
		Box::new(alice.task_manager.spawn_handle()),
	);

	// Test `initialize_block`.
	let storage_proof = prover
		.prove_execution::<sp_trie::PrefixedMemoryDB<BlakeTwo256>>(
			BlockId::Hash(parent_header.hash()),
			&execution_phase,
			None,
		)
		.expect("Create `initialize_block` proof");

	// Test `initialize_block` verification.
	let execution_result = prover
		.check_execution_proof(
			BlockId::Hash(parent_header.hash()),
			&execution_phase,
			*parent_header.state_root(),
			storage_proof.clone(),
		)
		.expect("Check `initialize_block` proof");
	let post_execution_root =
		execution_phase.decode_execution_result::<Header>(execution_result).unwrap();
	assert_eq!(post_execution_root, intermediate_roots[0].into());

	let proof_verifier = subspace_fraud_proof::ProofVerifier::new(
		ferdie.client.clone(),
		ferdie.backend.clone(),
		ferdie.executor.clone(),
		ferdie.task_manager.spawn_handle(),
	);

	// Incorrect but it's fine for the test purpose.
	let parent_hash_alice = ferdie.client.info().best_hash;
	let parent_number_alice = ferdie.client.info().best_number;

	let fraud_proof = FraudProof {
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
				panic!("Get StorageChanges before extrinsic #{}", target_extrinsic_index)
			});

		let delta = storage_changes.transaction;
		let post_delta_root = storage_changes.transaction_storage_root;

		let execution_phase = ExecutionPhase::ApplyExtrinsic { call_data: xt.encode() };

		let storage_proof = prover
			.prove_execution(
				BlockId::Hash(parent_header.hash()),
				&execution_phase,
				Some((delta, post_delta_root)),
			)
			.expect("Create extrinsic execution proof");

		let target_trace_root: Hash = intermediate_roots[target_extrinsic_index].into();
		assert_eq!(target_trace_root, post_delta_root);

		// Test `apply_extrinsic` verification.
		let execution_result = prover
			.check_execution_proof(
				BlockId::Hash(parent_header.hash()),
				&execution_phase,
				post_delta_root,
				storage_proof.clone(),
			)
			.expect("Check extrinsic execution proof");
		let post_execution_root =
			execution_phase.decode_execution_result::<Header>(execution_result).unwrap();
		assert_eq!(post_execution_root, intermediate_roots[target_extrinsic_index + 1].into());

		let fraud_proof = FraudProof {
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
			BlockId::Hash(parent_header.hash()),
			&execution_phase,
			Some((delta, post_delta_root)),
		)
		.expect("Create `finalize_block` proof");

	// Test `finalize_block` verification.
	let execution_result = prover
		.check_execution_proof(
			BlockId::Hash(parent_header.hash()),
			&execution_phase,
			post_delta_root,
			storage_proof.clone(),
		)
		.expect("Check `finalize_block` proof");
	let post_execution_root =
		execution_phase.decode_execution_result::<Header>(execution_result).unwrap();
	assert_eq!(post_execution_root, *header.state_root());

	let fraud_proof = FraudProof {
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
async fn fraud_proof_verification_in_tx_pool_should_work() {
	let mut builder = sc_cli::LoggerBuilder::new("");
	builder.with_colors(false);
	let _ = builder.init();

	let tokio_handle = tokio::runtime::Handle::current();

	// Start Ferdie
	let (ferdie, ferdie_network_starter) =
		run_primary_chain_validator_node(tokio_handle.clone(), Ferdie, vec![]).await;
	ferdie_network_starter.start_network();

	// Run Alice (a secondary chain authority node)
	let alice = cirrus_test_service::TestNodeBuilder::new(tokio_handle.clone(), Alice)
		.connect_to_primary_chain_node(&ferdie)
		.build(Role::Authority)
		.await;

	alice.wait_for_blocks(3).await;

	let header = alice.client.header(&BlockId::Number(1)).unwrap().unwrap();
	let parent_header =
		alice.client.header(&BlockId::Hash(*header.parent_hash())).unwrap().unwrap();

	let intermediate_roots = alice
		.client
		.runtime_api()
		.intermediate_roots(&BlockId::Hash(header.hash()))
		.expect("Get intermediate roots");

	let prover = subspace_fraud_proof::ExecutionProver::new(
		alice.backend.clone(),
		alice.code_executor.clone(),
		Box::new(alice.task_manager.spawn_handle()),
	);

	let new_header = Header::new(
		*header.number(),
		Default::default(),
		Default::default(),
		parent_header.hash(),
		Default::default(),
	);
	let execution_phase = ExecutionPhase::InitializeBlock { call_data: new_header.encode() };

	let storage_proof = prover
		.prove_execution::<sp_trie::PrefixedMemoryDB<BlakeTwo256>>(
			BlockId::Hash(parent_header.hash()),
			&execution_phase,
			None,
		)
		.expect("Create `initialize_block` proof");

	let header_ferdie = ferdie.client.header(&BlockId::Number(1)).unwrap().unwrap();
	let parent_hash_ferdie = header_ferdie.hash();
	let parent_number_ferdie = *header_ferdie.number();

	let valid_fraud_proof = FraudProof {
		parent_number: parent_number_ferdie,
		parent_hash: parent_hash_ferdie,
		pre_state_root: *parent_header.state_root(),
		post_state_root: intermediate_roots[0].into(),
		proof: storage_proof,
		execution_phase: execution_phase.clone(),
	};

	let tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
		pallet_executor::Call::submit_fraud_proof { fraud_proof: valid_fraud_proof.clone() }.into(),
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

	let invalid_fraud_proof = FraudProof { post_state_root: Hash::random(), ..valid_fraud_proof };

	let tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
		pallet_executor::Call::submit_fraud_proof { fraud_proof: invalid_fraud_proof }.into(),
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
		) => assert_eq!(invalid_tx, sp_executor::InvalidTransactionCode::FraudProof.into()),
		e => panic!("Unexpected error while submitting an invalid fraud proof: {e}"),
	}
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn invalid_execution_proof_should_not_work() {
	let mut builder = sc_cli::LoggerBuilder::new("");
	builder.with_colors(false);
	let _ = builder.init();

	let tokio_handle = tokio::runtime::Handle::current();

	// Start Ferdie
	let (ferdie, ferdie_network_starter) =
		run_primary_chain_validator_node(tokio_handle.clone(), Ferdie, vec![]).await;
	ferdie_network_starter.start_network();

	// Run Alice (a secondary chain authority node)
	let alice = cirrus_test_service::TestNodeBuilder::new(tokio_handle.clone(), Alice)
		.connect_to_primary_chain_node(&ferdie)
		.build(Role::Authority)
		.await;

	// Run Bob (a secondary chain full node)
	let bob = cirrus_test_service::TestNodeBuilder::new(tokio_handle, Bob)
		.connect_to_primary_chain_node(&ferdie)
		.build(Role::Full)
		.await;

	// Bob is able to sync blocks.
	futures::future::join(alice.wait_for_blocks(3), bob.wait_for_blocks(3)).await;

	let transfer_to_charlie = cirrus_test_service::construct_extrinsic(
		&alice.client,
		pallet_balances::Call::transfer {
			dest: cirrus_test_service::runtime::Address::Id(Charlie.public().into()),
			value: 8,
		},
		Alice,
		false,
		0,
	);

	let transfer_to_charlie_again = cirrus_test_service::construct_extrinsic(
		&alice.client,
		pallet_balances::Call::transfer {
			dest: cirrus_test_service::runtime::Address::Id(Charlie.public().into()),
			value: 8,
		},
		Alice,
		false,
		1,
	);

	let test_txs = vec![transfer_to_charlie.clone(), transfer_to_charlie_again.clone()];

	for tx in test_txs.iter() {
		alice.send_extrinsic(tx.clone()).await.expect("Failed to send extrinsic");
	}

	// Wait until the test txs are included in the next block.
	alice.wait_for_blocks(1).await;

	let best_hash = alice.client.info().best_hash;
	let header = alice.client.header(&BlockId::Hash(best_hash)).unwrap().unwrap();
	let parent_header =
		alice.client.header(&BlockId::Hash(*header.parent_hash())).unwrap().unwrap();

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

	let prover = subspace_fraud_proof::ExecutionProver::new(
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

		let execution_phase =
			ExecutionPhase::ApplyExtrinsic { call_data: test_txs[extrinsic_index].encode() };

		let proof = prover
			.prove_execution(
				BlockId::Hash(parent_header.hash()),
				&execution_phase,
				Some((delta, post_delta_root)),
			)
			.expect("Create extrinsic execution proof");

		(proof, post_delta_root, execution_phase)
	};

	let (proof0, post_delta_root0, execution_phase0) = create_extrinsic_proof(0);
	let (proof1, post_delta_root1, execution_phase1) = create_extrinsic_proof(1);

	let check_proof_executor = |post_delta_root: Hash, proof: StorageProof| {
		let execution_phase =
			ExecutionPhase::ApplyExtrinsic { call_data: transfer_to_charlie_again.encode() };
		prover.check_execution_proof(
			BlockId::Hash(parent_header.hash()),
			&execution_phase,
			post_delta_root,
			proof,
		)
	};

	assert!(check_proof_executor(post_delta_root1, proof0.clone()).is_err());
	assert!(check_proof_executor(post_delta_root0, proof1.clone()).is_err());
	assert!(check_proof_executor(post_delta_root0, proof0.clone()).is_ok());
	assert!(check_proof_executor(post_delta_root1, proof1.clone()).is_ok());

	let proof_verifier = subspace_fraud_proof::ProofVerifier::new(
		ferdie.client.clone(),
		ferdie.backend.clone(),
		ferdie.executor.clone(),
		ferdie.task_manager.spawn_handle(),
	);

	// Incorrect but it's fine for the test purpose.
	let parent_hash_alice = ferdie.client.info().best_hash;
	let parent_number_alice = ferdie.client.info().best_number;

	let fraud_proof = FraudProof {
		parent_number: parent_number_alice,
		parent_hash: parent_hash_alice,
		pre_state_root: post_delta_root0,
		post_state_root: post_delta_root1,
		proof: proof1,
		execution_phase: execution_phase0.clone(),
	};
	assert!(proof_verifier.verify(&fraud_proof).is_err());

	let fraud_proof = FraudProof {
		parent_number: parent_number_alice,
		parent_hash: parent_hash_alice,
		pre_state_root: post_delta_root0,
		post_state_root: post_delta_root1,
		proof: proof0.clone(),
		execution_phase: execution_phase1,
	};
	assert!(proof_verifier.verify(&fraud_proof).is_err());

	let fraud_proof = FraudProof {
		parent_number: parent_number_alice,
		parent_hash: parent_hash_alice,
		pre_state_root: post_delta_root0,
		post_state_root: post_delta_root1,
		proof: proof0,
		execution_phase: execution_phase0,
	};
	assert!(proof_verifier.verify(&fraud_proof).is_ok());
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn set_new_code_should_work() {
	let mut builder = sc_cli::LoggerBuilder::new("");
	builder.with_colors(false);
	let _ = builder.init();

	let tokio_handle = tokio::runtime::Handle::current();

	// Start Ferdie
	let (ferdie, ferdie_network_starter) =
		run_primary_chain_validator_node(tokio_handle.clone(), Ferdie, vec![]).await;
	ferdie_network_starter.start_network();

	// Run Alice (a secondary chain authority node)
	let alice = cirrus_test_service::TestNodeBuilder::new(tokio_handle.clone(), Alice)
		.connect_to_primary_chain_node(&ferdie)
		.build(Role::Authority)
		.await;

	ferdie.wait_for_blocks(1).await;

	let new_runtime_wasm_blob = b"new_runtime_wasm_blob".to_vec();

	alice
		.executor
		.clone()
		.process_bundles(
			(ferdie.client.info().best_hash, ferdie.client.info().best_number),
			Default::default(),
			BlakeTwo256::hash_of(&[1u8; 64]).into(),
			Some(new_runtime_wasm_blob.clone().into()),
		)
		.await;

	let best_hash = alice.client.info().best_hash;
	let state = alice.backend.state_at(BlockId::Hash(best_hash)).expect("Get state");
	let trie_backend = state.as_trie_backend().unwrap();
	let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(trie_backend);
	let runtime_code = state_runtime_code.fetch_runtime_code().unwrap();
	assert_eq!(runtime_code, new_runtime_wasm_blob);
	assert_eq!(
		alice.client.header(&BlockId::Hash(best_hash)).unwrap().unwrap().digest.logs,
		vec![DigestItem::RuntimeEnvironmentUpdated]
	);
}

#[substrate_test_utils::test(flavor = "multi_thread")]
async fn pallet_executor_unsigned_extrinsics_should_work() {
	let mut builder = sc_cli::LoggerBuilder::new("");
	builder.with_colors(false);
	let _ = builder.init();

	let tokio_handle = tokio::runtime::Handle::current();

	// Start Ferdie
	let (ferdie, ferdie_network_starter) =
		run_primary_chain_validator_node(tokio_handle.clone(), Ferdie, vec![]).await;
	ferdie_network_starter.start_network();

	// Run Alice (a secondary chain full node)
	// Run a full node deliberately in order to control the executoin chain by
	// submitting the receipts manually later.
	let alice = cirrus_test_service::TestNodeBuilder::new(tokio_handle.clone(), Alice)
		.connect_to_primary_chain_node(&ferdie)
		.build(Role::Full)
		.await;

	alice.wait_for_blocks(3).await;

	let create_and_send_submit_execution_receipt = |primary_number: BlockNumber| {
		let execution_receipt = crate::aux_schema::load_execution_receipt(
			&*alice.backend,
			alice.client.hash(primary_number).unwrap().unwrap(),
		)
		.expect("Failed to load execution receipt from the local aux_db")
		.expect("The requested execution receipt must exist");

		let pair = ExecutorPair::from_string("//Alice", None).unwrap();
		let signature = pair.sign(execution_receipt.hash().as_ref());
		let signer = pair.public();

		let signed_execution_receipt =
			SignedExecutionReceipt { execution_receipt, signature, signer };

		let tx = subspace_test_runtime::UncheckedExtrinsic::new_unsigned(
			pallet_executor::Call::submit_execution_receipt { signed_execution_receipt }.into(),
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

	let tx1 = create_and_send_submit_execution_receipt(1)
		.await
		.expect("Submit receipt successfully");
	let tx2 = create_and_send_submit_execution_receipt(2)
		.await
		.expect("Submit receipt successfully");
	let tx3 = create_and_send_submit_execution_receipt(3)
		.await
		.expect("Best block receipt must be able to be included in the next block");

	let ready_txs = || {
		ferdie
			.transaction_pool
			.pool()
			.validated_pool()
			.ready()
			.map(|tx| tx.hash)
			.collect::<Vec<_>>()
	};

	assert_eq!(vec![tx1, tx2, tx3], ready_txs());

	// Wait for a few more blocks to ensure the ready txs can be consumed.
	alice.wait_for_blocks(5).await;
	assert!(ready_txs().is_empty());

	alice.wait_for_blocks(4).await;

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
	// best execution chain number is 3, receipt for #5 will be put into the futures queue.
	let tx5 = create_and_send_submit_execution_receipt(5)
		.await
		.expect("Submit a future receipt successfully");
	assert_eq!(HashSet::from([tx5]), future_txs());

	let tx6 = create_and_send_submit_execution_receipt(6)
		.await
		.expect("Submit a future receipt successfully");
	let tx7 = create_and_send_submit_execution_receipt(7)
		.await
		.expect("Submit a future receipt successfully");
	assert_eq!(HashSet::from([tx5, tx6, tx7]), future_txs());

	// max drift is 4, hence the max allowed receipt number is 3 + 4, 8 will be rejected as being
	// too far.
	match create_and_send_submit_execution_receipt(8).await.unwrap_err() {
		sc_transaction_pool::error::Error::Pool(
			sc_transaction_pool_api::error::Error::InvalidTransaction(invalid_tx),
		) => assert_eq!(invalid_tx, sp_executor::InvalidTransactionCode::ExecutionReceipt.into()),
		e => panic!("Unexpected error while submitting execution receipt: {e}"),
	}

	// Wait for a few more blocks to ensure the ready txs can be consumed.
	alice.wait_for_blocks(5).await;
	assert!(ready_txs().is_empty());
	assert_eq!(HashSet::from([tx5, tx6, tx7]), future_txs());

	let tx4 = create_and_send_submit_execution_receipt(4)
		.await
		.expect("Submit receipt successfully");
	// All future txs become ready once the required tx is ready.
	assert_eq!(vec![tx4, tx5, tx6, tx7], ready_txs());
	assert!(future_txs().is_empty());

	// Wait for a few more blocks to ensure the ready txs can be consumed.
	alice.wait_for_blocks(5).await;
	assert!(ready_txs().is_empty());
}

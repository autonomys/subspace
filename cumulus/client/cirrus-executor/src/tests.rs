use cirrus_test_service::{
	run_primary_chain_validator_node,
	Keyring::{Alice, Charlie, Dave},
};
use sc_client_api::HeaderBackend;
use sp_runtime::generic::BlockId;

#[substrate_test_utils::test]
async fn test_executor_full_node_catching_up() {
	let mut builder = sc_cli::LoggerBuilder::new("");
	builder.with_colors(false);
	let _ = builder.init();

	let tokio_handle = tokio::runtime::Handle::current();

	// start alice
	let alice = run_primary_chain_validator_node(tokio_handle.clone(), Alice, vec![], true);

	// run cirrus charlie (a secondary chain authority node)
	let charlie = cirrus_test_service::TestNodeBuilder::new(tokio_handle.clone(), Charlie)
		.connect_to_relay_chain_node(&alice)
		.build()
		.await;

	// run cirrus dave (a secondary chain full node)
	let dave = cirrus_test_service::TestNodeBuilder::new(tokio_handle, Dave)
		.connect_to_parachain_node(&charlie)
		.connect_to_relay_chain_node(&alice)
		.build()
		.await;

	// dave is able to sync blocks.
	futures::future::join(charlie.wait_for_blocks(10), dave.wait_for_blocks(10)).await;

	let charlie_block_hash = charlie.client.expect_block_hash_from_id(&BlockId::Number(8)).unwrap();

	let dave_block_hash = dave.client.expect_block_hash_from_id(&BlockId::Number(8)).unwrap();

	assert_eq!(
		charlie_block_hash, dave_block_hash,
		"Executor authority node and full node must have the same state"
	);
}

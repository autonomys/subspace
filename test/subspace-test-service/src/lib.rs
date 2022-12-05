// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Subspace test service only.

#![warn(missing_docs, unused_crate_dependencies)]

use futures::future::Future;
use sc_client_api::execution_extensions::ExecutionStrategies;
use sc_consensus_slots::SlotProportion;
use sc_executor::NativeElseWasmExecutor;
use sc_network::config::NetworkConfiguration;
use sc_network::{multiaddr, NetworkStateInfo};
use sc_network_common::config::TransportConfig;
use sc_service::config::{
    DatabaseSource, KeystoreConfig, MultiaddrWithPeerId, WasmExecutionMethod,
};
use sc_service::{
    BasePath, BlocksPruning, Configuration, NetworkStarter, Role, RpcHandlers, TaskManager,
};
use sp_arithmetic::traits::SaturatedConversion;
use sp_blockchain::HeaderBackend;
use sp_keyring::Sr25519Keyring;
use sp_runtime::codec::Encode;
use sp_runtime::traits::IdentifyAccount;
use sp_runtime::{generic, MultiSigner};
use std::sync::Arc;
use subspace_networking::libp2p::identity;
use subspace_runtime_primitives::opaque::Block;
use subspace_runtime_primitives::Balance;
use subspace_service::{DsnConfig, FullPool, NewFull, SubspaceConfiguration, SubspaceNetworking};
use subspace_test_client::{
    chain_spec, start_farmer, Backend, Client, FraudProofVerifier, TestExecutorDispatch,
};
use subspace_test_runtime::{
    BlockHashCount, Runtime, RuntimeApi, SignedExtra, SignedPayload, UncheckedExtrinsic, VERSION,
};
use substrate_test_client::{
    BlockchainEventsExt, RpcHandlersExt, RpcTransactionError, RpcTransactionOutput,
};

/// Create a Subspace `Configuration`.
///
/// By default an in-memory socket will be used, therefore you need to provide boot
/// nodes if you want the future node to be connected to other nodes.
pub fn node_config(
    tokio_handle: tokio::runtime::Handle,
    key: Sr25519Keyring,
    boot_nodes: Vec<MultiaddrWithPeerId>,
    run_farmer: bool,
    force_authoring: bool,
    force_synced: bool,
    base_path: BasePath,
) -> Configuration {
    let root = base_path.path();
    let role = if run_farmer {
        Role::Authority
    } else {
        Role::Full
    };
    let key_seed = key.to_seed();
    let spec = chain_spec::subspace_local_testnet_config();

    let mut network_config = NetworkConfiguration::new(
        key_seed.to_string(),
        "network/test/0.1",
        Default::default(),
        None,
    );

    network_config.boot_nodes = boot_nodes;

    network_config.allow_non_globals_in_dht = true;

    let addr: multiaddr::Multiaddr = multiaddr::Protocol::Memory(rand::random()).into();
    network_config.listen_addresses.push(addr.clone());

    network_config.public_addresses.push(addr);

    network_config.transport = TransportConfig::MemoryOnly;

    network_config.force_synced = force_synced;

    Configuration {
        impl_name: "subspace-test-node".to_string(),
        impl_version: "0.1".to_string(),
        role,
        tokio_handle,
        transaction_pool: Default::default(),
        network: network_config,
        keystore: KeystoreConfig::InMemory,
        keystore_remote: Default::default(),
        database: DatabaseSource::ParityDb {
            path: root.join("paritydb"),
        },
        trie_cache_maximum_size: Some(64 * 1024 * 1024),
        state_pruning: Default::default(),
        blocks_pruning: BlocksPruning::KeepAll,
        chain_spec: Box::new(spec),
        wasm_method: WasmExecutionMethod::Interpreted,
        wasm_runtime_overrides: Default::default(),
        // NOTE: we enforce the use of the native runtime to make the errors more debuggable
        execution_strategies: ExecutionStrategies {
            syncing: sc_client_api::ExecutionStrategy::NativeWhenPossible,
            importing: sc_client_api::ExecutionStrategy::NativeWhenPossible,
            block_construction: sc_client_api::ExecutionStrategy::NativeWhenPossible,
            offchain_worker: sc_client_api::ExecutionStrategy::NativeWhenPossible,
            other: sc_client_api::ExecutionStrategy::NativeWhenPossible,
        },
        rpc_http: None,
        rpc_ws: None,
        rpc_ipc: None,
        rpc_max_payload: None,
        rpc_max_request_size: None,
        rpc_max_response_size: None,
        rpc_id_provider: None,
        rpc_ws_max_connections: None,
        rpc_cors: None,
        rpc_methods: Default::default(),
        ws_max_out_buffer_capacity: None,
        prometheus_config: None,
        telemetry_endpoints: None,
        default_heap_pages: None,
        offchain_worker: Default::default(),
        force_authoring,
        disable_grandpa: false,
        dev_key_seed: Some(key_seed),
        tracing_targets: None,
        tracing_receiver: Default::default(),
        max_runtime_instances: 8,
        announce_block: true,
        base_path: Some(base_path),
        informant_output_format: Default::default(),
        runtime_cache_size: 2,
        rpc_max_subs_per_conn: None,
    }
}

/// Run a test validator node that uses the test runtime.
///
/// The node will be using an in-memory socket, therefore you need to provide boot nodes if you
/// want it to be connected to other nodes.
pub async fn run_validator_node(
    tokio_handle: tokio::runtime::Handle,
    key: Sr25519Keyring,
    boot_nodes: Vec<MultiaddrWithPeerId>,
    run_farmer: bool,
    force_authoring: bool,
    force_synced: bool,
    base_path: BasePath,
) -> (PrimaryTestNode, NetworkStarter) {
    let primary_chain_config = node_config(
        tokio_handle,
        key,
        boot_nodes,
        run_farmer,
        force_authoring,
        force_synced,
        base_path,
    );
    let multiaddr = primary_chain_config.network.listen_addresses[0].clone();
    let executor = NativeElseWasmExecutor::<TestExecutorDispatch>::new(
        primary_chain_config.wasm_method,
        primary_chain_config.default_heap_pages,
        primary_chain_config.max_runtime_instances,
        primary_chain_config.runtime_cache_size,
    );

    let primary_chain_node = {
        let span = sc_tracing::tracing::info_span!(
            sc_tracing::logging::PREFIX_LOG_SPAN,
            name = primary_chain_config.network.node_name.as_str()
        );
        let _enter = span.enter();

        let primary_chain_config = SubspaceConfiguration {
            base: primary_chain_config,
            force_new_slot_notifications: true,
            subspace_networking: SubspaceNetworking::Create {
                config: DsnConfig {
                    listen_on: vec!["/ip4/127.0.0.1/tcp/0"
                        .parse()
                        .expect("Correct multiaddr; qed")],
                    bootstrap_nodes: vec![],
                    reserved_peers: vec![],
                    keypair: identity::Keypair::generate_ed25519(),
                    allow_non_global_addresses_in_dht: true,
                    piece_publisher_batch_size: 10,
                },
                piece_cache_size: 1024 * 1024 * 1024,
            },
        };

        let partial_components = subspace_service::new_partial::<RuntimeApi, TestExecutorDispatch>(
            &primary_chain_config,
        )
        .expect("Failed to create Subspace primary node");

        subspace_service::new_full(
            primary_chain_config,
            partial_components,
            false,
            SlotProportion::new(98f32 / 100f32),
        )
        .await
        .expect("Failed to create Subspace primary node")
    };

    if run_farmer {
        start_farmer(&primary_chain_node);
    }

    let NewFull {
        task_manager,
        client,
        backend,
        network,
        rpc_handlers,
        network_starter,
        transaction_pool,
        ..
    } = primary_chain_node;

    let peer_id = network.local_peer_id();
    let addr = MultiaddrWithPeerId { multiaddr, peer_id };

    (
        PrimaryTestNode {
            task_manager,
            client,
            backend,
            executor,
            addr,
            rpc_handlers,
            transaction_pool,
        },
        network_starter,
    )
}

/// A Subspace primary test node instance used for testing.
pub struct PrimaryTestNode {
    /// `TaskManager`'s instance.
    pub task_manager: TaskManager,
    /// Client's instance.
    pub client: Arc<Client>,
    /// Backend.
    pub backend: Arc<Backend>,
    /// Code executor.
    pub executor: NativeElseWasmExecutor<TestExecutorDispatch>,
    /// The `MultiaddrWithPeerId` to this node. This is useful if you want to pass it as "boot node" to other nodes.
    pub addr: MultiaddrWithPeerId,
    /// `RPCHandlers` to make RPC queries.
    pub rpc_handlers: RpcHandlers,
    /// Transaction pool.
    pub transaction_pool: Arc<FullPool<Block, Client, FraudProofVerifier>>,
}

impl PrimaryTestNode {
    /// Send an extrinsic to this node.
    pub async fn send_extrinsic(
        &self,
        function: impl Into<subspace_test_runtime::RuntimeCall>,
        caller: Sr25519Keyring,
    ) -> Result<RpcTransactionOutput, RpcTransactionError> {
        let extrinsic = construct_extrinsic(&self.client, function, caller, 0);
        self.rpc_handlers.send_transaction(extrinsic.into()).await
    }

    /// Wait for `count` blocks to be imported in the node and then exit. This function will not return if no blocks
    /// are ever created, thus you should restrict the maximum amount of time of the test execution.
    pub fn wait_for_blocks(&self, count: usize) -> impl Future<Output = ()> {
        self.client.wait_for_blocks(count)
    }
}

/// Construct an extrinsic that can be applied to the test runtime.
pub fn construct_extrinsic(
    client: &Client,
    function: impl Into<subspace_test_runtime::RuntimeCall>,
    caller: Sr25519Keyring,
    nonce: u32,
) -> UncheckedExtrinsic {
    let function = function.into();
    let current_block_hash = client.info().best_hash;
    let current_block = client.info().best_number.saturated_into();
    let genesis_block = client.hash(0).unwrap().unwrap();
    let block_hash_count: u32 = BlockHashCount::get();
    let period = block_hash_count
        .checked_next_power_of_two()
        .map(|c| c / 2)
        .unwrap_or(2) as u64;
    let tip = 0;
    let extra: SignedExtra = (
        frame_system::CheckNonZeroSender::<Runtime>::new(),
        frame_system::CheckSpecVersion::<Runtime>::new(),
        frame_system::CheckTxVersion::<Runtime>::new(),
        frame_system::CheckGenesis::<Runtime>::new(),
        frame_system::CheckMortality::<Runtime>::from(generic::Era::mortal(period, current_block)),
        frame_system::CheckNonce::<Runtime>::from(nonce),
        frame_system::CheckWeight::<Runtime>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(tip),
    );
    let raw_payload = SignedPayload::from_raw(
        function.clone(),
        extra.clone(),
        (
            (),
            VERSION.spec_version,
            VERSION.transaction_version,
            genesis_block,
            current_block_hash,
            (),
            (),
            (),
        ),
    );
    let signature = raw_payload.using_encoded(|e| caller.sign(e));
    UncheckedExtrinsic::new_signed(
        function,
        subspace_test_runtime::Address::Id(caller.public().into()),
        sp_runtime::MultiSignature::Sr25519(signature),
        extra,
    )
}

/// Construct a transfer extrinsic.
pub fn construct_transfer_extrinsic(
    client: &Client,
    origin: sp_keyring::AccountKeyring,
    dest: sp_keyring::AccountKeyring,
    value: Balance,
) -> UncheckedExtrinsic {
    let function = subspace_test_runtime::RuntimeCall::Balances(pallet_balances::Call::transfer {
        dest: MultiSigner::from(dest.public()).into_account().into(),
        value,
    });

    construct_extrinsic(client, function, origin, 0)
}

#[cfg(test)]
mod tests {
    use super::run_validator_node;
    use sc_service::BasePath;
    use sp_keyring::Sr25519Keyring::{Alice, Bob};
    use tempfile::TempDir;

    // TODO: always enable the test to catch any potential regressions.
    #[substrate_test_utils::test]
    #[ignore]
    async fn test_primary_node_catching_up() {
        let directory = TempDir::new().expect("Must be able to create temporary directory");

        let mut builder = sc_cli::LoggerBuilder::new("");
        builder.with_colors(false);
        let _ = builder.init();

        let tokio_handle = tokio::runtime::Handle::current();

        // start alice
        let (alice, alice_network_starter) = run_validator_node(
            tokio_handle.clone(),
            Alice,
            vec![],
            true,
            true,
            true,
            BasePath::new(directory.path().join("alice")),
        )
        .await;

        alice_network_starter.start_network();

        let (bob, bob_network_starter) = run_validator_node(
            tokio_handle.clone(),
            Bob,
            vec![alice.addr],
            false,
            false,
            false,
            BasePath::new(directory.path().join("bob")),
        )
        .await;

        bob_network_starter.start_network();

        bob.wait_for_blocks(10).await;
    }
}

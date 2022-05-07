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
use sc_executor::NativeElseWasmExecutor;
use sc_network::{
    config::{NetworkConfiguration, TransportConfig},
    multiaddr,
};
use sc_service::{
    config::{DatabaseSource, KeystoreConfig, MultiaddrWithPeerId, WasmExecutionMethod},
    BasePath, Configuration, KeepBlocks, NetworkStarter, Role, RpcHandlers, TaskManager,
};
use sp_arithmetic::traits::SaturatedConversion;
use sp_blockchain::HeaderBackend;
use sp_keyring::Sr25519Keyring;
use sp_runtime::{codec::Encode, generic, traits::IdentifyAccount, MultiSigner};
use std::sync::Arc;
use subspace_runtime_primitives::Balance;
use subspace_service::{NewFull, SubspaceConfiguration};
use subspace_test_client::{chain_spec, start_farmer, Backend, Client, TestExecutorDispatch};
use subspace_test_runtime::{
    BlockHashCount, Runtime, SignedExtra, SignedPayload, UncheckedExtrinsic, VERSION,
};
use substrate_test_client::{
    BlockchainEventsExt, RpcHandlersExt, RpcTransactionError, RpcTransactionOutput,
};

/// Create a new full node.
#[sc_tracing::logging::prefix_logs_with(config.network.node_name.as_str())]
pub fn new_full(
    config: Configuration,
    enable_rpc_extensions: bool,
    run_farmer: bool,
) -> (
    NewFull<Arc<Client>>,
    NativeElseWasmExecutor<TestExecutorDispatch>,
) {
    let config = SubspaceConfiguration {
        base: config,
        force_new_slot_notifications: true,
    };
    let executor = NativeElseWasmExecutor::<TestExecutorDispatch>::new(
        config.wasm_method,
        config.default_heap_pages,
        config.max_runtime_instances,
        config.runtime_cache_size,
    );
    let new_full = subspace_service::new_full::<
        subspace_test_runtime::RuntimeApi,
        TestExecutorDispatch,
    >(config, enable_rpc_extensions)
    .expect("Failed to create Subspace full client");
    if run_farmer {
        start_farmer(&new_full);
    }
    (new_full, executor)
}

/// Create a Subspace `Configuration`.
///
/// By default an in-memory socket will be used, therefore you need to provide boot
/// nodes if you want the future node to be connected to other nodes.
pub fn node_config(
    tokio_handle: tokio::runtime::Handle,
    key: Sr25519Keyring,
    boot_nodes: Vec<MultiaddrWithPeerId>,
    run_farmer: bool,
) -> Configuration {
    let base_path = BasePath::new_temp_dir().expect("Could not create temporary directory");
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

    Configuration {
        impl_name: "subspace-test-node".to_string(),
        impl_version: "0.1".to_string(),
        role,
        tokio_handle,
        transaction_pool: Default::default(),
        network: network_config,
        keystore: KeystoreConfig::InMemory,
        keystore_remote: Default::default(),
        database: DatabaseSource::RocksDb {
            path: root.join("db"),
            cache_size: 128,
        },
        state_cache_size: 16777216,
        state_cache_child_ratio: None,
        state_pruning: Default::default(),
        keep_blocks: KeepBlocks::All,
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
        rpc_ws_max_connections: None,
        rpc_cors: None,
        rpc_methods: Default::default(),
        ws_max_out_buffer_capacity: None,
        prometheus_config: None,
        telemetry_endpoints: None,
        default_heap_pages: None,
        offchain_worker: Default::default(),
        force_authoring: false,
        disable_grandpa: false,
        dev_key_seed: Some(key_seed),
        tracing_targets: None,
        tracing_receiver: Default::default(),
        max_runtime_instances: 8,
        announce_block: true,
        base_path: Some(base_path),
        informant_output_format: Default::default(),
        runtime_cache_size: 2,
    }
}

/// Run a test validator node that uses the test runtime.
///
/// The node will be using an in-memory socket, therefore you need to provide boot nodes if you
/// want it to be connected to other nodes.
pub fn run_validator_node(
    tokio_handle: tokio::runtime::Handle,
    key: Sr25519Keyring,
    boot_nodes: Vec<MultiaddrWithPeerId>,
    run_farmer: bool,
) -> (SubspaceTestNode, NetworkStarter) {
    let config = node_config(tokio_handle, key, boot_nodes, run_farmer);
    let multiaddr = config.network.listen_addresses[0].clone();
    let (
        NewFull {
            task_manager,
            client,
            backend,
            network,
            rpc_handlers,
            network_starter,
            ..
        },
        executor,
    ) = new_full(config, false, run_farmer);

    let peer_id = *network.local_peer_id();
    let addr = MultiaddrWithPeerId { multiaddr, peer_id };

    (
        SubspaceTestNode {
            task_manager,
            client,
            backend,
            executor,
            addr,
            rpc_handlers,
        },
        network_starter,
    )
}

/// A Subspace test node instance used for testing.
pub struct SubspaceTestNode {
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
}

impl SubspaceTestNode {
    /// Send an extrinsic to this node.
    pub async fn send_extrinsic(
        &self,
        function: impl Into<subspace_test_runtime::Call>,
        caller: Sr25519Keyring,
    ) -> Result<RpcTransactionOutput, RpcTransactionError> {
        let extrinsic = construct_extrinsic(&*self.client, function, caller, 0);
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
    function: impl Into<subspace_test_runtime::Call>,
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
    let function = subspace_test_runtime::Call::Balances(pallet_balances::Call::transfer {
        dest: MultiSigner::from(dest.public()).into_account().into(),
        value,
    });

    construct_extrinsic(client, function, origin, 0)
}

#[cfg(test)]
mod tests {
    use super::run_validator_node;
    use sp_keyring::Sr25519Keyring::{Alice, Bob};

    // TODO: always enable the test to catch any potential regressions.
    #[substrate_test_utils::test]
    #[ignore]
    async fn test_primary_node_catching_up() {
        let mut builder = sc_cli::LoggerBuilder::new("");
        builder.with_colors(false);
        let _ = builder.init();

        let tokio_handle = tokio::runtime::Handle::current();

        // start alice
        let (alice, alice_network_starter) =
            run_validator_node(tokio_handle.clone(), Alice, vec![], true);

        alice_network_starter.start_network();

        let (bob, bob_network_starter) =
            run_validator_node(tokio_handle.clone(), Bob, vec![alice.addr], false);

        bob_network_starter.start_network();

        bob.wait_for_blocks(10).await;
    }
}

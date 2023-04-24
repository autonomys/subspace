// Copyright 2019-2021 Parity Technologies (UK) Ltd.
// This file is part of Cumulus.

// Cumulus is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Cumulus is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Cumulus.  If not, see <http://www.gnu.org/licenses/>.

//! Crate used for testing with Domain.

#![warn(missing_docs)]

pub mod chain_spec;
pub mod system_domain;

use sc_client_api::execution_extensions::ExecutionStrategies;
use sc_network::config::{NonReservedPeerMode, TransportConfig};
use sc_network::multiaddr;
use sc_service::config::{
    DatabaseSource, KeystoreConfig, MultiaddrWithPeerId, NetworkConfiguration,
    OffchainWorkerConfig, PruningMode, WasmExecutionMethod, WasmtimeInstantiationStrategy,
};
use sc_service::{
    BasePath, BlocksPruning, Configuration as ServiceConfiguration, Error as ServiceError, Role,
    TFullBackend,
};
use sp_arithmetic::traits::SaturatedConversion;
use sp_blockchain::HeaderBackend;
use sp_domains::DomainId;
use sp_keyring::Sr25519Keyring;
use sp_runtime::codec::Encode;
use sp_runtime::generic;
use system_domain_test_runtime::opaque::Block;

pub use sp_keyring::Sr25519Keyring as Keyring;
pub use system_domain::*;
pub use system_domain_test_runtime;

/// The backend type used by the test service.
pub type Backend = TFullBackend<Block>;

/// Create a system domain node `Configuration`.
///
/// By default an in-memory socket will be used, therefore you need to provide nodes if you want the
/// node to be connected to other nodes. If `nodes_exclusive` is `true`, the node will only connect
/// to the given `nodes` and not to any other node.
pub fn node_config(
    tokio_handle: tokio::runtime::Handle,
    key: Sr25519Keyring,
    nodes: Vec<MultiaddrWithPeerId>,
    nodes_exclusive: bool,
    role: Role,
    base_path: BasePath,
) -> Result<ServiceConfiguration, ServiceError> {
    let root = base_path.path().to_path_buf();
    let key_seed = key.to_seed();

    let spec = chain_spec::get_chain_spec(DomainId::SYSTEM);

    let mut network_config = NetworkConfiguration::new(
        format!("{key_seed} (SystemDomain)"),
        "network/test/0.1",
        Default::default(),
        None,
    );

    if nodes_exclusive {
        network_config.default_peers_set.reserved_nodes = nodes;
        network_config.default_peers_set.non_reserved_mode = NonReservedPeerMode::Deny;
    } else {
        network_config.boot_nodes = nodes;
    }

    network_config.allow_non_globals_in_dht = true;

    network_config
        .listen_addresses
        .push(multiaddr::Protocol::Memory(rand::random()).into());

    network_config.transport = TransportConfig::MemoryOnly;

    Ok(ServiceConfiguration {
        impl_name: "domain-test-node".to_string(),
        impl_version: "0.1".to_string(),
        role,
        tokio_handle,
        transaction_pool: Default::default(),
        network: network_config,
        keystore: KeystoreConfig::InMemory,
        database: DatabaseSource::ParityDb {
            path: root.join("paritydb"),
        },
        trie_cache_maximum_size: Some(16 * 1024 * 1024),
        state_pruning: Some(PruningMode::ArchiveAll),
        blocks_pruning: BlocksPruning::KeepAll,
        chain_spec: spec,
        wasm_method: WasmExecutionMethod::Compiled {
            instantiation_strategy: WasmtimeInstantiationStrategy::PoolingCopyOnWrite,
        },
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
        rpc_ws_max_connections: None,
        rpc_cors: None,
        rpc_methods: Default::default(),
        rpc_max_payload: None,
        rpc_max_request_size: None,
        rpc_max_response_size: None,
        rpc_id_provider: None,
        rpc_max_subs_per_conn: None,
        ws_max_out_buffer_capacity: None,
        prometheus_config: None,
        telemetry_endpoints: None,
        default_heap_pages: None,
        offchain_worker: OffchainWorkerConfig {
            enabled: true,
            indexing_enabled: false,
        },
        force_authoring: false,
        disable_grandpa: false,
        dev_key_seed: Some(key_seed),
        tracing_targets: None,
        tracing_receiver: Default::default(),
        max_runtime_instances: 8,
        announce_block: true,
        base_path: Some(base_path),
        informant_output_format: Default::default(),
        wasm_runtime_overrides: None,
        runtime_cache_size: 2,
    })
}

/// Construct an extrinsic that can be applied to the test runtime.
pub fn construct_extrinsic(
    client: &SClient,
    function: impl Into<system_domain_test_runtime::RuntimeCall>,
    caller: Sr25519Keyring,
    immortal: bool,
    nonce: u32,
) -> system_domain_test_runtime::UncheckedExtrinsic {
    let function = function.into();
    let current_block_hash = client.info().best_hash;
    let current_block = client.info().best_number.saturated_into();
    let genesis_block = client.hash(0).unwrap().unwrap();
    let period = system_domain_test_runtime::BlockHashCount::get()
        .checked_next_power_of_two()
        .map(|c| c / 2)
        .unwrap_or(2) as u64;
    let tip = 0;
    let extra: system_domain_test_runtime::SignedExtra =
        (
            frame_system::CheckNonZeroSender::<system_domain_test_runtime::Runtime>::new(),
            frame_system::CheckSpecVersion::<system_domain_test_runtime::Runtime>::new(),
            frame_system::CheckTxVersion::<system_domain_test_runtime::Runtime>::new(),
            frame_system::CheckGenesis::<system_domain_test_runtime::Runtime>::new(),
            frame_system::CheckMortality::<system_domain_test_runtime::Runtime>::from(
                if immortal {
                    generic::Era::Immortal
                } else {
                    generic::Era::mortal(period, current_block)
                },
            ),
            frame_system::CheckNonce::<system_domain_test_runtime::Runtime>::from(nonce),
            frame_system::CheckWeight::<system_domain_test_runtime::Runtime>::new(),
            pallet_transaction_payment::ChargeTransactionPayment::<
                system_domain_test_runtime::Runtime,
            >::from(tip),
        );
    let raw_payload = system_domain_test_runtime::SignedPayload::from_raw(
        function.clone(),
        extra.clone(),
        (
            (),
            system_domain_test_runtime::VERSION.spec_version,
            system_domain_test_runtime::VERSION.transaction_version,
            genesis_block,
            current_block_hash,
            (),
            (),
            (),
        ),
    );
    let signature = raw_payload.using_encoded(|e| caller.sign(e));
    system_domain_test_runtime::UncheckedExtrinsic::new_signed(
        function,
        subspace_test_runtime::Address::Id(caller.public().into()),
        system_domain_test_runtime::Signature::Sr25519(signature),
        extra,
    )
}

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
pub mod core_domain;
pub mod system_domain;

use domain_runtime_primitives::opaque::Block;
use domain_runtime_primitives::{Address, Signature};
use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use sc_client_api::execution_extensions::ExecutionStrategies;
use sc_network::config::{NonReservedPeerMode, TransportConfig};
use sc_network::multiaddr;
use sc_service::config::{
    DatabaseSource, KeystoreConfig, MultiaddrWithPeerId, NetworkConfiguration,
    OffchainWorkerConfig, PruningMode, WasmExecutionMethod, WasmtimeInstantiationStrategy,
};
use sc_service::{
    BasePath, BlocksPruning, Configuration as ServiceConfiguration, Error as ServiceError, Role,
};
use sp_arithmetic::traits::SaturatedConversion;
use sp_blockchain::HeaderBackend;
use sp_core::{Get, H256};
use sp_domains::DomainId;
use sp_keyring::Sr25519Keyring;
use sp_runtime::codec::Encode;
use sp_runtime::generic;
use sp_runtime::traits::Dispatchable;

pub use core_domain::*;
pub use sp_keyring::Sr25519Keyring as Keyring;
pub use system_domain::*;
pub use system_domain_test_runtime;

/// Create a domain node `Configuration`.
///
/// By default an in-memory socket will be used, therefore you need to provide nodes if you want the
/// node to be connected to other nodes. If `nodes_exclusive` is `true`, the node will only connect
/// to the given `nodes` and not to any other node.
pub fn node_config(
    domain_id: DomainId,
    tokio_handle: tokio::runtime::Handle,
    key: Sr25519Keyring,
    nodes: Vec<MultiaddrWithPeerId>,
    nodes_exclusive: bool,
    role: Role,
    base_path: BasePath,
) -> Result<ServiceConfiguration, ServiceError> {
    let root = base_path.path().to_path_buf();
    let key_seed = key.to_seed();

    let domain_name = match domain_id {
        DomainId::SYSTEM => "SystemDomain",
        DomainId::CORE_PAYMENTS => "CorePaymentsDomain",
        _ => panic!("{domain_id:?} unimplemented"),
    };

    let mut network_config = NetworkConfiguration::new(
        format!("{key_seed} ({domain_name})"),
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

    // NOTE: Block sync is disabled for the domain subnet thus the major sync state may not be accurate,
    // which will cause transaction not propagate through network properly, setting the `force_synced`
    // flag can workaround this issue.
    network_config.force_synced = true;

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
        chain_spec: chain_spec::get_chain_spec(domain_id),
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
        rpc_addr: None,
        rpc_max_request_size: 0,
        rpc_max_response_size: 0,
        rpc_id_provider: None,
        rpc_max_subs_per_conn: 0,
        rpc_port: 0,
        rpc_max_connections: 0,
        rpc_cors: None,
        rpc_methods: Default::default(),
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
        data_path: base_path.path().into(),
        base_path,
        informant_output_format: Default::default(),
        wasm_runtime_overrides: None,
        runtime_cache_size: 2,
    })
}

type SignedExtraFor<Runtime> = (
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckMortality<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    pallet_transaction_payment::ChargeTransactionPayment<Runtime>,
);

type UncheckedExtrinsicFor<Runtime> = generic::UncheckedExtrinsic<
    Address,
    <Runtime as frame_system::Config>::RuntimeCall,
    Signature,
    SignedExtraFor<Runtime>,
>;

type BalanceOf<T> = <<T as pallet_transaction_payment::Config>::OnChargeTransaction as pallet_transaction_payment::OnChargeTransaction<T>>::Balance;

/// Construct an extrinsic that can be applied to the test runtime.
pub fn construct_extrinsic_generic<Runtime, Client>(
    client: impl AsRef<Client>,
    function: impl Into<<Runtime as frame_system::Config>::RuntimeCall>,
    caller: Sr25519Keyring,
    immortal: bool,
    nonce: u32,
) -> UncheckedExtrinsicFor<Runtime>
where
    Runtime: frame_system::Config<Hash = H256, BlockNumber = u32>
        + pallet_transaction_payment::Config
        + Send
        + Sync,
    Runtime::RuntimeCall:
        Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo> + Send + Sync,
    BalanceOf<Runtime>: Send + Sync + From<u64> + sp_runtime::FixedPointOperand,
    Client: HeaderBackend<Block>,
{
    let function = function.into();
    let current_block_hash = client.as_ref().info().best_hash;
    let current_block = client.as_ref().info().best_number.saturated_into();
    let genesis_block = client.as_ref().hash(0).unwrap().unwrap();
    let period = <Runtime as frame_system::Config>::BlockHashCount::get()
        .checked_next_power_of_two()
        .map(|c| c / 2)
        .unwrap_or(2) as u64;
    let tip = 0;
    let extra: SignedExtraFor<Runtime> = (
        frame_system::CheckNonZeroSender::<Runtime>::new(),
        frame_system::CheckSpecVersion::<Runtime>::new(),
        frame_system::CheckTxVersion::<Runtime>::new(),
        frame_system::CheckGenesis::<Runtime>::new(),
        frame_system::CheckMortality::<Runtime>::from(if immortal {
            generic::Era::Immortal
        } else {
            generic::Era::mortal(period, current_block)
        }),
        frame_system::CheckNonce::<Runtime>::from(nonce.into()),
        frame_system::CheckWeight::<Runtime>::new(),
        pallet_transaction_payment::ChargeTransactionPayment::<Runtime>::from(tip.into()),
    );
    let raw_payload = generic::SignedPayload::<
        <Runtime as frame_system::Config>::RuntimeCall,
        SignedExtraFor<Runtime>,
    >::from_raw(
        function.clone(),
        extra.clone(),
        ((), 0, 0, genesis_block, current_block_hash, (), (), ()),
    );
    let signature = raw_payload.using_encoded(|e| caller.sign(e));
    UncheckedExtrinsicFor::<Runtime>::new_signed(
        function,
        subspace_test_runtime::Address::Id(caller.public().into()),
        Signature::Sr25519(signature),
        extra,
    )
}

/// Construct an unsigned extrinsic that can be applied to the test runtime.
pub fn construct_unsigned_extrinsic<Runtime>(
    function: impl Into<<Runtime as frame_system::Config>::RuntimeCall>,
) -> UncheckedExtrinsicFor<Runtime>
where
    Runtime: frame_system::Config<Hash = H256, BlockNumber = u32>
        + pallet_transaction_payment::Config
        + Send
        + Sync,
    Runtime::RuntimeCall:
        Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo> + Send + Sync,
    BalanceOf<Runtime>: Send + Sync + From<u64> + sp_runtime::FixedPointOperand,
{
    let function = function.into();
    UncheckedExtrinsicFor::<Runtime>::new_unsigned(function)
}

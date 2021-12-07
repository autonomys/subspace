// Copyright 2017-2020 Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

use super::Error;
use lru::LruCache;
pub use polkadot_node_collation_generation::CollationGenerationSubsystem;
pub use polkadot_node_core_chain_api::ChainApiSubsystem;
pub use polkadot_node_core_runtime_api::RuntimeApiSubsystem;
use polkadot_node_subsystem_util::metrics::Metrics;
use polkadot_overseer::{
    metrics::Metrics as OverseerMetrics, BlockInfo, MetricsTrait, Overseer, OverseerConnector,
    OverseerHandle, KNOWN_LEAVES_CACHE_SIZE,
};
use sc_client_api::AuxStore;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::SpawnNamed;
use sp_executor::ExecutorApi;
use std::sync::Arc;
use subspace_runtime::opaque::Block;
use substrate_prometheus_endpoint::Registry;

/// Arguments passed for overseer construction.
pub struct CreateOverseerArgs<'a, Spawner, RuntimeClient>
where
    RuntimeClient: 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block> + AuxStore,
    RuntimeClient::Api: ExecutorApi<Block>,
    Spawner: 'static + SpawnNamed + Clone + Unpin,
{
    /// Overseer connector.
    pub connector: OverseerConnector,
    /// Set of initial relay chain leaves to track.
    pub leaves: Vec<BlockInfo>,
    /// Runtime client generic, providing the `ProvieRuntimeApi` trait besides others.
    pub runtime_client: Arc<RuntimeClient>,
    /// Prometheus registry, commonly used for production systems, less so for test.
    pub registry: Option<&'a Registry>,
    /// Task spawner to be used throughout the overseer and the APIs it provides.
    pub spawner: Spawner,
}

/// Obtain a prepared `OverseerBuilder`, that is initialized
/// with all default values.
pub fn create_overseer<Spawner, RuntimeClient>(
    CreateOverseerArgs {
        connector,
        leaves,
        runtime_client,
        registry,
        spawner,
    }: CreateOverseerArgs<Spawner, RuntimeClient>,
) -> Result<(Overseer<Spawner>, OverseerHandle), Error>
where
    RuntimeClient: 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block> + AuxStore,
    RuntimeClient::Api: ExecutorApi<Block>,
    Spawner: 'static + SpawnNamed + Clone + Unpin,
{
    let metrics = <OverseerMetrics as MetricsTrait>::register(registry)?;

    Overseer::builder()
        .chain_api(ChainApiSubsystem::new(
            runtime_client.clone(),
            Metrics::register(registry)?,
        ))
        .collation_generation(CollationGenerationSubsystem::new(Metrics::register(
            registry,
        )?))
        .runtime_api(RuntimeApiSubsystem::new(
            runtime_client,
            Metrics::register(registry)?,
            spawner.clone(),
        ))
        .leaves(Vec::from_iter(leaves.into_iter().map(
            |BlockInfo {
                 hash,
                 parent_hash: _,
                 number,
             }| (hash, number),
        )))
        .activation_external_listeners(Default::default())
        .span_per_active_leaf(Default::default())
        .active_leaves(Default::default())
        .known_leaves(LruCache::new(KNOWN_LEAVES_CACHE_SIZE))
        .metrics(metrics)
        .spawner(spawner)
        .build_with_connector(connector)
        .map_err(Into::into)
}

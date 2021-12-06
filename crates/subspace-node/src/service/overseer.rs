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
use polkadot_overseer::{
    metrics::Metrics as OverseerMetrics, BlockInfo, MetricsTrait, Overseer, OverseerBuilder,
    OverseerConnector, OverseerHandle,
};
use sc_client_api::AuxStore;
use sc_keystore::LocalKeystore;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::SpawnNamed;
use sp_executor::ExecutorApi;
use std::sync::Arc;
use subspace_runtime::{opaque::Block, Hash};
use subspace_runtime_primitives::CollatorPair;
use substrate_prometheus_endpoint::Registry;

/// Is this node a collator?
#[derive(Clone)]
pub enum IsCollator {
    /// This node is a collator.
    Yes(CollatorPair),
    /// This node is not a collator.
    No,
}

impl std::fmt::Debug for IsCollator {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use sp_core::Pair;
        match self {
            Self::Yes(pair) => write!(fmt, "Yes({})", pair.public()),
            Self::No => write!(fmt, "No"),
        }
    }
}

impl IsCollator {
    /// Is this a collator?
    pub fn is_collator(&self) -> bool {
        matches!(self, Self::Yes(_))
    }
}

/// Arguments passed for overseer construction.
pub struct OverseerGenArgs<'a, Spawner, RuntimeClient>
where
    RuntimeClient: 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block> + AuxStore,
    RuntimeClient::Api: ExecutorApi<Block>,
    Spawner: 'static + SpawnNamed + Clone + Unpin,
{
    /// Set of initial relay chain leaves to track.
    pub leaves: Vec<BlockInfo>,
    /// The keystore to use for i.e. validator keys.
    pub keystore: Arc<LocalKeystore>,
    /// Runtime client generic, providing the `ProvieRuntimeApi` trait besides others.
    pub runtime_client: Arc<RuntimeClient>,
    /// Underlying network service implementation.
    pub network_service: Arc<sc_network::NetworkService<Block, Hash>>,
    /// Prometheus registry, commonly used for production systems, less so for test.
    pub registry: Option<&'a Registry>,
    /// Task spawner to be used throughout the overseer and the APIs it provides.
    pub spawner: Spawner,
    /// Determines the behavior of the collator.
    pub is_collator: IsCollator,
}

/// Obtain a prepared `OverseerBuilder`, that is initialized
/// with all default values.
pub fn prepared_overseer_builder<Spawner, RuntimeClient>(
    OverseerGenArgs {
        leaves,
        keystore: _,
        runtime_client,
        network_service: _,
        registry,
        spawner,
        is_collator: _,
    }: OverseerGenArgs<Spawner, RuntimeClient>,
) -> Result<
    OverseerBuilder<
        Spawner,
        RuntimeApiSubsystem<RuntimeClient>,
        ChainApiSubsystem<RuntimeClient>,
        CollationGenerationSubsystem,
    >,
    Error,
>
where
    RuntimeClient: 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block> + AuxStore,
    RuntimeClient::Api: ExecutorApi<Block>,
    Spawner: 'static + SpawnNamed + Clone + Unpin,
{
    use polkadot_node_subsystem_util::metrics::Metrics;

    let metrics = <OverseerMetrics as MetricsTrait>::register(registry)?;

    let builder = Overseer::builder()
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
        .spawner(spawner);
    Ok(builder)
}

/// Trait for the `fn` generating the overseer.
///
/// Default behavior is to create an unmodified overseer, as `RealOverseerGen`
/// would do.
pub trait OverseerGen {
    /// Overwrite the full generation of the overseer, including the subsystems.
    fn generate<Spawner, RuntimeClient>(
        &self,
        connector: OverseerConnector,
        args: OverseerGenArgs<Spawner, RuntimeClient>,
    ) -> Result<(Overseer<Spawner>, OverseerHandle), Error>
    where
        RuntimeClient: 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block> + AuxStore,
        RuntimeClient::Api: ExecutorApi<Block>,
        Spawner: 'static + SpawnNamed + Clone + Unpin,
    {
        let gen = RealOverseerGen;
        RealOverseerGen::generate::<Spawner, RuntimeClient>(&gen, connector, args)
    }
    // It would be nice to make `create_subsystems` part of this trait,
    // but the amount of generic arguments that would be required as
    // as consequence make this rather annoying to implement and use.
}

use polkadot_overseer::KNOWN_LEAVES_CACHE_SIZE;

/// The regular set of subsystems.
pub struct RealOverseerGen;

impl OverseerGen for RealOverseerGen {
    fn generate<Spawner, RuntimeClient>(
        &self,
        connector: OverseerConnector,
        args: OverseerGenArgs<Spawner, RuntimeClient>,
    ) -> Result<(Overseer<Spawner>, OverseerHandle), Error>
    where
        RuntimeClient: 'static + ProvideRuntimeApi<Block> + HeaderBackend<Block> + AuxStore,
        RuntimeClient::Api: ExecutorApi<Block>,
        Spawner: 'static + SpawnNamed + Clone + Unpin,
    {
        prepared_overseer_builder(args)?
            .build_with_connector(connector)
            .map_err(|e| e.into())
    }
}

use crate::dsn::DsnConfig;
use prometheus_client::registry::Registry;
use sc_service::Configuration;
use std::collections::HashSet;
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::Node;

/// Subspace networking instantiation variant
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SubspaceNetworking {
    /// Use existing networking instance
    Reuse {
        /// Node instance
        node: Node,
        /// Bootstrap nodes used (that can be also sent to the farmer over RPC)
        bootstrap_nodes: Vec<Multiaddr>,
        /// DSN metrics registry
        metrics_registry: Option<Registry>,
    },
    /// Networking must be instantiated internally
    Create {
        /// Configuration to use for DSN instantiation
        config: DsnConfig,
    },
}

/// Subspace-specific service configuration.
#[derive(Debug)]
pub struct SubspaceConfiguration {
    /// Base configuration.
    pub base: Configuration,
    /// Whether slot notifications need to be present even if node is not responsible for block
    /// authoring.
    pub force_new_slot_notifications: bool,
    /// Subspace networking (DSN).
    pub subspace_networking: SubspaceNetworking,
    /// Enables DSN-sync on startup.
    pub sync_from_dsn: bool,
    /// Is this node a Timekeeper
    pub is_timekeeper: bool,
    /// CPU cores that timekeeper can use
    pub timekeeper_cpu_cores: HashSet<usize>,
}

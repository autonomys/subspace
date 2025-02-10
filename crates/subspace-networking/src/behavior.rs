pub(crate) mod persistent_parameters;
#[cfg(test)]
mod tests;

use crate::constructor::DummyRecordStore;
use crate::protocols::autonat_wrapper::{
    Behaviour as AutonatWrapper, Config as AutonatWrapperConfig,
};
use crate::protocols::request_response::request_response_factory::{
    Event as RequestResponseEvent, RequestHandler, RequestResponseFactoryBehaviour,
};
use crate::protocols::reserved_peers::{
    Behaviour as ReservedPeersBehaviour, Config as ReservedPeersConfig, Event as ReservedPeersEvent,
};
use crate::protocols::subspace_connection_limits::Behaviour as ConnectionLimitsBehaviour;
use derive_more::From;
use libp2p::allow_block_list::{Behaviour as AllowBlockListBehaviour, BlockedPeers};
use libp2p::autonat::Event as AutonatEvent;
use libp2p::connection_limits::ConnectionLimits;
use libp2p::gossipsub::{
    Behaviour as Gossipsub, Config as GossipsubConfig, Event as GossipsubEvent, MessageAuthenticity,
};
use libp2p::identify::{Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent};
use libp2p::kad::{Behaviour as Kademlia, Config as KademliaConfig, Event as KademliaEvent};
use libp2p::ping::{Behaviour as Ping, Event as PingEvent};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::PeerId;
use void::Void as VoidEvent;

type BlockListBehaviour = AllowBlockListBehaviour<BlockedPeers>;

pub(crate) struct BehaviorConfig {
    /// Identity keypair of a node used for authenticated connections.
    pub(crate) peer_id: PeerId,
    /// The configuration for the [`Identify`] behaviour.
    pub(crate) identify: IdentifyConfig,
    /// The configuration for the [`Kademlia`] behaviour.
    pub(crate) kademlia: KademliaConfig,
    /// The configuration for the [`Gossipsub`] behaviour.
    pub(crate) gossipsub: Option<GossipsubConfig>,
    /// The configuration for the [`RequestResponsesBehaviour`] protocol.
    pub(crate) request_response_protocols: Vec<Box<dyn RequestHandler>>,
    /// The upper bound for the number of concurrent inbound + outbound streams for request/response
    /// protocols.
    pub(crate) request_response_max_concurrent_streams: usize,
    /// Connection limits for the swarm.
    pub(crate) connection_limits: ConnectionLimits,
    /// The configuration for the [`ReservedPeersBehaviour`].
    pub(crate) reserved_peers: ReservedPeersConfig,
    /// Autonat configuration.
    pub(crate) autonat: AutonatWrapperConfig,
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
pub(crate) struct Behavior {
    // TODO: Connection limits must be the first protocol due to https://github.com/libp2p/rust-libp2p/issues/4773 as
    //  suggested in https://github.com/libp2p/rust-libp2p/issues/4898#issuecomment-1818013483
    pub(crate) connection_limits: ConnectionLimitsBehaviour,
    pub(crate) identify: Identify,
    pub(crate) kademlia: Kademlia<DummyRecordStore>,
    pub(crate) gossipsub: Toggle<Gossipsub>,
    pub(crate) ping: Ping,
    pub(crate) request_response: RequestResponseFactoryBehaviour,
    pub(crate) block_list: BlockListBehaviour,
    pub(crate) reserved_peers: ReservedPeersBehaviour,
    pub(crate) autonat: AutonatWrapper,
}

impl Behavior {
    pub(crate) fn new(config: BehaviorConfig) -> Self {
        let kademlia = Kademlia::with_config(config.peer_id, DummyRecordStore, config.kademlia);

        let gossipsub = config
            .gossipsub
            .map(|gossip_config| {
                Gossipsub::new(
                    // TODO: Do we want message signing?
                    MessageAuthenticity::Anonymous,
                    gossip_config,
                )
                .expect("Correct configuration")
            })
            .into();

        Self {
            connection_limits: ConnectionLimitsBehaviour::new(config.connection_limits),
            identify: Identify::new(config.identify),
            kademlia,
            gossipsub,
            ping: Ping::default(),
            request_response: RequestResponseFactoryBehaviour::new(
                config.request_response_protocols,
                config.request_response_max_concurrent_streams,
            )
            //TODO: Convert to an error.
            .expect("RequestResponse protocols registration failed."),
            block_list: BlockListBehaviour::default(),
            reserved_peers: ReservedPeersBehaviour::new(config.reserved_peers),
            autonat: AutonatWrapper::new(config.autonat),
        }
    }
}

#[derive(Debug, From)]
pub(crate) enum Event {
    Identify(IdentifyEvent),
    Kademlia(KademliaEvent),
    Gossipsub(GossipsubEvent),
    Ping(PingEvent),
    RequestResponse(RequestResponseEvent),
    /// Event stub for connection limits and block list behaviours. We won't receive such events.
    VoidEventStub(VoidEvent),
    ReservedPeers(ReservedPeersEvent),
    Autonat(AutonatEvent),
}

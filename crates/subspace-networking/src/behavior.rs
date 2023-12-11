pub(crate) mod persistent_parameters;
#[cfg(test)]
mod tests;

use crate::protocols::autonat_wrapper::{
    Behaviour as AutonatWrapper, Config as AutonatWrapperConfig,
};
use crate::protocols::connected_peers::Config as ConnectedPeersConfig;
use crate::protocols::peer_info::Event as PeerInfoEvent;
use crate::protocols::request_response::request_response_factory::{
    Event as RequestResponseEvent, RequestHandler, RequestResponseFactoryBehaviour,
};
use crate::protocols::reserved_peers::{
    Behaviour as ReservedPeersBehaviour, Config as ReservedPeersConfig, Event as ReservedPeersEvent,
};
use crate::protocols::subspace_connection_limits::Behaviour as ConnectionLimitsBehaviour;
use crate::{PeerInfoConfig, PeerInfoProvider};
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

pub(crate) struct BehaviorConfig<RecordStore> {
    /// Identity keypair of a node used for authenticated connections.
    pub(crate) peer_id: PeerId,
    /// The configuration for the [`Identify`] behaviour.
    pub(crate) identify: IdentifyConfig,
    /// The configuration for the [`Kademlia`] behaviour.
    pub(crate) kademlia: KademliaConfig,
    /// The configuration for the [`Gossipsub`] behaviour.
    pub(crate) gossipsub: Option<GossipsubConfig>,
    /// Externally provided implementation of the custom record store for Kademlia DHT,
    pub(crate) record_store: RecordStore,
    /// The configuration for the [`RequestResponsesBehaviour`] protocol.
    pub(crate) request_response_protocols: Vec<Box<dyn RequestHandler>>,
    /// Connection limits for the swarm.
    pub(crate) connection_limits: ConnectionLimits,
    /// The configuration for the [`ReservedPeersBehaviour`].
    pub(crate) reserved_peers: ReservedPeersConfig,
    // TODO: Restore or remove connected peer later
    #[allow(dead_code)]
    /// The configuration for the [`PeerInfo`] protocol.
    pub(crate) peer_info_config: PeerInfoConfig,
    // TODO: Restore or remove connected peer later
    #[allow(dead_code)]
    /// Provides peer-info for local peer.
    pub(crate) peer_info_provider: Option<PeerInfoProvider>,
    /// The configuration for the [`ConnectedPeers`] protocol (general instance).
    // TODO: Restore or remove connected peer later
    #[allow(dead_code)]
    pub(crate) general_connected_peers_config: Option<ConnectedPeersConfig>,
    // TODO: Restore or remove connected peer later
    #[allow(dead_code)]
    /// The configuration for the [`ConnectedPeers`] protocol (special instance).
    pub(crate) special_connected_peers_config: Option<ConnectedPeersConfig>,
    /// Autonat configuration.
    pub(crate) autonat: AutonatWrapperConfig,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GeneralConnectedPeersInstance;
#[derive(Debug, Clone, Copy)]
pub(crate) struct SpecialConnectedPeersInstance;

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event")]
#[behaviour(event_process = false)]
pub(crate) struct Behavior<RecordStore> {
    // TODO: Connection limits must be the first protocol due to https://github.com/libp2p/rust-libp2p/issues/4773 as
    //  suggested in https://github.com/libp2p/rust-libp2p/issues/4898#issuecomment-1818013483
    pub(crate) connection_limits: ConnectionLimitsBehaviour,
    pub(crate) identify: Identify,
    pub(crate) kademlia: Kademlia<RecordStore>,
    pub(crate) gossipsub: Toggle<Gossipsub>,
    pub(crate) ping: Ping,
    pub(crate) request_response: RequestResponseFactoryBehaviour,
    pub(crate) block_list: BlockListBehaviour,
    pub(crate) reserved_peers: ReservedPeersBehaviour,
    // TODO: Restore or remove connected peer later
    // pub(crate) peer_info: Toggle<PeerInfoBehaviour>,
    // pub(crate) general_connected_peers:
    //     Toggle<ConnectedPeersBehaviour<GeneralConnectedPeersInstance>>,
    // pub(crate) special_connected_peers:
    //     Toggle<ConnectedPeersBehaviour<SpecialConnectedPeersInstance>>,
    pub(crate) autonat: AutonatWrapper,
}

impl<RecordStore> Behavior<RecordStore>
where
    RecordStore: Send + Sync + libp2p::kad::store::RecordStore + 'static,
{
    pub(crate) fn new(config: BehaviorConfig<RecordStore>) -> Self {
        let kademlia = Kademlia::<RecordStore>::with_config(
            config.peer_id,
            config.record_store,
            config.kademlia,
        );

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

        // TODO: Restore or remove connected peer later
        // let peer_info = config
        //     .peer_info_provider
        //     .map(|provider| PeerInfoBehaviour::new(config.peer_info_config, provider));

        Self {
            connection_limits: ConnectionLimitsBehaviour::new(config.connection_limits),
            identify: Identify::new(config.identify),
            kademlia,
            gossipsub,
            ping: Ping::default(),
            request_response: RequestResponseFactoryBehaviour::new(
                config.request_response_protocols,
            )
            //TODO: Convert to an error.
            .expect("RequestResponse protocols registration failed."),
            block_list: BlockListBehaviour::default(),
            reserved_peers: ReservedPeersBehaviour::new(config.reserved_peers),
            // TODO: Restore or remove connected peer later
            //peer_info: peer_info.into(),
            // general_connected_peers: config
            //     .general_connected_peers_config
            //     .map(ConnectedPeersBehaviour::new)
            //     .into(),
            // special_connected_peers: config
            //     .special_connected_peers_config
            //     .map(ConnectedPeersBehaviour::new)
            //     .into(),
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
    PeerInfo(PeerInfoEvent),
    // TODO: Restore or remove connected peer later
    // GeneralConnectedPeers(ConnectedPeersEvent<GeneralConnectedPeersInstance>),
    // SpecialConnectedPeers(ConnectedPeersEvent<SpecialConnectedPeersInstance>),
    Autonat(AutonatEvent),
}

pub(crate) mod custom_record_store;
pub(crate) mod persistent_parameters;
#[cfg(test)]
mod tests;

use crate::request_responses::{
    Event as RequestResponseEvent, RequestHandler, RequestResponsesBehaviour,
};
use custom_record_store::CustomRecordStore;
use derive_more::From;
use libp2p::gossipsub::{Gossipsub, GossipsubConfig, GossipsubEvent, MessageAuthenticity};
use libp2p::identify::{Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent};
use libp2p::kad::{Kademlia, KademliaConfig, KademliaEvent};
use libp2p::ping::{Behaviour as Ping, Event as PingEvent};
use libp2p::{NetworkBehaviour, PeerId};

pub(crate) struct BehaviorConfig<RecordStore = CustomRecordStore> {
    /// Identity keypair of a node used for authenticated connections.
    pub(crate) peer_id: PeerId,
    /// The configuration for the [`Identify`] behaviour.
    pub(crate) identify: IdentifyConfig,
    /// The configuration for the [`Kademlia`] behaviour.
    pub(crate) kademlia: KademliaConfig,
    /// The configuration for the [`Gossipsub`] behaviour.
    pub(crate) gossipsub: GossipsubConfig,
    /// Externally provided implementation of the custom record store for Kademlia DHT,
    pub(crate) record_store: RecordStore,
    /// The configuration for the [`RequestResponsesBehaviour`] protocol.
    pub(crate) request_response_protocols: Vec<Box<dyn RequestHandler>>,
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event")]
#[behaviour(event_process = false)]
pub(crate) struct Behavior<RecordStore> {
    pub(crate) identify: Identify,
    pub(crate) kademlia: Kademlia<RecordStore>,
    pub(crate) gossipsub: Gossipsub,
    pub(crate) ping: Ping,
    pub(crate) request_response: RequestResponsesBehaviour,
}

impl<RecordStore> Behavior<RecordStore>
where
    RecordStore: Send + Sync + for<'a> libp2p::kad::store::RecordStore<'a> + 'static,
{
    pub(crate) fn new(config: BehaviorConfig<RecordStore>) -> Self {
        let kademlia = Kademlia::<RecordStore>::with_config(
            config.peer_id,
            config.record_store,
            config.kademlia,
        );

        let gossipsub = Gossipsub::new(
            // TODO: Do we want message signing?
            MessageAuthenticity::Anonymous,
            config.gossipsub,
        )
        .expect("Correct configuration");

        Self {
            identify: Identify::new(config.identify),
            kademlia,
            gossipsub,
            ping: Ping::default(),
            request_response: RequestResponsesBehaviour::new(
                config.request_response_protocols.into_iter(),
            )
            //TODO: Convert to an error.
            .expect("RequestResponse protocols registration failed."),
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
}

use libp2p::identify::{Identify, IdentifyEvent};
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{Kademlia, KademliaEvent};
use libp2p::ping::{Ping, PingEvent};
use libp2p::NetworkBehaviour;

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event")]
#[behaviour(event_process = false)]
pub(crate) struct Behaviour {
    pub(crate) kademlia: Kademlia<MemoryStore>,
    pub(crate) identify: Identify,
    pub(crate) ping: Ping,
}

#[derive(Debug)]
pub(crate) enum Event {
    Kademlia(KademliaEvent),
    Identify(IdentifyEvent),
    Ping(PingEvent),
}

impl From<KademliaEvent> for Event {
    fn from(event: KademliaEvent) -> Self {
        Event::Kademlia(event)
    }
}

impl From<IdentifyEvent> for Event {
    fn from(event: IdentifyEvent) -> Self {
        Event::Identify(event)
    }
}

impl From<PingEvent> for Event {
    fn from(event: PingEvent) -> Self {
        Event::Ping(event)
    }
}

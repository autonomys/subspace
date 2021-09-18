// Pull imports from the parent module
use super::*;

#[derive(NetworkBehaviour)]
#[behaviour(event_process = false, out_event = "ComposedEvent")]
pub struct ComposedBehaviour {
    kademlia: Kademlia<MemoryStore>,
}

pub enum ComposedEvent {
    Kademlia(KademliaEvent),
}

impl From<KademliaEvent> for ComposedEvent {
    fn from(event: KademliaEvent) -> Self {
        ComposedEvent::Kademlia(event)
    }
}

use super::client::{handle_client_event, ClientEvent};
use super::core::{ComposedBehaviour, ComposedEvent};
use super::*;

pub struct EventLoop {
    swarm: Swarm<ComposedBehaviour>,
    client_rx: Receiver<ClientEvent>,
    network_tx: Sender<ClientEvent>,
}

impl EventLoop {
    /// Create new event loop
    pub fn new(
        swarm: Swarm<ComposedBehaviour>,
        client_rx: Receiver<ClientEvent>,
        network_tx: Sender<ClientEvent>,
    ) -> Self {
        EventLoop {
            swarm,
            client_rx,
            network_tx,
        }
    }

    /// Run event loop. We will use this method to spawn the event loop in a background task.
    pub async fn run(mut self) {
        loop {
            futures::select! {
                client_event = self.client_rx.next() => self.handle_event(client_event.unwrap()),
                network_event = self.swarm.next() => match network_event {
                    Some(event) => self.handle_network_event(event).await,
                    None => break,
                }
            }
        }
    }

    // NOTE: This method is just a wrapper around the actual method that will handle client events.
    // We have to put the handle client event method in the EventLoop impl because it needs access
    // to the swarm.
    fn handle_event(&mut self, event: ClientEvent) {
        handle_client_event(&mut self.swarm, event)
    }

    async fn handle_network_event(&mut self, event: SwarmEvent<ComposedEvent, std::io::Error>) {
        match event {
            SwarmEvent::Behaviour(event) => match event {
                ComposedEvent::Kademlia(event) => match event {
                    _ => {}
                },
            },
            SwarmEvent::NewListenAddr { address, .. } => {
                self.network_tx
                    .send(ClientEvent::ReturnListen {
                        addr: address.clone(),
                    })
                    .await
                    .unwrap();
            }
            SwarmEvent::UnreachableAddr { .. } => todo!(),
            SwarmEvent::Dialing(_) => todo!(),
            _ => {}
        }
    }
}

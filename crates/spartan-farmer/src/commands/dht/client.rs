use super::core::{create_bootstrap, create_node, ComposedBehaviour};
use super::eventloop::EventLoop;
use super::*;

#[derive(Debug)]
pub enum ClientEvent {
    Listen {
        addr: Multiaddr,
        sender: oneshot::Sender<OneshotType>,
    },
}

pub enum ClientType {
    Bootstrap,
    Normal,
}

// TODO: It would make sense to add an enum for the types of `Clients`: `Normal` and `Bootnode
pub struct Client {
    client_tx: Sender<ClientEvent>,
}

impl Client {
    pub fn new(client_tx: Sender<ClientEvent>) -> Self {
        Client { client_tx }
    }

    pub async fn start_listening(&mut self, addr: Multiaddr) {
        let (tx, rx) = oneshot::channel();

        self.client_tx
            .send(ClientEvent::Listen { addr, sender: tx })
            .await
            .unwrap();

        rx.await.expect("Failed to start listening.");
    }

    pub async fn dial() {}
}

pub type BootAddr = String;

pub struct ClientConfig {
    // This will be true, if we are running a bootstrap node.
    pub bootstrap: bool,
    pub bootstrap_nodes: Vec<BootAddr>,
    // pub bootstrap_keys: Vec<BootAddr>,
    pub client_type: ClientType,
}

// TODO: This method needs a new (and, better) name.
/// This method will construct a new Swarm and EventLoop object.
pub async fn create_connection(config: ClientConfig) -> (Client, EventLoop) {
    let (client_tx, client_rx) = channel(10);

    let client = Client::new(client_tx);

    // TODO: We need to split the creation of bootstrap nodes at this point, don't call create_swarm at
    // all.
    // - If, we have an enum for Client type, this can be made even better.
    // - The seperate method to create bootnodes can be in the `Client` module and called by `farm.rs`.
    // - We can read the ClientConfig file, in that method itself.
    // - We can even it spawn another task for it.

    match config.client_type {
        ClientType::Bootstrap => {
            let eventloop = EventLoop::new(create_bootstrap(config).await, client_rx);
            return (client, eventloop);
        }
        ClientType::Normal => {
            let eventloop = EventLoop::new(create_node(config).await, client_rx);
            return (client, eventloop);
        }
    }
}

pub fn handle_client_event(swarm: &mut Swarm<ComposedBehaviour>, event: ClientEvent) {
    match event {
        ClientEvent::Listen { addr, sender } => match swarm.listen_on(addr) {
            Ok(_) => {
                sender.send(Ok(())).unwrap();
            }
            Err(e) => {
                sender.send(Err(Box::new(e))).unwrap();
            }
        },
        _ => {}
    }
}

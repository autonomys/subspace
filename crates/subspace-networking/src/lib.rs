// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Networking functionality of Subspace Network, primarily used for DSN (Distributed Storage
//! Network).

pub use libp2p;
use libp2p::dns::TokioDnsConfig;
use libp2p::futures::channel::mpsc;
use libp2p::futures::StreamExt;
use libp2p::identify::{Identify, IdentifyConfig, IdentifyEvent};
use libp2p::kad::record::store::MemoryStore;
use libp2p::kad::{Kademlia, KademliaConfig, KademliaEvent};
use libp2p::noise::NoiseConfig;
use libp2p::ping::{Ping, PingEvent};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::tcp::TokioTcpConfig;
use libp2p::websocket::WsConfig;
use libp2p::yamux::{WindowUpdateMode, YamuxConfig};
use libp2p::{
    core, futures, identity, noise, Multiaddr, NetworkBehaviour, PeerId, Transport, TransportError,
};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};
use thiserror::Error;

const KADEMLIA_PROTOCOL: &[u8] = b"/subspace/kad";

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ComposedEvent")]
#[behaviour(event_process = false)]
struct ComposedBehaviour {
    kademlia: Kademlia<MemoryStore>,
    identify: Identify,
    ping: Ping,
}

#[derive(Debug)]
enum ComposedEvent {
    Kademlia(KademliaEvent),
    Identify(IdentifyEvent),
    Ping(PingEvent),
}

impl From<KademliaEvent> for ComposedEvent {
    fn from(event: KademliaEvent) -> Self {
        ComposedEvent::Kademlia(event)
    }
}

impl From<IdentifyEvent> for ComposedEvent {
    fn from(event: IdentifyEvent) -> Self {
        ComposedEvent::Identify(event)
    }
}

impl From<PingEvent> for ComposedEvent {
    fn from(event: PingEvent) -> Self {
        ComposedEvent::Ping(event)
    }
}

/// [`Node`] configuration.
#[derive(Clone)]
pub struct Config {
    /// Identity keypair of a node used for authenticated connections.
    pub keypair: identity::Keypair,
    /// Nodes to connect to on creation.
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    /// List of [`Multiaddr`] on which to listen for incoming connections.
    pub listen_on: Vec<Multiaddr>,
    /// Adds a timeout to the setup and protocol upgrade process for all inbound and outbound
    /// connections established through the transport.
    pub timeout: Duration,
    /// The configuration for the [`Kademlia`] behaviour.
    pub kademlia_config: KademliaConfig,
    /// Yamux multiplexing configuration.
    pub yamux_config: YamuxConfig,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkConfig").finish()
    }
}

impl Config {
    pub fn new(keypair: identity::ed25519::Keypair) -> Self {
        let mut kademlia_config = KademliaConfig::default();
        kademlia_config.set_protocol_name(KADEMLIA_PROTOCOL);

        let mut yamux_config = YamuxConfig::default();
        // Enable proper flow-control: window updates are only sent when buffered data has been
        // consumed.
        yamux_config.set_window_update_mode(WindowUpdateMode::on_read());

        Self {
            keypair: identity::Keypair::Ed25519(keypair),
            bootstrap_nodes: vec![],
            listen_on: vec![],
            timeout: Duration::from_secs(10),
            kademlia_config,
            yamux_config,
        }
    }
}

/// Errors that might happen during network creation.
#[derive(Debug, Error)]
pub enum CreationError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Transport error when attempting to listen on multiaddr.
    #[error("Transport error when attempting to listen on multiaddr: {0}")]
    TransportError(#[from] TransportError<io::Error>),
}

#[derive(Debug)]
enum Command {
    // TODO
}

#[derive(Debug)]
struct Inner {
    local_peer_id: PeerId,
    local_peer_addresses: Mutex<Vec<Multiaddr>>,
    command_sender: mpsc::Sender<Command>,
}

/// Runner for then Node
#[must_use = "Node does not function properly unless its runner is driven forward"]
pub struct NodeRunner {
    command_receiver: mpsc::Receiver<Command>,
    swarm: Swarm<ComposedBehaviour>,
    inner: Arc<Inner>,
}

impl NodeRunner {
    pub async fn run(&mut self) {
        loop {
            futures::select! {
                swarm_event = self.swarm.next() => {
                    if let Some(swarm_event) = swarm_event {
                        self.handle_swarm_event(swarm_event).await;
                    } else {
                        break;
                    }
                },
                command = self.command_receiver.next() => {
                    if let Some(command) = command {
                        self.handle_command(command).await;
                    } else {
                        break;
                    }
                },
            }
        }
    }

    async fn handle_swarm_event<E>(&mut self, swarm_event: SwarmEvent<ComposedEvent, E>) {
        match swarm_event {
            SwarmEvent::Behaviour(ComposedEvent::Kademlia(kademlia_event)) => {
                println!("Kademlia event: {:?}", kademlia_event);
            }
            SwarmEvent::NewListenAddr {
                listener_id,
                address,
            } => {
                println!("New listener {:?} with address {}", listener_id, address);
                self.inner.local_peer_addresses.lock().push(address);
            }
            _ => {}
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            // TODO
        }
    }
}

/// Implementation of a network node on Subspace Network.
#[derive(Debug, Clone)]
pub struct Node {
    inner: Arc<Inner>,
}

impl Node {
    /// Create a new network node/instance.
    pub async fn create(
        Config {
            keypair,
            listen_on,
            timeout,
            kademlia_config,
            bootstrap_nodes,
            yamux_config,
        }: Config,
    ) -> Result<(Self, NodeRunner), CreationError> {
        // libp2p uses blocking API, hence we need to create a blocking task.
        let create_swarm_fut = tokio::task::spawn_blocking(move || {
            let local_public_key = keypair.public();
            let local_peer_id = local_public_key.to_peer_id();

            let transport = {
                let transport = {
                    let tcp = TokioTcpConfig::new().nodelay(true);
                    let dns_tcp = TokioDnsConfig::system(tcp)?;
                    let ws = WsConfig::new(dns_tcp.clone());
                    dns_tcp.or_transport(ws)
                };

                let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
                    .into_authentic(&keypair)
                    .expect("Signing libp2p-noise static DH keypair failed.");

                transport
                    .upgrade(core::upgrade::Version::V1Lazy)
                    .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
                    .multiplex(yamux_config)
                    .timeout(timeout)
                    .boxed()
            };

            let kademlia = {
                let store = MemoryStore::new(local_peer_id);
                let mut kademlia = Kademlia::with_config(local_peer_id, store, kademlia_config);

                for (peer_id, address) in bootstrap_nodes {
                    kademlia.add_address(&peer_id, address);
                }

                kademlia
            };

            let behaviour = ComposedBehaviour {
                kademlia,
                identify: Identify::new(IdentifyConfig::new(
                    "/ipfs/0.1.0".to_string(),
                    local_public_key,
                )),
                ping: Ping::default(),
            };

            let mut swarm = Swarm::new(transport, behaviour, local_peer_id);

            for addr in listen_on {
                swarm.listen_on(addr)?;
            }

            Ok::<_, CreationError>(swarm)
        });

        let swarm = create_swarm_fut.await.unwrap()?;

        let (command_sender, command_receiver) = mpsc::channel(1);

        let inner = Arc::new(Inner {
            local_peer_id: *swarm.local_peer_id(),
            local_peer_addresses: Mutex::default(),
            command_sender,
        });

        let node = Self {
            inner: Arc::clone(&inner),
        };
        let node_runner = NodeRunner {
            command_receiver,
            swarm,
            inner,
        };

        Ok((node, node_runner))
    }

    pub fn id(&self) -> PeerId {
        self.inner.local_peer_id
    }

    pub fn addresses(&self) -> Vec<Multiaddr> {
        self.inner.local_peer_addresses.lock().clone()
    }
}

// Stuff for Kademlia
use libp2p::kad::{record::store::MemoryStore, Kademlia, KademliaEvent};

// Stuff for defining composed behaviour
use libp2p::NetworkBehaviour;

// Stuff needed to create the swarm
use libp2p::core::{upgrade, Transport};
use libp2p::identity;
use libp2p::mplex;
use libp2p::noise::{Keypair, NoiseConfig, X25519Spec};
use libp2p::swarm::SwarmBuilder;
use libp2p::tcp::TokioTcpConfig;
use libp2p::{PeerId, Swarm};

// Stuff needed to set up channels between Client API task and EventLoop task.
use tokio::sync::mpsc::{channel, Receiver, Sender};

// The Client API which the end-user is supposed to interact with.
pub mod client;
// Core libp2p activities like defining network behaviour and events, bootstrap-ing,
// creating of swarm and such...
mod core;
// EventLoop which actually processes libp2p SwarmEvents. The Client API interacts with the
// EventLoop to transfer and receieve data.
mod eventloop;

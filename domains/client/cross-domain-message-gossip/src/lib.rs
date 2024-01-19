#![warn(rust_2018_idioms)]

mod gossip_worker;
mod message_listener;

pub use gossip_worker::{
    xdm_gossip_peers_set_config, ChainTxPoolMsg, ChainTxPoolSink, GossipWorker,
    GossipWorkerBuilder, Message,
};
pub use message_listener::start_cross_chain_message_listener;

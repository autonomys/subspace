#![warn(rust_2018_idioms)]

mod aux_schema;
mod gossip_worker;
mod message_listener;

pub use gossip_worker::{
    xdm_gossip_peers_set_config, ChainMsg, ChainSink, GossipWorker, GossipWorkerBuilder, Message,
    MessageData,
};
pub use message_listener::start_cross_chain_message_listener;

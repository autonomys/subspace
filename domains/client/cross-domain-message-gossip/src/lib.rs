#![feature(let_chains)]
#![warn(rust_2018_idioms)]

mod aux_schema;
mod gossip_worker;
mod message_listener;

pub use aux_schema::{get_channel_state, set_channel_state, ChannelDetail};
pub use gossip_worker::{
    xdm_gossip_peers_set_config, ChainMsg, ChainSink, ChannelUpdate, GossipWorker,
    GossipWorkerBuilder, Message, MessageData,
};
pub use message_listener::start_cross_chain_message_listener;

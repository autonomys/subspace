#![feature(let_chains)]
#![warn(rust_2018_idioms)]

mod aux_schema;
mod gossip_worker;
mod message_listener;

pub use aux_schema::{
    BlockId, ChannelDetail, get_channel_state, get_xdm_processed_block_number, set_channel_state,
    set_xdm_message_processed_at,
};
pub use gossip_worker::{
    ChainMsg, ChainSink, ChannelUpdate, GossipWorker, GossipWorkerBuilder, Message, MessageData,
    xdm_gossip_peers_set_config,
};
pub use message_listener::{can_allow_xdm_submission, start_cross_chain_message_listener};

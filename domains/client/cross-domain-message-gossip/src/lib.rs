#![warn(rust_2018_idioms)]

mod gossip_worker;
mod message_listener;

pub use message_listener::start_domain_message_listener;

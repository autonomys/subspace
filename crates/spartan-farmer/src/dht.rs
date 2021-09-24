// The Client API which the end-user is supposed to interact with.
mod client;
// Core libp2p activities like defining network behaviour and events, bootstrap-ing,
// creating of swarm and such...
mod core;
// EventLoop which actually processes libp2p SwarmEvents. The Client API interacts with the
// EventLoop to transfer and receieve data.
mod eventloop;

// DHT related tests.
#[cfg(test)]
mod test;

pub(crate) use client::{create_connection, ClientConfig};

use crate::behavior::BehaviorConfig;
use crate::network::{GenericRequest, Network, NetworkConfig, SendRequestError};
use futures::channel::oneshot;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::OutboundFailure;
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use std::assert_matches::assert_matches;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

const MAX_REQUEST_SIZE: u64 = 1024;
const MAX_RESPONSE_SIZE: u64 = 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_STREAMS: usize = 1024;
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

impl GenericRequest for String {
    type Response = String;
}

#[derive(Debug, Encode, Decode)]
enum Requests {
    S(String),
}

impl From<String> for Requests {
    fn from(value: String) -> Self {
        Self::S(value)
    }
}

#[derive(Debug, Encode, Decode)]
enum Responses {
    S(String),
}

impl TryFrom<Responses> for String {
    type Error = Box<dyn Error>;

    fn try_from(Responses::S(s): Responses) -> Result<Self, Self::Error> {
        Ok(s)
    }
}

#[derive(Debug, Encode, Decode)]
enum BadRequests {
    #[codec(index = 1)]
    S(String),
}

impl From<String> for BadRequests {
    fn from(value: String) -> Self {
        Self::S(value)
    }
}

#[derive(Debug, Encode, Decode)]
enum BadResponses {
    #[codec(index = 1)]
    S(String),
}

impl TryFrom<BadResponses> for String {
    type Error = Box<dyn Error>;

    fn try_from(BadResponses::S(s): BadResponses) -> Result<Self, Self::Error> {
        Ok(s)
    }
}

fn typical_behavior_config() -> BehaviorConfig {
    BehaviorConfig {
        request_response_protocol: "/request_response_protocol",
        max_request_size: MAX_REQUEST_SIZE,
        max_response_size: MAX_RESPONSE_SIZE,
        request_timeout: REQUEST_TIMEOUT,
        max_concurrent_streams: MAX_CONCURRENT_STREAMS,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn basic() {
    let (peer_1, mut peer_1_worker) = Network::<Requests, Responses>::new(NetworkConfig {
        bootstrap_nodes: vec![],
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        keypair: Keypair::generate_ed25519(),
        network_key: vec![],
        behavior_config: typical_behavior_config(),
        idle_connection_timeout: IDLE_CONNECTION_TIMEOUT,
        request_handler: Box::new(|Requests::S(request)| {
            Box::pin(async move { Responses::S(format!("response: {request}")) })
        }),
        metrics: None,
    })
    .unwrap();

    let peer_1_addr = {
        let (peer_1_address_sender, peer_1_address_receiver) = oneshot::channel();
        let _on_new_listener_handler = peer_1.on_new_listener(Arc::new({
            let peer_1_address_sender = Mutex::new(Some(peer_1_address_sender));

            move |address| {
                if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                    if let Some(peer_1_address_sender) = peer_1_address_sender.lock().take() {
                        peer_1_address_sender.send(address.clone()).unwrap();
                    }
                }
            }
        }));

        tokio::spawn(async move {
            peer_1_worker.run().await;
        });

        // Wait for first peer to know its address
        let mut peer_1_addr = peer_1_address_receiver.await.unwrap();
        peer_1_addr.push(Protocol::P2p(peer_1.id()));
        peer_1_addr
    };

    let (peer_2, mut peer_2_worker) = Network::<Requests, Responses>::new(NetworkConfig {
        bootstrap_nodes: vec![peer_1_addr.clone()],
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        keypair: Keypair::generate_ed25519(),
        network_key: vec![],
        behavior_config: typical_behavior_config(),
        idle_connection_timeout: IDLE_CONNECTION_TIMEOUT,
        request_handler: Box::new(|Requests::S(request)| {
            Box::pin(async move { Responses::S(format!("response: {request}")) })
        }),
        metrics: None,
    })
    .unwrap();

    let peer_2_addr = {
        let (connected_sender, connected_receiver) = oneshot::channel::<()>();
        let connected_sender = Mutex::new(Some(connected_sender));
        let _connected_handler_id = peer_2.on_connected_peer(Arc::new({
            move |_| {
                connected_sender.lock().take();
            }
        }));

        let (peer_2_address_sender, peer_2_address_receiver) = oneshot::channel();
        let _on_new_listener_handler = peer_2.on_new_listener(Arc::new({
            let peer_2_address_sender = Mutex::new(Some(peer_2_address_sender));

            move |address| {
                if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                    if let Some(peer_2_address_sender) = peer_2_address_sender.lock().take() {
                        peer_2_address_sender.send(address.clone()).unwrap();
                    }
                }
            }
        }));

        tokio::spawn(async move {
            peer_2_worker.run().await;
        });

        // Wait for second peer to know its address
        let mut peer_2_addr = peer_2_address_receiver.await.unwrap();
        peer_2_addr.push(Protocol::P2p(peer_2.id()));

        // Wait for connection to bootstrap node
        let _ = connected_receiver.await;

        // Basic request to bootstrap node succeeds
        let response = peer_2
            .request(peer_1.id(), vec![], "hello".to_string())
            .await
            .unwrap();
        assert_eq!(response, "response: hello");

        peer_2_addr
    };

    {
        let (peer_3, mut peer_3_worker) = Network::<Requests, Responses>::new(NetworkConfig {
            bootstrap_nodes: vec![peer_1_addr.clone()],
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            keypair: Keypair::generate_ed25519(),
            network_key: vec![0, 1, 2, 3],
            behavior_config: typical_behavior_config(),
            idle_connection_timeout: IDLE_CONNECTION_TIMEOUT,
            request_handler: Box::new(|_| unreachable!()),
            metrics: None,
        })
        .unwrap();

        tokio::spawn(async move {
            peer_3_worker.run().await;
        });

        // Network key mismatch results in dial failure
        let response = peer_3
            .request(peer_1.id(), vec![peer_1_addr.clone()], "hello".to_string())
            .await;
        assert_matches!(
            response,
            Err(SendRequestError::ProtocolFailure(
                OutboundFailure::DialFailure
            ))
        );
    }

    {
        let idle_connection_timeout = Duration::from_millis(10);

        let (peer_4, mut peer_4_worker) = Network::<Requests, Responses>::new(NetworkConfig {
            bootstrap_nodes: vec![peer_1_addr.clone()],
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            keypair: Keypair::generate_ed25519(),
            network_key: vec![],
            behavior_config: typical_behavior_config(),
            idle_connection_timeout,
            request_handler: Box::new(|_| unreachable!()),
            metrics: None,
        })
        .unwrap();

        tokio::spawn(async move {
            peer_4_worker.run().await;
        });

        let (disconnected_sender, disconnected_receiver) = oneshot::channel::<()>();
        let disconnected_sender = Mutex::new(Some(disconnected_sender));
        let mut disconnected_receiver = Some(disconnected_receiver);
        let _disconnected_handler_id = peer_4.on_disconnected_peer(Arc::new({
            move |_| {
                disconnected_sender.lock().take();
            }
        }));

        // Try twice with an interval larger than idle connection timeout to make sure it reconnects
        // successfully
        for _ in 0..2 {
            let response = peer_4
                .request(peer_1.id(), vec![peer_1_addr.clone()], "hello".to_string())
                .await
                .unwrap();

            assert_eq!(response, "response: hello");

            if let Some(disconnected_receiver) = disconnected_receiver.take() {
                let _ = disconnected_receiver.await;
            }
        }
    }

    {
        let (peer_5, mut peer_5_worker) = Network::<Requests, Responses>::new(NetworkConfig {
            bootstrap_nodes: vec![peer_1_addr.clone()],
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            keypair: Keypair::generate_ed25519(),
            network_key: vec![],
            behavior_config: typical_behavior_config(),
            idle_connection_timeout: IDLE_CONNECTION_TIMEOUT,
            request_handler: Box::new(|_| unreachable!()),
            metrics: None,
        })
        .unwrap();

        tokio::spawn(async move {
            peer_5_worker.run().await;
        });

        // Initially not connected to the second peer
        {
            let response = peer_5
                .request(peer_2.id(), vec![], "hello".to_string())
                .await;
            assert_matches!(
                response,
                Err(SendRequestError::ProtocolFailure(
                    OutboundFailure::DialFailure
                ))
            );
        }

        // With explicit address connection succeeds
        {
            let response = peer_5
                .request(peer_2.id(), vec![peer_2_addr.clone()], "hello".to_string())
                .await
                .unwrap();
            assert_eq!(response, "response: hello");
        }
        // And also succeeds without address shortly after due to already established connection
        {
            let response = peer_5
                .request(peer_2.id(), vec![], "hello".to_string())
                .await
                .unwrap();
            assert_eq!(response, "response: hello");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_requests_responses() {
    let (peer_1, mut peer_1_worker) = Network::<Requests, Responses>::new(NetworkConfig {
        bootstrap_nodes: vec![],
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        keypair: Keypair::generate_ed25519(),
        network_key: vec![],
        behavior_config: typical_behavior_config(),
        idle_connection_timeout: IDLE_CONNECTION_TIMEOUT,
        request_handler: Box::new(|Requests::S(request)| {
            Box::pin(async move { Responses::S(format!("response: {request}")) })
        }),
        metrics: None,
    })
    .unwrap();

    let peer_1_addr = {
        let (peer_1_address_sender, peer_1_address_receiver) = oneshot::channel();
        let _on_new_listener_handler = peer_1.on_new_listener(Arc::new({
            let peer_1_address_sender = Mutex::new(Some(peer_1_address_sender));

            move |address| {
                if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                    if let Some(peer_1_address_sender) = peer_1_address_sender.lock().take() {
                        peer_1_address_sender.send(address.clone()).unwrap();
                    }
                }
            }
        }));

        tokio::spawn(async move {
            peer_1_worker.run().await;
        });

        // Wait for first peer to know its address
        let mut peer_1_addr = peer_1_address_receiver.await.unwrap();
        peer_1_addr.push(Protocol::P2p(peer_1.id()));
        peer_1_addr
    };

    {
        let (peer_2, mut peer_2_worker) = Network::<BadRequests, Responses>::new(NetworkConfig {
            bootstrap_nodes: vec![peer_1_addr.clone()],
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            keypair: Keypair::generate_ed25519(),
            network_key: vec![],
            behavior_config: typical_behavior_config(),
            idle_connection_timeout: IDLE_CONNECTION_TIMEOUT,
            request_handler: Box::new(|_| unreachable!()),
            metrics: None,
        })
        .unwrap();

        tokio::spawn(async move {
            peer_2_worker.run().await;
        });

        // Bad request results in error on the other end and response fails as well
        let response = peer_2
            .request(peer_1.id(), vec![peer_1_addr.clone()], "hello".to_string())
            .await;
        assert_matches!(response, Err(SendRequestError::IncorrectResponseFormat(_)));
    }

    {
        let (peer_3, mut peer_3_worker) = Network::<Requests, BadResponses>::new(NetworkConfig {
            bootstrap_nodes: vec![peer_1_addr.clone()],
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            keypair: Keypair::generate_ed25519(),
            network_key: vec![],
            behavior_config: typical_behavior_config(),
            idle_connection_timeout: IDLE_CONNECTION_TIMEOUT,
            request_handler: Box::new(|_| unreachable!()),
            metrics: None,
        })
        .unwrap();

        tokio::spawn(async move {
            peer_3_worker.run().await;
        });

        // Can't decode unexpectedly encoded response
        let response = peer_3
            .request(peer_1.id(), vec![peer_1_addr.clone()], "hello".to_string())
            .await;
        assert_matches!(response, Err(SendRequestError::IncorrectResponseFormat(_)));
    }
}

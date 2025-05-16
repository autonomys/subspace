use crate::protocols::request_response::request_response_factory::{
    Event, IfDisconnected, IncomingRequest, OutboundFailure, OutgoingResponse, ProtocolConfig,
    RequestFailure, RequestHandler, RequestResponseFactoryBehaviour,
};
use async_trait::async_trait;
use futures::StreamExt;
use futures::channel::{mpsc, oneshot};
use futures::stream::FuturesUnordered;
use libp2p::core::transport::{MemoryTransport, Transport};
use libp2p::core::upgrade;
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{SwarmBuilder, noise};
use libp2p_swarm_test::SwarmExt;
use std::time::Duration;
use std::{io, iter};

#[derive(Clone)]
struct MockRunner(ProtocolConfig);

#[async_trait]
impl RequestHandler for MockRunner {
    async fn run(&mut self) {}

    fn protocol_config(&self) -> ProtocolConfig {
        self.0.clone()
    }

    fn protocol_name(&self) -> &'static str {
        self.0.name
    }

    fn clone_box(&self) -> Box<dyn RequestHandler> {
        Box::new(Self(self.0.clone()))
    }
}

async fn build_swarm(
    list: impl Iterator<Item = ProtocolConfig>,
) -> Swarm<RequestResponseFactoryBehaviour> {
    let configs = list
        .into_iter()
        .map(|config| Box::new(MockRunner(config)) as Box<dyn RequestHandler>)
        .collect::<Vec<_>>();
    let behaviour = RequestResponseFactoryBehaviour::new(configs, 100).unwrap();

    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_other_transport(|keypair| {
            MemoryTransport::default()
                .or_transport(libp2p::tcp::tokio::Transport::default())
                .upgrade(upgrade::Version::V1)
                .authenticate(noise::Config::new(keypair).unwrap())
                .multiplex(libp2p::yamux::Config::default())
                .boxed()
        })
        .unwrap()
        .with_behaviour(move |_keypair| behaviour)
        .unwrap()
        // Make sure connections stay alive
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(10)))
        .build();

    swarm.listen().with_memory_addr_external().await;

    swarm
}

#[tokio::test(flavor = "multi_thread")]
async fn basic_request_response_works() {
    let protocol_name = "/test/req-resp/1";

    // Build swarms whose behaviour is `RequestResponsesBehaviour`.
    let mut swarms = (0..2)
        .map(|_| async {
            let (tx, mut rx) = mpsc::channel::<IncomingRequest>(64);

            tokio::spawn(async move {
                while let Some(rq) = rx.next().await {
                    assert_eq!(rq.payload, b"this is a request");
                    let _ = rq.pending_response.send(OutgoingResponse {
                        result: Ok(b"this is a response".to_vec()),
                        sent_feedback: None,
                    });
                }
            });

            let protocol_config = ProtocolConfig {
                name: protocol_name,
                max_request_size: 1024,
                max_response_size: 1024 * 1024,
                request_timeout: Duration::from_secs(30),
                inbound_queue: Some(tx),
            };

            build_swarm(iter::once(protocol_config)).await
        })
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;

    let mut swarm_0 = swarms.remove(0);
    let mut swarm_1 = swarms.remove(0);

    // Ask `swarm_0` to dial `swarm_1`. There isn't any discovery mechanism in place in this test, so they wouldn't
    // connect to each other.
    swarm_0.connect(&mut swarm_1).await;

    let peer_id_0 = *swarm_0.local_peer_id();

    // Running `swarm_0` in the background.
    tokio::spawn(async move {
        loop {
            if let SwarmEvent::Behaviour(Event::InboundRequest { result, .. }) =
                swarm_0.select_next_some().await
            {
                result.unwrap();
            }
        }
    });

    let (sender, receiver) = oneshot::channel();
    // Send request
    swarm_1.behaviour_mut().send_request(
        &peer_id_0,
        protocol_name,
        b"this is a request".to_vec(),
        sender,
        IfDisconnected::ImmediateError,
        Vec::new(),
    );
    // Wait for request to finish
    loop {
        if let SwarmEvent::Behaviour(Event::RequestFinished { result, .. }) =
            swarm_1.select_next_some().await
        {
            result.unwrap();
            break;
        }
    }
    // Expect response
    assert_eq!(receiver.await.unwrap().unwrap(), b"this is a response");
}

#[tokio::test(flavor = "multi_thread")]
async fn max_response_size_exceeded() {
    let protocol_name = "/test/req-resp/1";

    // Build swarms whose behaviour is `RequestResponsesBehaviour`.
    let mut swarms = (0..2)
        .map(|_| async {
            let (tx, mut rx) = mpsc::channel::<IncomingRequest>(64);

            tokio::spawn(async move {
                while let Some(rq) = rx.next().await {
                    assert_eq!(rq.payload, b"this is a request");
                    let _ = rq.pending_response.send(OutgoingResponse {
                        result: Ok(b"this response exceeds the limit".to_vec()),
                        sent_feedback: None,
                    });
                }
            });

            let protocol_config = ProtocolConfig {
                name: protocol_name,
                max_request_size: 1024,
                max_response_size: 8, // <-- important for the test
                request_timeout: Duration::from_secs(30),
                inbound_queue: Some(tx),
            };

            build_swarm(iter::once(protocol_config)).await
        })
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;

    let mut swarm_0 = swarms.remove(0);
    let mut swarm_1 = swarms.remove(0);

    // Ask `swarm_0` to dial `swarm_1`. There isn't any discovery mechanism in place in this test, so they wouldn't
    // connect to each other.
    swarm_0.connect(&mut swarm_1).await;

    let peer_id_0 = *swarm_0.local_peer_id();

    // Running `swarm_0` in the background until a `InboundRequest` event happens, which is a hint about the test
    // having ended.
    tokio::spawn(async move {
        loop {
            if let SwarmEvent::Behaviour(Event::InboundRequest { result, .. }) =
                swarm_0.select_next_some().await
            {
                assert!(result.is_ok());
            }
        }
    });

    // Run the remaining swarm.
    let (sender, receiver) = oneshot::channel();
    // Send request
    swarm_1.behaviour_mut().send_request(
        &peer_id_0,
        protocol_name,
        b"this is a request".to_vec(),
        sender,
        IfDisconnected::ImmediateError,
        Vec::new(),
    );
    // Wait for request to finish
    loop {
        if let SwarmEvent::Behaviour(Event::RequestFinished { result, .. }) =
            swarm_1.select_next_some().await
        {
            assert!(result.is_err());
            break;
        }
    }
    // Expect response
    match receiver.await.unwrap().unwrap_err() {
        RequestFailure::Network(OutboundFailure::Io(error)) => {
            if error.kind() != io::ErrorKind::InvalidInput
                || error.to_string() != "Response size exceeds limit: 31 > 8"
            {
                panic!("Unexpected I/O error: {error}")
            }
        }
        error => panic!("Unexpected error: {error}"),
    }
}

/// A [`RequestId`] is a unique identifier among either all inbound or all outbound requests for
/// a single [`RequestResponse`] behaviour. It is not guaranteed to be unique across multiple
/// [`RequestResponse`] behaviours. Thus when handling [`RequestId`] in the context of multiple
/// [`RequestResponse`] behaviours, one needs to couple the protocol name with the [`RequestId`]
/// to get a unique request identifier.
///
/// This test ensures that two requests on different protocols can be handled concurrently
/// without a [`RequestId`] collision.
///
/// See [`ProtocolRequestId`] for additional information.
#[tokio::test(flavor = "multi_thread")]
async fn request_id_collision() {
    let protocol_name_1 = "/test/req-resp-1/1";
    let protocol_name_2 = "/test/req-resp-2/1";

    let mut swarm_1 = {
        let protocol_configs = vec![
            ProtocolConfig {
                name: protocol_name_1,
                max_request_size: 1024,
                max_response_size: 1024 * 1024,
                request_timeout: Duration::from_secs(30),
                inbound_queue: None,
            },
            ProtocolConfig {
                name: protocol_name_2,
                max_request_size: 1024,
                max_response_size: 1024 * 1024,
                request_timeout: Duration::from_secs(30),
                inbound_queue: None,
            },
        ];

        build_swarm(protocol_configs.into_iter()).await
    };

    let (mut swarm_2, mut swarm_2_handler_1, mut swarm_2_handler_2) = {
        let (tx_1, rx_1) = mpsc::channel(64);
        let (tx_2, rx_2) = mpsc::channel(64);

        let protocol_configs = vec![
            ProtocolConfig {
                name: protocol_name_1,
                max_request_size: 1024,
                max_response_size: 1024 * 1024,
                request_timeout: Duration::from_secs(30),
                inbound_queue: Some(tx_1),
            },
            ProtocolConfig {
                name: protocol_name_2,
                max_request_size: 1024,
                max_response_size: 1024 * 1024,
                request_timeout: Duration::from_secs(30),
                inbound_queue: Some(tx_2),
            },
        ];

        let swarm = build_swarm(protocol_configs.into_iter()).await;

        (swarm, rx_1, rx_2)
    };

    // Ask swarm 1 to dial swarm 2. There isn't any discovery mechanism in place in this test,
    // so they wouldn't connect to each other.
    swarm_1.connect(&mut swarm_2).await;

    let peer_id_2 = *swarm_2.local_peer_id();

    // Run swarm 2 in the background, receiving two requests.
    tokio::spawn(async move {
        loop {
            if let SwarmEvent::Behaviour(Event::InboundRequest { result, .. }) =
                swarm_2.select_next_some().await
            {
                result.unwrap();
            }
        }
    });

    // Handle both requests sent by swarm 1 to swarm 2 in the background.
    //
    // Make sure both requests overlap, by answering the first only after receiving the
    // second.
    tokio::spawn(async move {
        let protocol_1_request = swarm_2_handler_1.next().await;
        let protocol_2_request = swarm_2_handler_2.next().await;

        protocol_1_request
            .unwrap()
            .pending_response
            .send(OutgoingResponse {
                result: Ok(b"this is a response 1".to_vec()),
                sent_feedback: None,
            })
            .unwrap();
        protocol_2_request
            .unwrap()
            .pending_response
            .send(OutgoingResponse {
                result: Ok(b"this is a response 2".to_vec()),
                sent_feedback: None,
            })
            .unwrap();
    });

    // Have swarm 1 send two requests to swarm 2 and await responses.
    let mut num_responses = 0;

    let (sender_1, receiver_1) = oneshot::channel();
    let (sender_2, receiver_2) = oneshot::channel();
    // Send two requests
    swarm_1.behaviour_mut().send_request(
        &peer_id_2,
        protocol_name_1,
        b"this is a request 1".to_vec(),
        sender_1,
        IfDisconnected::ImmediateError,
        Vec::new(),
    );
    swarm_1.behaviour_mut().send_request(
        &peer_id_2,
        protocol_name_2,
        b"this is a request 2".to_vec(),
        sender_2,
        IfDisconnected::ImmediateError,
        Vec::new(),
    );
    // Expect both to finish
    loop {
        if let SwarmEvent::Behaviour(Event::RequestFinished { result, .. }) =
            swarm_1.select_next_some().await
        {
            num_responses += 1;
            result.unwrap();
            if num_responses == 2 {
                break;
            }
        }
    }
    // Expect two responses
    assert_eq!(receiver_1.await.unwrap().unwrap(), b"this is a response 1");
    assert_eq!(receiver_2.await.unwrap().unwrap(), b"this is a response 2");
}

use crate::request_responses::{
    Event, IfDisconnected, IncomingRequest, OutboundFailure, OutgoingResponse, ProtocolConfig,
    RequestFailure, RequestResponsesBehaviour,
};
use futures::channel::{mpsc, oneshot};
use futures::executor::LocalPool;
use futures::task::Spawn;
use futures::{FutureExt, StreamExt};
use libp2p::core::transport::{MemoryTransport, Transport};
use libp2p::core::upgrade;
use libp2p::identity::Keypair;
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{noise, Multiaddr};
use std::iter;
use std::time::Duration;

fn build_swarm(
    list: impl Iterator<Item = ProtocolConfig>,
) -> (Swarm<RequestResponsesBehaviour>, Multiaddr) {
    let keypair = Keypair::generate_ed25519();

    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&keypair)
        .unwrap();

    let transport = MemoryTransport
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(libp2p::yamux::YamuxConfig::default())
        .boxed();

    let behaviour = RequestResponsesBehaviour::new(list).unwrap();

    let mut swarm = Swarm::new(transport, behaviour, keypair.public().to_peer_id());
    let listen_addr: Multiaddr = format!("/memory/{}", rand::random::<u64>())
        .parse()
        .unwrap();

    swarm.listen_on(listen_addr.clone()).unwrap();
    (swarm, listen_addr)
}

#[test]
fn basic_request_response_works() {
    let protocol_name = "/test/req-resp/1";
    let mut pool = LocalPool::new();

    // Build swarms whose behaviour is `RequestResponsesBehaviour`.
    let mut swarms = (0..2)
        .map(|_| {
            let (tx, mut rx) = mpsc::channel::<IncomingRequest>(64);

            pool.spawner()
                .spawn_obj(
                    async move {
                        while let Some(rq) = rx.next().await {
                            let (fb_tx, fb_rx) = oneshot::channel();
                            assert_eq!(rq.payload, b"this is a request");
                            let _ = rq.pending_response.send(OutgoingResponse {
                                result: Ok(b"this is a response".to_vec()),
                                sent_feedback: Some(fb_tx),
                            });
                            fb_rx.await.unwrap();
                        }
                    }
                    .boxed()
                    .into(),
                )
                .unwrap();

            let protocol_config = ProtocolConfig {
                name: From::from(protocol_name),
                max_request_size: 1024,
                max_response_size: 1024 * 1024,
                request_timeout: Duration::from_secs(30),
                inbound_queue: Some(tx),
            };

            build_swarm(iter::once(protocol_config))
        })
        .collect::<Vec<_>>();

    // Ask `swarm[0]` to dial `swarm[1]`. There isn't any discovery mechanism in place in
    // this test, so they wouldn't connect to each other.
    {
        let dial_addr = swarms[1].1.clone();
        Swarm::dial(&mut swarms[0].0, dial_addr).unwrap();
    }

    let (mut swarm, _) = swarms.remove(0);

    // Running `swarm[0]` in the background.
    pool.spawner()
        .spawn_obj({
            async move {
                loop {
                    if let SwarmEvent::Behaviour(Event::InboundRequest { result, .. }) =
                        swarm.select_next_some().await
                    {
                        result.unwrap();
                    }
                }
            }
            .boxed()
            .into()
        })
        .unwrap();

    // Remove and run the remaining swarm.
    let (mut swarm, _) = swarms.remove(0);

    pool.run_until(async move {
        let mut response_receiver = None;

        loop {
            match swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    let (sender, receiver) = oneshot::channel();
                    swarm.behaviour_mut().send_request(
                        &peer_id,
                        protocol_name,
                        b"this is a request".to_vec(),
                        sender,
                        IfDisconnected::ImmediateError,
                    );
                    assert!(response_receiver.is_none());
                    response_receiver = Some(receiver);
                }
                SwarmEvent::Behaviour(Event::RequestFinished { result, .. }) => {
                    result.unwrap();
                    break;
                }
                _ => {}
            }
        }

        assert_eq!(
            response_receiver.unwrap().await.unwrap().unwrap(),
            b"this is a response"
        );
    });
}

#[test]
fn max_response_size_exceeded() {
    let protocol_name = "/test/req-resp/1";
    let mut pool = LocalPool::new();

    // Build swarms whose behaviour is `RequestResponsesBehaviour`.
    let mut swarms = (0..2)
        .map(|_| {
            let (tx, mut rx) = mpsc::channel::<IncomingRequest>(64);

            pool.spawner()
                .spawn_obj(
                    async move {
                        while let Some(rq) = rx.next().await {
                            assert_eq!(rq.payload, b"this is a request");
                            let _ = rq.pending_response.send(OutgoingResponse {
                                result: Ok(b"this response exceeds the limit".to_vec()),
                                sent_feedback: None,
                            });
                        }
                    }
                    .boxed()
                    .into(),
                )
                .unwrap();

            let protocol_config = ProtocolConfig {
                name: From::from(protocol_name),
                max_request_size: 1024,
                max_response_size: 8, // <-- important for the test
                request_timeout: Duration::from_secs(30),
                inbound_queue: Some(tx),
            };

            build_swarm(iter::once(protocol_config))
        })
        .collect::<Vec<_>>();

    // Ask `swarm[0]` to dial `swarm[1]`. There isn't any discovery mechanism in place in
    // this test, so they wouldn't connect to each other.
    {
        let dial_addr = swarms[1].1.clone();
        Swarm::dial(&mut swarms[0].0, dial_addr).unwrap();
    }

    // Running `swarm[0]` in the background until a `InboundRequest` event happens,
    // which is a hint about the test having ended.
    let (mut swarm, _) = swarms.remove(0);

    pool.spawner()
        .spawn_obj({
            async move {
                loop {
                    if let SwarmEvent::Behaviour(Event::InboundRequest { result, .. }) =
                        swarm.select_next_some().await
                    {
                        assert!(result.is_ok());
                        break;
                    }
                }
            }
            .boxed()
            .into()
        })
        .unwrap();

    // Remove and run the remaining swarm.
    let (mut swarm, _) = swarms.remove(0);

    pool.run_until(async move {
        let mut response_receiver = None;

        loop {
            match swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    let (sender, receiver) = oneshot::channel();
                    swarm.behaviour_mut().send_request(
                        &peer_id,
                        protocol_name,
                        b"this is a request".to_vec(),
                        sender,
                        IfDisconnected::ImmediateError,
                    );
                    assert!(response_receiver.is_none());
                    response_receiver = Some(receiver);
                }
                SwarmEvent::Behaviour(Event::RequestFinished { result, .. }) => {
                    assert!(result.is_err());
                    break;
                }
                _ => {}
            }
        }

        match response_receiver.unwrap().await.unwrap().unwrap_err() {
            RequestFailure::Network(OutboundFailure::ConnectionClosed) => {}
            _ => panic!(),
        }
    });
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
#[test]
fn request_id_collision() {
    let protocol_name_1 = "/test/req-resp-1/1";
    let protocol_name_2 = "/test/req-resp-2/1";
    let mut pool = LocalPool::new();

    let mut swarm_1 = {
        let protocol_configs = vec![
            ProtocolConfig {
                name: From::from(protocol_name_1),
                max_request_size: 1024,
                max_response_size: 1024 * 1024,
                request_timeout: Duration::from_secs(30),
                inbound_queue: None,
            },
            ProtocolConfig {
                name: From::from(protocol_name_2),
                max_request_size: 1024,
                max_response_size: 1024 * 1024,
                request_timeout: Duration::from_secs(30),
                inbound_queue: None,
            },
        ];

        build_swarm(protocol_configs.into_iter()).0
    };

    let (mut swarm_2, mut swarm_2_handler_1, mut swarm_2_handler_2, listen_add_2) = {
        let (tx_1, rx_1) = mpsc::channel(64);
        let (tx_2, rx_2) = mpsc::channel(64);

        let protocol_configs = vec![
            ProtocolConfig {
                name: From::from(protocol_name_1),
                max_request_size: 1024,
                max_response_size: 1024 * 1024,
                request_timeout: Duration::from_secs(30),
                inbound_queue: Some(tx_1),
            },
            ProtocolConfig {
                name: From::from(protocol_name_2),
                max_request_size: 1024,
                max_response_size: 1024 * 1024,
                request_timeout: Duration::from_secs(30),
                inbound_queue: Some(tx_2),
            },
        ];

        let (swarm, listen_addr) = build_swarm(protocol_configs.into_iter());

        (swarm, rx_1, rx_2, listen_addr)
    };

    // Ask swarm 1 to dial swarm 2. There isn't any discovery mechanism in place in this test,
    // so they wouldn't connect to each other.
    swarm_1.dial(listen_add_2).unwrap();

    // Run swarm 2 in the background, receiving two requests.
    pool.spawner()
        .spawn_obj(
            async move {
                loop {
                    if let SwarmEvent::Behaviour(Event::InboundRequest { result, .. }) =
                        swarm_2.select_next_some().await
                    {
                        result.unwrap();
                    }
                }
            }
            .boxed()
            .into(),
        )
        .unwrap();

    // Handle both requests sent by swarm 1 to swarm 2 in the background.
    //
    // Make sure both requests overlap, by answering the first only after receiving the
    // second.
    pool.spawner()
        .spawn_obj(
            async move {
                let protocol_1_request = swarm_2_handler_1.next().await;
                let protocol_2_request = swarm_2_handler_2.next().await;

                protocol_1_request
                    .unwrap()
                    .pending_response
                    .send(OutgoingResponse {
                        result: Ok(b"this is a response".to_vec()),
                        sent_feedback: None,
                    })
                    .unwrap();
                protocol_2_request
                    .unwrap()
                    .pending_response
                    .send(OutgoingResponse {
                        result: Ok(b"this is a response".to_vec()),
                        sent_feedback: None,
                    })
                    .unwrap();
            }
            .boxed()
            .into(),
        )
        .unwrap();

    // Have swarm 1 send two requests to swarm 2 and await responses.
    pool.run_until(async move {
        let mut response_receivers = None;
        let mut num_responses = 0;

        loop {
            match swarm_1.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    let (sender_1, receiver_1) = oneshot::channel();
                    let (sender_2, receiver_2) = oneshot::channel();
                    swarm_1.behaviour_mut().send_request(
                        &peer_id,
                        protocol_name_1,
                        b"this is a request".to_vec(),
                        sender_1,
                        IfDisconnected::ImmediateError,
                    );
                    swarm_1.behaviour_mut().send_request(
                        &peer_id,
                        protocol_name_2,
                        b"this is a request".to_vec(),
                        sender_2,
                        IfDisconnected::ImmediateError,
                    );
                    assert!(response_receivers.is_none());
                    response_receivers = Some((receiver_1, receiver_2));
                }
                SwarmEvent::Behaviour(Event::RequestFinished { result, .. }) => {
                    num_responses += 1;
                    result.unwrap();
                    if num_responses == 2 {
                        break;
                    }
                }
                _ => {}
            }
        }
        let (response_receiver_1, response_receiver_2) = response_receivers.unwrap();
        assert_eq!(
            response_receiver_1.await.unwrap().unwrap(),
            b"this is a response"
        );
        assert_eq!(
            response_receiver_2.await.unwrap().unwrap(),
            b"this is a response"
        );
    });
}

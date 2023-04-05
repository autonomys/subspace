// Copyright (C) 2019-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Collection of request-response protocols.
//!
//! The [`RequestResponse`] struct defined in this module provides support for zero or more
//! so-called "request-response" protocols.
//!
//! A request-response protocol works in the following way:
//!
//! - For every emitted request, a new substream is open and the protocol is negotiated. If the
//! remote supports the protocol, the size of the request is sent as a LEB128 number, followed
//! with the request itself. The remote then sends the size of the response as a LEB128 number,
//! followed with the response.
//!
//! - Requests have a certain time limit before they time out. This time includes the time it
//! takes to send/receive the request and response.
//!
//! - If provided, a ["requests processing"](ProtocolConfig::inbound_queue) channel
//! is used to handle incoming requests.

//! Original file commit: <https://github.com/paritytech/substrate/commit/c2fc4b3ca0d7a15cc3f9cb1e5f441d99ec8d6e0b>

#[cfg(test)]
mod tests;

use async_trait::async_trait;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use libp2p::core::{Multiaddr, PeerId};
use libp2p::request_response::{
    Behaviour as RequestResponse, Codec as RequestResponseCodec, Config as RequestResponseConfig,
    Event as RequestResponseEvent, Message as RequestResponseMessage, ProtocolSupport,
    ResponseChannel,
};
pub use libp2p::request_response::{InboundFailure, OutboundFailure, RequestId};
use libp2p::swarm::behaviour::{ConnectionClosed, DialFailure, FromSwarm, ListenFailure};
use libp2p::swarm::handler::multi::MultiHandler;
use libp2p::swarm::{
    ConnectionHandler, ConnectionId, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
    THandlerInEvent,
};
use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use std::{io, iter};
use tracing::{debug, error, warn};

const LOG_TARGET: &str = "request-response-protocols";

/// Defines a handler for the request-response protocol factory.
#[async_trait]
pub trait RequestHandler: Send {
    /// Runs the underlying protocol handler.
    async fn run(&mut self);

    /// Returns a config for the request-response protocol factory.
    fn protocol_config(&self) -> ProtocolConfig;

    /// Returns a protocol name.
    fn protocol_name(&self) -> &'static str;

    /// Clone boxed value.
    fn clone_box(&self) -> Box<dyn RequestHandler>;
}

impl Clone for Box<dyn RequestHandler> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// Configuration for a single request-response protocol.
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// Name of the protocol on the wire. Should be something like `/foo/bar`.
    pub name: &'static str,

    /// Maximum allowed size, in bytes, of a request.
    ///
    /// Any request larger than this value will be declined as a way to avoid allocating too
    /// much memory for it.
    pub max_request_size: u64,

    /// Maximum allowed size, in bytes, of a response.
    ///
    /// Any response larger than this value will be declined as a way to avoid allocating too
    /// much memory for it.
    pub max_response_size: u64,

    /// Duration after which emitted requests are considered timed out.
    ///
    /// If you expect the response to come back quickly, you should set this to a smaller duration.
    pub request_timeout: Duration,

    /// Channel on which the networking service will send incoming requests.
    ///
    /// Every time a peer sends a request to the local node using this protocol, the networking
    /// service will push an element on this channel. The receiving side of this channel then has
    /// to pull this element, process the request, and send back the response to send back to the
    /// peer.
    ///
    /// The size of the channel has to be carefully chosen. If the channel is full, the networking
    /// service will discard the incoming request send back an error to the peer. Consequently,
    /// the channel being full is an indicator that the node is overloaded.
    ///
    /// You can typically set the size of the channel to `T / d`, where `T` is the
    /// `request_timeout` and `d` is the expected average duration of CPU and I/O it takes to
    /// build a response.
    ///
    /// Can be `None` if the local node does not support answering incoming requests.
    /// If this is `None`, then the local node will not advertise support for this protocol towards
    /// other peers. If this is `Some` but the channel is closed, then the local node will
    /// advertise support for this protocol, but any incoming request will lead to an error being
    /// sent back.
    pub inbound_queue: Option<mpsc::Sender<IncomingRequest>>,
}

impl ProtocolConfig {
    /// Creates request-response protocol config.
    pub fn new(protocol_name: &'static str) -> ProtocolConfig {
        ProtocolConfig {
            name: protocol_name,
            max_request_size: 1024 * 1024,
            max_response_size: 16 * 1024 * 1024,
            request_timeout: Duration::from_secs(20),
            inbound_queue: None,
        }
    }
}

/// A single request received by a peer on a request-response protocol.
#[derive(Debug)]
pub struct IncomingRequest {
    /// Who sent the request.
    pub peer: PeerId,

    /// Request sent by the remote. Will always be smaller than
    /// [`ProtocolConfig::max_request_size`].
    pub payload: Vec<u8>,

    /// Channel to send back the response.
    ///
    /// There are two ways to indicate that handling the request failed:
    ///
    /// 1. Drop `pending_response` and thus not changing the reputation of the peer.
    ///
    /// 2. Sending an `Err(())` via `pending_response`, optionally including reputation changes for
    /// the given peer.
    pub pending_response: oneshot::Sender<OutgoingResponse>,
}

/// Response for an incoming request to be send by a request protocol handler.
#[derive(Debug)]
pub struct OutgoingResponse {
    /// The payload of the response.
    ///
    /// `Err(())` if none is available e.g. due an error while handling the request.
    pub result: Result<Vec<u8>, ()>,

    /// If provided, the `oneshot::Sender` will be notified when the request has been sent to the
    /// peer.
    ///
    /// Note: Operating systems typically maintain a buffer of a few dozen kilobytes of
    /// outgoing data for each TCP socket, and it is not possible for a user
    /// application to inspect this buffer. This channel here is not actually notified
    /// when the response has been fully sent out, but rather when it has fully been
    /// written to the buffer managed by the operating system.
    pub sent_feedback: Option<oneshot::Sender<()>>,
}

/// Event generated by the [`RequestResponsesBehaviour`].
#[derive(Debug)]
pub enum Event {
    /// A remote sent a request and either we have successfully answered it or an error happened.
    ///
    /// This event is generated for statistics purposes.
    InboundRequest {
        /// Peer which has emitted the request.
        peer: PeerId,
        /// Name of the protocol in question.
        protocol: Cow<'static, str>,
        /// Whether handling the request was successful or unsuccessful.
        ///
        /// When successful contains the time elapsed between when we received the request and when
        /// we sent back the response. When unsuccessful contains the failure reason.
        result: Result<(), ResponseFailure>,
    },

    /// A request initiated using [`RequestResponsesBehaviour::send_request`] has succeeded or
    /// failed.
    ///
    /// This event is generated for statistics purposes.
    RequestFinished {
        /// Peer that we send a request to.
        peer: PeerId,
        /// Name of the protocol in question.
        protocol: Cow<'static, str>,
        /// Duration the request took.
        duration: Duration,
        /// Result of the request.
        result: Result<(), RequestFailure>,
    },
}

/// Combination of a protocol name and a request id.
///
/// Uniquely identifies an inbound or outbound request among all handled protocols. Note however
/// that uniqueness is only guaranteed between two inbound and likewise between two outbound
/// requests. There is no uniqueness guarantee in a set of both inbound and outbound
/// [`ProtocolRequestId`]s.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProtocolRequestId {
    protocol: Cow<'static, str>,
    request_id: RequestId,
}

impl From<(Cow<'static, str>, RequestId)> for ProtocolRequestId {
    fn from((protocol, request_id): (Cow<'static, str>, RequestId)) -> Self {
        Self {
            protocol,
            request_id,
        }
    }
}

/// When sending a request, what to do on a disconnected recipient.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum IfDisconnected {
    /// Try to connect to the peer.
    TryConnect,
    /// Just fail if the destination is not yet connected.
    #[allow(dead_code)] // reserved for the future logic or config change
    ImmediateError,
}

/// Convenience functions for `IfDisconnected`.
impl IfDisconnected {
    /// Shall we connect to a disconnected peer?
    pub fn should_connect(self) -> bool {
        match self {
            Self::TryConnect => true,
            Self::ImmediateError => false,
        }
    }
}

/// Implementation of `NetworkBehaviour` that provides support for request-response protocols.
#[allow(clippy::type_complexity)] // to preserve compatibility with copied implementation
pub struct RequestResponsesBehaviour {
    /// The multiple sub-protocols, by name.
    /// Contains the underlying libp2p `RequestResponse` behaviour, plus an optional
    /// "response builder" used to build responses for incoming requests.
    protocols: HashMap<
        Cow<'static, str>,
        (
            RequestResponse<GenericCodec>,
            Option<mpsc::Sender<IncomingRequest>>,
        ),
    >,

    /// Pending requests, passed down to a [`RequestResponse`] behaviour, awaiting a reply.
    pending_requests:
        HashMap<ProtocolRequestId, (Instant, oneshot::Sender<Result<Vec<u8>, RequestFailure>>)>,

    /// Whenever an incoming request arrives, a `Future` is added to this list and will yield the
    /// start time and the response to send back to the remote.
    pending_responses: stream::FuturesUnordered<
        Pin<Box<dyn Future<Output = Option<RequestProcessingOutcome>> + Send>>,
    >,

    /// Pending message request, holds `MessageRequest` as a Future state to poll it
    /// until we get a response from `Peerset`
    message_request: Option<MessageRequest>,

    /// Request handlers future collection.
    request_handlers: Vec<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

// This is a state of processing incoming request Message.
struct MessageRequest {
    peer: PeerId,
    request_id: RequestId,
    request: Vec<u8>,
    channel: ResponseChannel<Result<Vec<u8>, ()>>,
    protocol: String,
    response_builder: Option<mpsc::Sender<IncomingRequest>>,
}

/// Generated by the response builder and waiting to be processed.
struct RequestProcessingOutcome {
    request_id: RequestId,
    protocol: Cow<'static, str>,
    inner_channel: ResponseChannel<Result<Vec<u8>, ()>>,
    response: OutgoingResponse,
}

impl RequestResponsesBehaviour {
    /// Creates a new behaviour. Must be passed a list of supported protocols. Returns an error if
    /// the same protocol is passed twice.
    pub fn new(
        list: impl IntoIterator<Item = Box<dyn RequestHandler>>,
    ) -> Result<Self, RegisterError> {
        let mut protocols = HashMap::new();
        let mut request_handlers = Vec::new();
        for mut handler in list {
            let config = handler.protocol_config();

            let mut cfg = RequestResponseConfig::default();
            cfg.set_connection_keep_alive(Duration::from_secs(10));
            cfg.set_request_timeout(config.request_timeout);

            let protocol_support = if config.inbound_queue.is_some() {
                ProtocolSupport::Full
            } else {
                ProtocolSupport::Outbound
            };

            let rq_rp = RequestResponse::new(
                GenericCodec {
                    max_request_size: config.max_request_size,
                    max_response_size: config.max_response_size,
                },
                iter::once((config.name.as_bytes().to_vec(), protocol_support)),
                cfg,
            );

            match protocols.entry(Cow::Borrowed(config.name)) {
                Entry::Vacant(e) => e.insert((rq_rp, config.inbound_queue)),
                Entry::Occupied(e) => {
                    return Err(RegisterError::DuplicateProtocol(e.key().clone()))
                }
            };

            let request_handler_run: Pin<Box<dyn Future<Output = ()> + Send>> =
                Box::pin(async move { handler.run().await }.fuse());

            request_handlers.push(request_handler_run);
        }

        Ok(Self {
            protocols,
            pending_requests: Default::default(),
            pending_responses: Default::default(),
            message_request: None,
            request_handlers,
        })
    }

    /// Initiates sending a request.
    ///
    /// If there is no established connection to the target peer, the behavior is determined by the
    /// choice of `connect`.
    ///
    /// An error is returned if the protocol doesn't match one that has been registered.
    pub fn send_request(
        &mut self,
        target: &PeerId,
        protocol_name: &str,
        request: Vec<u8>,
        pending_response: oneshot::Sender<Result<Vec<u8>, RequestFailure>>,
        connect: IfDisconnected,
    ) {
        if let Some((protocol, _)) = self.protocols.get_mut(protocol_name) {
            if protocol.is_connected(target) || connect.should_connect() {
                let request_id = protocol.send_request(target, request);
                let prev_req_id = self.pending_requests.insert(
                    (protocol_name.to_string().into(), request_id).into(),
                    (Instant::now(), pending_response),
                );
                debug_assert!(prev_req_id.is_none(), "Expect request id to be unique.");
            } else if pending_response
                .send(Err(RequestFailure::NotConnected))
                .is_err()
            {
                debug!(
                    target: LOG_TARGET,
                    "Not connected to peer {:?}. At the same time local \
                     node is no longer interested in the result.",
                    target,
                );
            }
        } else if pending_response
            .send(Err(RequestFailure::UnknownProtocol))
            .is_err()
        {
            debug!(
                target: LOG_TARGET,
                "Unknown protocol {:?}. At the same time local \
                 node is no longer interested in the result.",
                protocol_name,
            );
        }
    }
}

impl NetworkBehaviour for RequestResponsesBehaviour {
    type ConnectionHandler = MultiHandler<
        String,
        <RequestResponse<GenericCodec> as NetworkBehaviour>::ConnectionHandler,
    >;
    type OutEvent = Event;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        let iter = self
            .protocols
            .iter_mut()
            .map(|(p, (r, _))| (p.to_string(), NetworkBehaviour::new_handler(r)));

        MultiHandler::try_from_iter(iter).expect(
            "Protocols are in a HashMap and there can be at most one handler per protocol name, \
			 which is the only possible error; qed",
        )
    }

    /// Informs the behaviour about an event from the [`Swarm`](crate::Swarm).
    fn on_swarm_event(&mut self, event: FromSwarm<Self::ConnectionHandler>) {
        match event {
            FromSwarm::ConnectionEstablished(inner) => {
                for (protocol, _) in self.protocols.values_mut() {
                    protocol.on_swarm_event(FromSwarm::ConnectionEstablished(inner));
                }
            }
            FromSwarm::ConnectionClosed(inner) => {
                for (p_name, handler) in inner.handler.into_iter() {
                    if let Some((protocol, _)) = self.protocols.get_mut(p_name.as_str()) {
                        protocol.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                            peer_id: inner.peer_id,
                            connection_id: inner.connection_id,
                            endpoint: inner.endpoint,
                            handler,
                            remaining_established: inner.remaining_established,
                        }));
                    } else {
                        error!(
                            target: LOG_TARGET,
                            "inject_connection_closed: no request-response instance registered \
                            for protocol {:?}",
                            p_name,
                        )
                    }
                }
            }
            FromSwarm::AddressChange(inner) => {
                for (protocol, _) in self.protocols.values_mut() {
                    protocol.on_swarm_event(FromSwarm::AddressChange(inner));
                }
            }
            FromSwarm::DialFailure(inner) => {
                for (protocol, _) in self.protocols.values_mut() {
                    protocol.on_swarm_event(FromSwarm::DialFailure(DialFailure {
                        peer_id: inner.peer_id,
                        error: inner.error,
                        connection_id: inner.connection_id,
                    }));
                }
            }
            FromSwarm::ListenFailure(inner) => {
                for (protocol, _) in self.protocols.values_mut() {
                    protocol.on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
                        local_addr: inner.local_addr,
                        send_back_addr: inner.send_back_addr,
                        error: inner.error,
                        connection_id: inner.connection_id,
                    }));
                }
            }
            FromSwarm::NewListener(inner) => {
                for (protocol, _) in self.protocols.values_mut() {
                    protocol.on_swarm_event(FromSwarm::NewListener(inner));
                }
            }
            FromSwarm::NewListenAddr(inner) => {
                for (protocol, _) in self.protocols.values_mut() {
                    protocol.on_swarm_event(FromSwarm::NewListenAddr(inner));
                }
            }
            FromSwarm::ExpiredListenAddr(inner) => {
                for (protocol, _) in self.protocols.values_mut() {
                    protocol.on_swarm_event(FromSwarm::ExpiredListenAddr(inner));
                }
            }
            FromSwarm::ListenerError(inner) => {
                for (protocol, _) in self.protocols.values_mut() {
                    protocol.on_swarm_event(FromSwarm::ListenerError(inner));
                }
            }
            FromSwarm::ListenerClosed(inner) => {
                for (protocol, _) in self.protocols.values_mut() {
                    protocol.on_swarm_event(FromSwarm::ListenerClosed(inner));
                }
            }
            FromSwarm::NewExternalAddr(inner) => {
                for (protocol, _) in self.protocols.values_mut() {
                    protocol.on_swarm_event(FromSwarm::NewExternalAddr(inner));
                }
            }
            FromSwarm::ExpiredExternalAddr(inner) => {
                for (protocol, _) in self.protocols.values_mut() {
                    protocol.on_swarm_event(FromSwarm::ExpiredExternalAddr(inner));
                }
            }
        };
    }

    fn addresses_of_peer(&mut self, _: &PeerId) -> Vec<Multiaddr> {
        Vec::new()
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection: ConnectionId,
        (p_name, event): <Self::ConnectionHandler as ConnectionHandler>::OutEvent,
    ) {
        if let Some((proto, _)) = self.protocols.get_mut(&*p_name) {
            return proto.on_connection_handler_event(peer_id, connection, event);
        }

        warn!(
            target: LOG_TARGET,
            "inject_node_event: no request-response instance registered for protocol {:?}", p_name
        )
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, THandlerInEvent<Self>>> {
        'poll_all: loop {
            if let Some(message_request) = self.message_request.take() {
                let MessageRequest {
                    peer,
                    request_id,
                    request,
                    channel,
                    protocol,
                    response_builder,
                } = message_request;

                let (tx, rx) = oneshot::channel();

                // Submit the request to the "response builder" passed by the user at
                // initialization.
                if let Some(mut response_builder) = response_builder {
                    // If the response builder is too busy, silently drop `tx`. This
                    // will be reported by the corresponding `RequestResponse` through
                    // an `InboundFailure::Omission` event.
                    let _ = response_builder.try_send(IncomingRequest {
                        peer,
                        payload: request,
                        pending_response: tx,
                    });
                } else {
                    debug_assert!(false, "Received message on outbound-only protocol.");
                }

                self.pending_responses.push(Box::pin(async move {
                    // The `tx` created above can be dropped if we are not capable of
                    // processing this request, which is reflected as a
                    // `InboundFailure::Omission` event.
                    if let Ok(response) = rx.await {
                        Some(RequestProcessingOutcome {
                            request_id,
                            protocol: Cow::from(protocol),
                            inner_channel: channel,
                            response,
                        })
                    } else {
                        None
                    }
                }));

                // This `continue` makes sure that `pending_responses` gets polled
                // after we have added the new element.
                continue 'poll_all;
            }
            // Poll to see if any response is ready to be sent back.
            while let Poll::Ready(Some(outcome)) = self.pending_responses.poll_next_unpin(cx) {
                let RequestProcessingOutcome {
                    request_id,
                    protocol: protocol_name,
                    inner_channel,
                    response: OutgoingResponse { result, .. },
                } = match outcome {
                    Some(outcome) => outcome,
                    // The response builder was too busy or handling the request failed. This is
                    // later on reported as a `InboundFailure::Omission`.
                    None => continue,
                };

                if let Ok(payload) = result {
                    if let Some((protocol, _)) = self.protocols.get_mut(&*protocol_name) {
                        if protocol.send_response(inner_channel, Ok(payload)).is_err() {
                            // Note: Failure is handled further below when receiving
                            // `InboundFailure` event from `RequestResponse` behaviour.
                            debug!(
                                target: LOG_TARGET,
                                %request_id,
                                "Failed to send response for request on protocol {} due to a \
                                timeout or due to the connection to the peer being closed. \
                                Dropping response",
                                protocol_name,
                            );
                        }
                    }
                }
            }

            for rq_rs_runner in &mut self.request_handlers {
                // Future.Output == (), so we don't need a result here
                let _ = rq_rs_runner.poll_unpin(cx);
            }

            // Poll request-responses protocols.
            for (protocol, (behaviour, response_builder)) in &mut self.protocols {
                while let Poll::Ready(ev) = behaviour.poll(cx, params) {
                    let ev = match ev {
                        // Main events we are interested in.
                        NetworkBehaviourAction::GenerateEvent(ev) => ev,

                        // Other events generated by the underlying behaviour are transparently
                        // passed through.
                        NetworkBehaviourAction::Dial { opts } => {
                            if opts.get_peer_id().is_none() {
                                error!(
                                    "The request-response isn't supposed to start dialing \
                                    addresses"
                                );
                            }
                            return Poll::Ready(NetworkBehaviourAction::Dial { opts });
                        }
                        NetworkBehaviourAction::NotifyHandler {
                            peer_id,
                            handler,
                            event,
                        } => {
                            return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                                peer_id,
                                handler,
                                event: ((*protocol).to_string(), event),
                            })
                        }
                        NetworkBehaviourAction::ReportObservedAddr { address, score } => {
                            return Poll::Ready(NetworkBehaviourAction::ReportObservedAddr {
                                address,
                                score,
                            })
                        }
                        NetworkBehaviourAction::CloseConnection {
                            peer_id,
                            connection,
                        } => {
                            return Poll::Ready(NetworkBehaviourAction::CloseConnection {
                                peer_id,
                                connection,
                            })
                        }
                    };

                    match ev {
                        // Received a request from a remote.
                        RequestResponseEvent::Message {
                            peer,
                            message:
                                RequestResponseMessage::Request {
                                    request_id,
                                    request,
                                    channel,
                                },
                        } => {
                            self.message_request = Some(MessageRequest {
                                peer,
                                request_id,
                                request,
                                channel,
                                protocol: protocol.to_string(),
                                response_builder: response_builder.clone(),
                            });

                            // This `continue` makes sure that `message_request` gets polled
                            // after we have added the new element.
                            continue 'poll_all;
                        }

                        // Received a response from a remote to one of our requests.
                        RequestResponseEvent::Message {
                            peer,
                            message:
                                RequestResponseMessage::Response {
                                    request_id,
                                    response,
                                },
                        } => {
                            let (started, delivered) = match self
                                .pending_requests
                                .remove(&(protocol.clone(), request_id).into())
                            {
                                Some((started, pending_response)) => {
                                    let delivered = pending_response
                                        .send(response.map_err(|()| RequestFailure::Refused))
                                        .map_err(|_| RequestFailure::Obsolete);
                                    (started, delivered)
                                }
                                None => {
                                    warn!(
                                        target: LOG_TARGET,
                                        "Received `RequestResponseEvent::Message` with unexpected request id {:?}",
                                        request_id,
                                    );
                                    debug_assert!(false);
                                    continue;
                                }
                            };

                            let out = Event::RequestFinished {
                                peer,
                                protocol: protocol.clone(),
                                duration: started.elapsed(),
                                result: delivered,
                            };

                            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(out));
                        }

                        // One of our requests has failed.
                        RequestResponseEvent::OutboundFailure {
                            peer,
                            request_id,
                            error,
                            ..
                        } => {
                            let started = match self
                                .pending_requests
                                .remove(&(protocol.clone(), request_id).into())
                            {
                                Some((started, pending_response)) => {
                                    if pending_response
                                        .send(Err(RequestFailure::Network(error.clone())))
                                        .is_err()
                                    {
                                        debug!(
                                            target: LOG_TARGET,
                                            %request_id,
                                            "Request failed. At the same time local \
                                             node is no longer interested in the result.",
                                        );
                                    }
                                    started
                                }
                                None => {
                                    warn!(
                                        target: LOG_TARGET,
                                        %request_id,
                                        "Received `RequestResponseEvent::Message` with unexpected request",

                                    );
                                    debug_assert!(false);
                                    continue;
                                }
                            };

                            let out = Event::RequestFinished {
                                peer,
                                protocol: protocol.clone(),
                                duration: started.elapsed(),
                                result: Err(RequestFailure::Network(error)),
                            };

                            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(out));
                        }

                        // An inbound request failed, either while reading the request or due to
                        // failing to send a response.
                        RequestResponseEvent::InboundFailure { peer, error, .. } => {
                            debug!(?error, %peer, "Inbound request failed.");

                            let out = Event::InboundRequest {
                                peer,
                                protocol: protocol.clone(),
                                result: Err(ResponseFailure::Network(error)),
                            };
                            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(out));
                        }

                        // A response to an inbound request has been sent.
                        RequestResponseEvent::ResponseSent { peer, .. } => {
                            let out = Event::InboundRequest {
                                peer,
                                protocol: protocol.clone(),
                                result: Ok(()),
                            };

                            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(out));
                        }
                    };
                }
            }

            break Poll::Pending;
        }
    }
}

/// Error when registering a protocol.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    /// A protocol has been specified multiple times.
    #[error("{0}")]
    DuplicateProtocol(Cow<'static, str>),
}

/// Error in a request.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum RequestFailure {
    #[error("We are not currently connected to the requested peer.")]
    NotConnected,
    #[error("Given protocol hasn't been registered.")]
    UnknownProtocol,
    #[error("Remote has closed the substream before answering, thereby signaling that it considers the request as valid, but refused to answer it.")]
    Refused,
    #[error("The remote replied, but the local node is no longer interested in the response.")]
    Obsolete,
    /// Problem on the network.
    #[error("Problem on the network: {0}")]
    Network(OutboundFailure),
}

/// Error when processing a request sent by a remote.
#[derive(Debug, thiserror::Error)]
pub enum ResponseFailure {
    /// Problem on the network.
    #[error("Problem on the network: {0}")]
    Network(InboundFailure),
}

/// Implements the libp2p [`RequestResponseCodec`] trait. Defines how streams of bytes are turned
/// into requests and responses and vice-versa.
#[derive(Debug, Clone)]
#[doc(hidden)] // Needs to be public in order to satisfy the Rust compiler.
pub struct GenericCodec {
    max_request_size: u64,
    max_response_size: u64,
}

#[async_trait::async_trait]
impl RequestResponseCodec for GenericCodec {
    type Protocol = Vec<u8>;
    type Request = Vec<u8>;
    type Response = Result<Vec<u8>, ()>;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        mut io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Read the length.
        let length = unsigned_varint::aio::read_usize(&mut io)
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        if length > usize::try_from(self.max_request_size).unwrap_or(usize::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Request size exceeds limit: {} > {}",
                    length, self.max_request_size
                ),
            ));
        }

        // Read the payload.
        let mut buffer = vec![0; length];
        io.read_exact(&mut buffer).await?;
        Ok(buffer)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        mut io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Note that this function returns a `Result<Result<...>>`. Returning an `Err` is
        // considered as a protocol error and will result in the entire connection being closed.
        // Returning `Ok(Err(_))` signifies that a response has successfully been fetched, and
        // that this response is an error.

        // Read the length.
        let length = match unsigned_varint::aio::read_usize(&mut io).await {
            Ok(l) => l,
            Err(unsigned_varint::io::ReadError::Io(err))
                if matches!(err.kind(), io::ErrorKind::UnexpectedEof) =>
            {
                return Ok(Err(()))
            }
            Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidInput, err)),
        };

        if length > usize::try_from(self.max_response_size).unwrap_or(usize::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Response size exceeds limit: {} > {}",
                    length, self.max_response_size
                ),
            ));
        }

        // Read the payload.
        let mut buffer = vec![0; length];
        io.read_exact(&mut buffer).await?;
        Ok(Ok(buffer))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Write the length.
        {
            let mut buffer = unsigned_varint::encode::usize_buffer();
            io.write_all(unsigned_varint::encode::usize(req.len(), &mut buffer))
                .await?;
        }

        // Write the payload.
        io.write_all(&req).await?;

        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // If `res` is an `Err`, we jump to closing the substream without writing anything on it.
        if let Ok(res) = res {
            // Write the length.
            {
                let mut buffer = unsigned_varint::encode::usize_buffer();
                io.write_all(unsigned_varint::encode::usize(res.len(), &mut buffer))
                    .await?;
            }

            // Write the payload.
            io.write_all(&res).await?;
        }

        io.close().await?;
        Ok(())
    }
}

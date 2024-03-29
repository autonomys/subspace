use crate::behavior::{Behavior, Event};
use crate::shared::{Command, Shared};
use crate::utils::AsyncJoinOnDrop;
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use futures::channel::{mpsc, oneshot};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use libp2p::metrics::{Metrics, Recorder};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{
    Event as RequestResponseEvent, InboundRequestId, Message, OutboundFailure, OutboundRequestId,
    ResponseChannel,
};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{DialError, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Swarm};
use parity_scale_codec::{Decode, Encode};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Weak;
use tokio::task::yield_now;
use tokio::time::sleep;
use tracing::{debug, error, trace, warn};

pub type InboundRequestsHandler<Requests, Responses> =
    Box<dyn Fn(Requests) -> Pin<Box<dyn Future<Output = Responses> + Send>> + Send>;

#[derive(Debug)]
struct BootstrapNode {
    backoff: ExponentialBackoff,
    addresses: Vec<Multiaddr>,
}

impl Default for BootstrapNode {
    fn default() -> Self {
        BootstrapNode {
            backoff: ExponentialBackoff {
                max_elapsed_time: None,
                ..ExponentialBackoff::default()
            },
            addresses: vec![],
        }
    }
}

pub struct NetworkWorker<Requests, Responses> {
    bootstrap_nodes: HashMap<PeerId, BootstrapNode>,
    request_handler: InboundRequestsHandler<Requests, Responses>,
    command_receiver: mpsc::Receiver<Command>,
    swarm: Swarm<Behavior>,
    shared_weak: Weak<Shared>,
    redials: FuturesUnordered<AsyncJoinOnDrop<(PeerId, Vec<Multiaddr>)>>,
    #[allow(clippy::type_complexity)]
    inbound_requests: FuturesUnordered<
        AsyncJoinOnDrop<(InboundRequestId, PeerId, ResponseChannel<Vec<u8>>, Vec<u8>)>,
    >,
    #[allow(clippy::type_complexity)]
    pending_outbound_requests:
        HashMap<PeerId, Vec<(Vec<u8>, oneshot::Sender<Result<Vec<u8>, OutboundFailure>>)>>,
    outbound_requests:
        HashMap<OutboundRequestId, oneshot::Sender<Result<Vec<u8>, OutboundFailure>>>,
    metrics: Option<Metrics>,
}

impl<Requests, Responses> NetworkWorker<Requests, Responses>
where
    Requests: Decode + Send,
    Responses: Encode + Send + 'static,
{
    pub(crate) fn new(
        request_handler: InboundRequestsHandler<Requests, Responses>,
        command_receiver: mpsc::Receiver<Command>,
        swarm: Swarm<Behavior>,
        shared_weak: Weak<Shared>,
        bootstrap_nodes: Vec<Multiaddr>,
        metrics: Option<Metrics>,
    ) -> Self {
        let mut grouped_bootstrap_nodes = HashMap::<PeerId, BootstrapNode>::new();
        for mut address in bootstrap_nodes {
            if let Some(Protocol::P2p(peer_id)) = address.pop() {
                grouped_bootstrap_nodes
                    .entry(peer_id)
                    .or_default()
                    .addresses
                    .push(address);
            }
        }

        Self {
            bootstrap_nodes: grouped_bootstrap_nodes,
            request_handler,
            command_receiver,
            swarm,
            shared_weak,
            redials: FuturesUnordered::default(),
            inbound_requests: FuturesUnordered::default(),
            pending_outbound_requests: HashMap::default(),
            outbound_requests: HashMap::default(),
            metrics,
        }
    }

    /// Drives the network worker
    pub async fn run(&mut self) {
        for (peer_id, bootstrap_node) in self.bootstrap_nodes.iter() {
            for address in bootstrap_node.addresses.clone() {
                self.swarm
                    .behaviour_mut()
                    .request_response
                    .add_address(peer_id, address);
            }
            if let Err(error) = self.swarm.dial(
                DialOpts::peer_id(*peer_id)
                    .addresses(bootstrap_node.addresses.clone())
                    .build(),
            ) {
                error!(%error, %peer_id, "Failed to dial bootstrap node");
            }
        }

        loop {
            futures::select! {
                swarm_event = self.swarm.next() => {
                    if let Some(swarm_event) = swarm_event {
                        self.register_event_metrics(&swarm_event);
                        self.handle_swarm_event(swarm_event).await;
                    } else {
                        break;
                    }
                },
                redial_result = self.redials.select_next_some() => {
                    match redial_result {
                        Ok((peer_id, addresses)) => {
                            if let Err(error) = self.swarm.dial(
                                DialOpts::peer_id(peer_id)
                                    .addresses(addresses)
                                    .build(),
                            ) {
                                error!(%error, %peer_id, "Failed to redial peer");
                            }
                        }
                        Err(error) => {
                            error!(%error, "Redial task error");
                        }
                    }
                },
                inbound_request_result = self.inbound_requests.select_next_some() => {
                    match inbound_request_result {
                        Ok((request_id, peer, channel, response)) => {
                            self.handle_inbound_request_response(request_id, peer, channel, response);
                        }
                        Err(error) => {
                            error!(%error, "Failed to join inbound request");
                        }
                    }
                },
                command = self.command_receiver.next() => {
                    if let Some(command) = command {
                        self.handle_command(command);
                    } else {
                        break;
                    }
                },
            }

            // Allow to exit from busy loop during graceful shutdown
            yield_now().await;
        }
    }

    async fn handle_swarm_event(&mut self, swarm_event: SwarmEvent<Event>) {
        match swarm_event {
            SwarmEvent::Behaviour(Event::RequestResponse(event)) => {
                self.handle_request_response_event(event).await;
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                let shared = match self.shared_weak.upgrade() {
                    Some(shared) => shared,
                    None => {
                        return;
                    }
                };
                shared.listeners.lock().push(address.clone());
                shared.handlers.new_listener.call_simple(&address);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                num_established,
                ..
            } => {
                let shared = match self.shared_weak.upgrade() {
                    Some(shared) => shared,
                    None => {
                        return;
                    }
                };

                debug!(
                    %peer_id,
                    ?endpoint,
                    %num_established,
                    "Connection established"
                );

                // A new connection
                if num_established.get() == 1 {
                    shared.handlers.connected_peer.call_simple(&peer_id);
                }

                // If bootstrap node then reset retries
                if let Some(bootstrap_node) = self.bootstrap_nodes.get_mut(&peer_id) {
                    bootstrap_node.backoff.reset();
                }

                // Process any pending requests for this peer
                if let Some(pending_outbound_requests) =
                    self.pending_outbound_requests.remove(&peer_id)
                {
                    for (request, result_sender) in pending_outbound_requests {
                        let request_id = self
                            .swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer_id, request);
                        self.outbound_requests.insert(request_id, result_sender);
                    }
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                cause,
                ..
            } => {
                let shared = match self.shared_weak.upgrade() {
                    Some(shared) => shared,
                    None => {
                        return;
                    }
                };

                debug!(
                    %peer_id,
                    ?cause,
                    %num_established,
                    "Connection closed with peer"
                );

                // No more connections
                if num_established == 0 {
                    shared.handlers.disconnected_peer.call_simple(&peer_id);

                    // In case of disconnection from bootstrap node reconnect to it
                    if let Some(bootstrap_node) = self.bootstrap_nodes.get_mut(&peer_id) {
                        if let Err(error) = self.swarm.dial(
                            DialOpts::peer_id(peer_id)
                                .addresses(bootstrap_node.addresses.clone())
                                .build(),
                        ) {
                            error!(%error, %peer_id, "Failed to dial bootstrap node");
                        }
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer_id) = peer_id {
                    warn!(%error, %peer_id, "Failed to establish outgoing connection");

                    // If bootstrap node then retry after some delay
                    if let Some(bootstrap_node) = self.bootstrap_nodes.get_mut(&peer_id) {
                        if let Some(delay) = bootstrap_node.backoff.next_backoff() {
                            let addresses = bootstrap_node.addresses.clone();

                            self.redials.push(AsyncJoinOnDrop::new(
                                tokio::spawn(async move {
                                    sleep(delay).await;

                                    (peer_id, addresses)
                                }),
                                true,
                            ))
                        }
                    }
                    // Send errors to all pending requests for this peer
                    if let Some(pending_outbound_requests) =
                        self.pending_outbound_requests.remove(&peer_id)
                    {
                        for (_request, result_sender) in pending_outbound_requests {
                            let _ = result_sender.send(Err(OutboundFailure::DialFailure));
                        }
                    }
                }
            }
            other => {
                trace!("Other swarm event: {:?}", other);
            }
        }
    }

    async fn handle_request_response_event(
        &mut self,
        event: RequestResponseEvent<Vec<u8>, Vec<u8>>,
    ) {
        match event {
            RequestResponseEvent::Message { peer, message } => match message {
                Message::Request {
                    request_id,
                    request,
                    channel,
                } => {
                    let request = match Requests::decode(&mut request.as_slice()) {
                        Ok(request) => request,
                        Err(error) => {
                            warn!(%error, "Failed to decode requests");
                            return;
                        }
                    };
                    let response_fut = (self.request_handler)(request);

                    self.inbound_requests.push(AsyncJoinOnDrop::new(
                        tokio::spawn(async move {
                            let response = response_fut.await.encode();
                            (request_id, peer, channel, response)
                        }),
                        true,
                    ));
                }
                Message::Response {
                    request_id,
                    response,
                } => {
                    if let Some(sender) = self.outbound_requests.remove(&request_id) {
                        let _ = sender.send(Ok(response));
                    }
                }
            },
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error,
            } => {
                debug!(
                    %peer,
                    %request_id,
                    %error,
                    "Outbound request failed"
                );

                if let Some(sender) = self.outbound_requests.remove(&request_id) {
                    let _ = sender.send(Err(error));
                }
            }
            RequestResponseEvent::InboundFailure {
                peer,
                request_id,
                error,
            } => {
                debug!(
                    %peer,
                    %request_id,
                    %error,
                    "Inbound request failed"
                );
            }
            RequestResponseEvent::ResponseSent { .. } => {
                // Not interested
            }
        }
    }

    fn handle_inbound_request_response(
        &mut self,
        request_id: InboundRequestId,
        peer: PeerId,
        channel: ResponseChannel<Vec<u8>>,
        response: Vec<u8>,
    ) {
        if !channel.is_open() {
            trace!(%peer, %request_id, "Response channel already closed");
            return;
        }

        if self
            .swarm
            .behaviour_mut()
            .request_response
            .send_response(channel, response)
            .is_err()
        {
            debug!(%peer, %request_id, "Response sending failed");
        }
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::Request {
                peer_id,
                addresses,
                request,
                result_sender,
            } => {
                let request_response = &mut self.swarm.behaviour_mut().request_response;
                if request_response.is_connected(&peer_id) {
                    // If already connected - send request right away
                    let request_id = request_response.send_request(&peer_id, request);
                    self.outbound_requests.insert(request_id, result_sender);
                } else {
                    // Otherwise try to dial
                    match self.swarm.dial(
                        DialOpts::peer_id(peer_id)
                            .addresses(addresses)
                            .condition(PeerCondition::DisconnectedAndNotDialing)
                            .build(),
                    ) {
                        Ok(()) | Err(DialError::DialPeerConditionFalse(_)) => {
                            // In case dial initiated successfully, or it was initiated prior -
                            // store pending request
                            self.pending_outbound_requests
                                .entry(peer_id)
                                .or_default()
                                .push((request, result_sender));
                        }
                        Err(error) => {
                            warn!(%error, %peer_id, "Failed to dial peer on request");
                            let _ = result_sender.send(Err(OutboundFailure::DialFailure));
                        }
                    }
                }
            }
        }
    }

    fn register_event_metrics(&mut self, swarm_event: &SwarmEvent<Event>) {
        if let Some(ref mut metrics) = self.metrics {
            #[allow(clippy::match_single_binding)]
            match swarm_event {
                // TODO: implement in the upstream repository
                // SwarmEvent::Behaviour(Event::RequestResponse(request_response_event)) => {
                //     self.metrics.record(request_response_event);
                // }
                swarm_event => {
                    metrics.record(swarm_event);
                }
            }
        }
    }
}

use crate::behavior::{Behavior, BehaviorConfig};
use crate::network_worker::{InboundRequestsHandler, NetworkWorker};
use crate::shared::{Command, HandlerFn, Shared};
use event_listener_primitives::HandlerId;
use futures::channel::{mpsc, oneshot};
use futures::SinkExt;
use libp2p::identity::Keypair;
use libp2p::metrics::Metrics;
use libp2p::noise::Config as NoiseConfig;
use libp2p::request_response::OutboundFailure;
use libp2p::yamux::Config as YamuxConfig;
use libp2p::{Multiaddr, PeerId, SwarmBuilder};
use parity_scale_codec::{Decode, Encode};
use std::error::Error;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

/// Generic request with associated response
pub trait GenericRequest: Encode + Decode + Send + Sync + 'static {
    /// Response type that corresponds to this request
    type Response: Encode + Decode + Send + Sync + 'static;
}

/// Request sending errors
#[derive(Debug, Error)]
pub enum SendRequestError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] mpsc::SendError),
    /// Worker was dropped
    #[error("Worker was dropped")]
    WorkerDropped,
    /// Underlying protocol returned an error, impossible to get response
    #[error("Underlying protocol returned an error: {0}")]
    ProtocolFailure(#[from] OutboundFailure),
    /// Underlying protocol returned an incorrect format, impossible to get response
    #[error("Received incorrectly formatted response: {0}")]
    IncorrectResponseFormat(#[from] parity_scale_codec::Error),
    /// Unrecognized response
    #[error("Unrecognized response")]
    UnrecognizedResponse(Box<dyn Error>),
}

impl From<oneshot::Canceled> for SendRequestError {
    #[inline]
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::WorkerDropped
    }
}

/// Network configuration
pub struct NetworkConfig<Requests, Responses> {
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<Multiaddr>,
    /// Multiaddrs to listen on
    pub listen_on: Vec<Multiaddr>,
    /// Keypair to use
    pub keypair: Keypair,
    /// Network key to limit connections to those who know the key
    pub network_key: Vec<u8>,
    /// Behavior config
    pub behavior_config: BehaviorConfig,
    /// How long to keep a connection alive once it is idling
    pub idle_connection_timeout: Duration,
    /// Handler for incoming requests
    pub request_handler: InboundRequestsHandler<Requests, Responses>,
    /// Optional libp2p metrics
    pub metrics: Option<Metrics>,
}

/// Implementation of a network
#[derive(Debug)]
#[must_use = "Network doesn't do anything if dropped"]
pub struct Network<Requests, Responses> {
    id: PeerId,
    shared: Arc<Shared>,
    phantom: PhantomData<(Requests, Responses)>,
}

impl<Requests, Responses> Clone for Network<Requests, Responses> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            shared: Arc::clone(&self.shared),
            phantom: PhantomData,
        }
    }
}

impl<Requests, Responses> Network<Requests, Responses>
where
    Requests: Encode + Decode + Send,
    Responses: Encode + Decode + Send + 'static,
{
    pub fn new(
        config: NetworkConfig<Requests, Responses>,
    ) -> Result<(Self, NetworkWorker<Requests, Responses>), Box<dyn Error>> {
        let mut swarm = SwarmBuilder::with_existing_identity(config.keypair)
            .with_tokio()
            .with_tcp(
                Default::default(),
                |keypair: &Keypair| {
                    NoiseConfig::new(keypair)
                        .map(|noise_config| noise_config.with_prologue(config.network_key))
                },
                YamuxConfig::default,
            )?
            .with_dns()?
            .with_behaviour(move |_keypair| Ok(Behavior::new(config.behavior_config)))
            .expect("Not fallible; qed")
            .with_swarm_config(|swarm_config| {
                swarm_config.with_idle_connection_timeout(config.idle_connection_timeout)
            })
            .build();

        // Setup listen_on addresses
        for addr in config.listen_on {
            swarm.listen_on(addr.clone())?;
        }

        let (command_sender, command_receiver) = mpsc::channel(1);
        let shared = Arc::new(Shared::new(command_sender));
        let shared_weak = Arc::downgrade(&shared);

        let network = Self {
            id: *swarm.local_peer_id(),
            shared,
            phantom: PhantomData,
        };
        let network_worker = NetworkWorker::new(
            config.request_handler,
            command_receiver,
            swarm,
            shared_weak,
            config.bootstrap_nodes,
            config.metrics,
        );

        Ok((network, network_worker))
    }

    /// Node's own local ID.
    pub fn id(&self) -> PeerId {
        self.id
    }

    /// Sends the generic request to the peer at specified address and awaits the result
    pub async fn request<Request>(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: Request,
    ) -> Result<Request::Response, SendRequestError>
    where
        Request: GenericRequest,
        Request: Into<Requests>,
        Request::Response: TryFrom<Responses>,
        <<Request as GenericRequest>::Response as TryFrom<Responses>>::Error: Into<Box<dyn Error>>,
    {
        let (result_sender, result_receiver) = oneshot::channel();
        let command = Command::Request {
            peer_id,
            addresses,
            request: Into::<Requests>::into(request).encode(),
            result_sender,
        };

        self.shared.command_sender.clone().send(command).await?;

        let result = result_receiver.await??;

        let responses = Responses::decode(&mut result.as_slice())?;
        Request::Response::try_from(responses)
            .map_err(|error| SendRequestError::UnrecognizedResponse(error.into()))
    }

    /// Callback is called when node starts listening on new address.
    pub fn on_new_listener(&self, callback: HandlerFn<Multiaddr>) -> HandlerId {
        self.shared.handlers.new_listener.add(callback)
    }

    /// Callback is called when a peer is connected.
    pub fn on_connected_peer(&self, callback: HandlerFn<PeerId>) -> HandlerId {
        self.shared.handlers.connected_peer.add(callback)
    }

    /// Callback is called when a peer is disconnected.
    pub fn on_disconnected_peer(&self, callback: HandlerFn<PeerId>) -> HandlerId {
        self.shared.handlers.disconnected_peer.add(callback)
    }
}

use crate::create::{create, Config, CreationError};
use crate::node_runner::NodeRunner;
use crate::request_handlers::generic_request_handler::GenericRequest;
use crate::request_responses;
use crate::shared::{Command, CreatedSubscription, Shared};
use bytes::Bytes;
use event_listener_primitives::HandlerId;
use futures::channel::mpsc::SendError;
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, Stream};
use libp2p::core::multihash::Multihash;
use libp2p::gossipsub::error::SubscriptionError;
use libp2p::gossipsub::Sha256Topic;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use parity_scale_codec::Decode;
use parking_lot::Mutex;
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, trace};

/// Topic subscription, will unsubscribe when last instance is dropped for a particular topic.
#[derive(Debug)]
#[pin_project::pin_project(PinnedDrop)]
pub struct TopicSubscription {
    topic: Option<Sha256Topic>,
    subscription_id: usize,
    command_sender: Option<mpsc::Sender<Command>>,
    #[pin]
    receiver: mpsc::UnboundedReceiver<Bytes>,
}

impl Stream for TopicSubscription {
    type Item = Bytes;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.project().receiver.poll_next(cx)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.receiver.size_hint()
    }
}

#[pin_project::pinned_drop]
impl PinnedDrop for TopicSubscription {
    fn drop(mut self: std::pin::Pin<&mut Self>) {
        let topic = self
            .topic
            .take()
            .expect("Always specified on creation and only removed on drop; qed");
        let subscription_id = self.subscription_id;
        let mut command_sender = self
            .command_sender
            .take()
            .expect("Always specified on creation and only removed on drop; qed");

        tokio::spawn(async move {
            // Doesn't matter if node runner is already dropped.
            let _ = command_sender
                .send(Command::Unsubscribe {
                    topic,
                    subscription_id,
                })
                .await;
        });
    }
}

#[derive(Debug, Error)]
pub enum GetValueError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
}

impl From<oneshot::Canceled> for GetValueError {
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::NodeRunnerDropped
    }
}

#[derive(Debug, Error)]
pub enum GetClosestPeersError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
}

impl From<oneshot::Canceled> for GetClosestPeersError {
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::NodeRunnerDropped
    }
}

#[derive(Debug, Error)]
pub enum SubscribeError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
    /// Failed to create subscription.
    #[error("Failed to create subscription: {0}")]
    Subscription(#[from] SubscriptionError),
}

impl From<oneshot::Canceled> for SubscribeError {
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::NodeRunnerDropped
    }
}

#[derive(Debug, Error)]
pub enum PublishError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
    /// Failed to publish message.
    #[error("Failed to publish message: {0}")]
    Publish(#[from] libp2p::gossipsub::error::PublishError),
}

impl From<oneshot::Canceled> for PublishError {
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::NodeRunnerDropped
    }
}

#[derive(Debug, Error)]
pub enum SendRequestError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
    /// Underlying protocol returned an error, impossible to get response.
    #[error("Underlying protocol returned an error: {0}")]
    ProtocolFailure(#[from] request_responses::RequestFailure),
    /// Underlying protocol returned an incorrect format, impossible to get response.
    #[error("Received incorrectly formatted response: {0}")]
    IncorrectResponseFormat(#[from] parity_scale_codec::Error),
}

impl From<oneshot::Canceled> for SendRequestError {
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::NodeRunnerDropped
    }
}

#[derive(Debug, Error)]
pub enum CircuitRelayClientError {
    /// Expected node to be a circuit relay server, found only client
    #[error("Expected node to be a circuit relay server, found only client")]
    ExpectedServer,
    /// Failed to retrieve memory address, typically means networking was destroyed.
    #[error("Failed to retrieve memory address")]
    FailedToRetrieveMemoryAddress,
}

impl From<oneshot::Canceled> for CircuitRelayClientError {
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::FailedToRetrieveMemoryAddress
    }
}

/// Implementation of a network node on Subspace Network.
#[derive(Debug, Clone)]
#[must_use = "Node doesn't do anything if dropped"]
pub struct Node {
    shared: Arc<Shared>,
    is_relay_server: bool,
    relay_server_memory_port: Arc<Mutex<Option<u64>>>,
}

impl Node {
    pub(crate) fn new(shared: Arc<Shared>, is_relay_server: bool) -> Self {
        Self {
            shared,
            is_relay_server,
            relay_server_memory_port: Arc::new(Mutex::new(None)),
        }
    }

    /// Node's own local ID.
    pub fn id(&self) -> PeerId {
        self.shared.id
    }

    /// Configures circuit relay client using this node as circuit relay server. It expects Node
    /// running in the relay server mode (which happens automatically when addresses to listen on
    /// are provided).
    pub async fn spawn(&self, mut config: Config) -> Result<(Node, NodeRunner), CreationError> {
        let relay_server_memory_port = self.get_relay_server_memory_port().await?;

        config.relay_server_address.replace(
            Multiaddr::from(Protocol::Memory(relay_server_memory_port))
                .with(Protocol::P2p(self.id().into()))
                .with(Protocol::P2pCircuit),
        );
        config.parent_node.replace(self.clone());

        create(config).await
    }

    /// Get address of circuit relay server for use
    pub async fn get_relay_server_memory_port(&self) -> Result<u64, CircuitRelayClientError> {
        if !self.is_relay_server {
            return Err(CircuitRelayClientError::ExpectedServer);
        }

        // Fast path in case address is already known
        if let Some(port) = *self.relay_server_memory_port.lock() {
            return Ok(port);
        }

        let (port_sender, port_receiver) = oneshot::channel();
        let _handler = self.on_new_listener(Arc::new({
            let port_sender = Mutex::new(Some(port_sender));

            move |address| {
                if let Some(Protocol::Memory(port)) = address.iter().next() {
                    if let Some(port_sender) = port_sender.lock().take() {
                        let _ = port_sender.send(port);
                    }
                }
            }
        }));

        // Subscription to events is in place, check if listener is already known
        for address in self.shared.listeners.lock().iter() {
            if let Some(Protocol::Memory(port)) = address.iter().next() {
                self.relay_server_memory_port.lock().replace(port);

                return Ok(port);
            }
        }

        // Otherwise for new memory listener
        let port = port_receiver.await?;
        self.relay_server_memory_port.lock().replace(port);
        Ok(port)
    }

    pub async fn get_value(&self, key: Multihash) -> Result<Option<Vec<u8>>, GetValueError> {
        let (result_sender, result_receiver) = oneshot::channel();

        self.shared
            .command_sender
            .clone()
            .send(Command::GetValue { key, result_sender })
            .await?;

        Ok(result_receiver.await?)
    }

    pub async fn subscribe(&self, topic: Sha256Topic) -> Result<TopicSubscription, SubscribeError> {
        let (result_sender, result_receiver) = oneshot::channel();

        self.shared
            .command_sender
            .clone()
            .send(Command::Subscribe {
                topic: topic.clone(),
                result_sender,
            })
            .await?;

        let CreatedSubscription {
            subscription_id,
            receiver,
        } = result_receiver.await??;

        Ok(TopicSubscription {
            topic: Some(topic),
            subscription_id,
            command_sender: Some(self.shared.command_sender.clone()),
            receiver,
        })
    }

    pub async fn publish(&self, topic: Sha256Topic, message: Vec<u8>) -> Result<(), PublishError> {
        let (result_sender, result_receiver) = oneshot::channel();

        self.shared
            .command_sender
            .clone()
            .send(Command::Publish {
                topic,
                message,
                result_sender,
            })
            .await?;

        result_receiver.await?.map_err(PublishError::Publish)
    }

    // Sends the generic request to the peer and awaits the result.
    pub async fn send_generic_request<Request>(
        &self,
        peer_id: PeerId,
        request: Request,
    ) -> Result<Request::Response, SendRequestError>
    where
        Request: GenericRequest,
    {
        let (result_sender, result_receiver) = oneshot::channel();
        let command = Command::GenericRequest {
            peer_id,
            protocol_name: Request::PROTOCOL_NAME,
            request: request.encode(),
            result_sender,
        };

        self.shared.command_sender.clone().send(command).await?;

        let result = result_receiver.await??;

        Request::Response::decode(&mut result.as_slice()).map_err(Into::into)
    }

    /// Get closest peers by multihash key using Kademlia DHT.
    pub async fn get_closest_peers(
        &self,
        key: Multihash,
    ) -> Result<Vec<PeerId>, GetClosestPeersError> {
        trace!(?key, "Starting 'GetClosestPeers' request.");

        let (result_sender, result_receiver) = oneshot::channel();

        self.shared
            .command_sender
            .clone()
            .send(Command::GetClosestPeers { key, result_sender })
            .await?;

        let peers = result_receiver.await?;

        trace!("Kademlia 'GetClosestPeers' returned {} peers", peers.len());

        Ok(peers)
    }

    /// Node's own addresses where it listens for incoming requests.
    pub fn listeners(&self) -> Vec<Multiaddr> {
        self.shared.listeners.lock().clone()
    }

    /// Callback is called when node starts listening on new address.
    pub fn on_new_listener(
        &self,
        callback: Arc<dyn Fn(&Multiaddr) + Send + Sync + 'static>,
    ) -> HandlerId {
        self.shared.handlers.new_listener.add(callback)
    }
}

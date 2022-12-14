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
use libp2p::{Multiaddr, PeerId};
use parity_scale_codec::Decode;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::sleep;
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
    _permit: OwnedSemaphorePermit,
}

impl Stream for TopicSubscription {
    type Item = Bytes;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
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
pub enum PutValueError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
}

impl From<oneshot::Canceled> for PutValueError {
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
pub enum CheckConnectedPeersError {
    /// Node runner was dropped, impossible to check connected peers.
    #[error("Node runner was dropped, impossible to check connected peers")]
    NodeRunnerDropped,
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
pub enum GetProvidersError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
    /// Failed to get providers.
    #[error("Failed to get providers.")]
    GetProviders,
}

impl From<oneshot::Canceled> for GetProvidersError {
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::NodeRunnerDropped
    }
}

#[derive(Debug, Error)]
pub enum AnnounceError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
}

impl From<oneshot::Canceled> for AnnounceError {
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::NodeRunnerDropped
    }
}

#[derive(Debug, Error)]
pub enum StopAnnouncingError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
    /// Failed to stop announcing an item.
    #[error("Failed to stop announcing an item.")]
    StopAnnouncing,
}

impl From<oneshot::Canceled> for StopAnnouncingError {
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
    kademlia_tasks_semaphore: Arc<Semaphore>,
    regular_tasks_semaphore: Arc<Semaphore>,
}

impl Node {
    pub(crate) fn new(
        shared: Arc<Shared>,
        kademlia_tasks_semaphore: Arc<Semaphore>,
        regular_tasks_semaphore: Arc<Semaphore>,
    ) -> Self {
        Self {
            shared,
            kademlia_tasks_semaphore,
            regular_tasks_semaphore,
        }
    }

    /// Node's own local ID.
    pub fn id(&self) -> PeerId {
        self.shared.id
    }

    pub async fn get_value(
        &self,
        key: Multihash,
    ) -> Result<impl Stream<Item = Vec<u8>>, GetValueError> {
        let permit = self
            .kademlia_tasks_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("We never close a semaphore; qed");
        let (result_sender, result_receiver) = mpsc::unbounded();

        self.shared
            .command_sender
            .clone()
            .send(Command::GetValue {
                key,
                result_sender,
                permit,
            })
            .await?;

        // TODO: A wrapper that'll immediately cancel query on drop
        Ok(result_receiver)
    }

    pub async fn put_value(
        &self,
        key: Multihash,
        value: Vec<u8>,
    ) -> Result<impl Stream<Item = ()>, PutValueError> {
        let permit = self
            .kademlia_tasks_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("We never close a semaphore; qed");
        let (result_sender, result_receiver) = mpsc::unbounded();

        self.shared
            .command_sender
            .clone()
            .send(Command::PutValue {
                key,
                value,
                result_sender,
                permit,
            })
            .await?;

        // TODO: A wrapper that'll immediately cancel query on drop
        Ok(result_receiver)
    }

    pub async fn subscribe(&self, topic: Sha256Topic) -> Result<TopicSubscription, SubscribeError> {
        let permit = self
            .regular_tasks_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("We never close a semaphore; qed");
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
            _permit: permit,
        })
    }

    pub async fn publish(&self, topic: Sha256Topic, message: Vec<u8>) -> Result<(), PublishError> {
        let _permit = self
            .regular_tasks_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("We never close a semaphore; qed");
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

    /// Sends the generic request to the peer and awaits the result.
    pub async fn send_generic_request<Request>(
        &self,
        peer_id: PeerId,
        request: Request,
    ) -> Result<Request::Response, SendRequestError>
    where
        Request: GenericRequest,
    {
        // TODO: Cancelling this method's future will drop the permit, but will not abort the
        //  request if it is already initiated
        let _permit = self
            .regular_tasks_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("We never close a semaphore; qed");
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
    ) -> Result<impl Stream<Item = PeerId>, GetClosestPeersError> {
        let permit = self
            .kademlia_tasks_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("We never close a semaphore; qed");
        trace!(?key, "Starting 'GetClosestPeers' request.");

        let (result_sender, result_receiver) = mpsc::unbounded();

        self.shared
            .command_sender
            .clone()
            .send(Command::GetClosestPeers {
                key,
                result_sender,
                permit,
            })
            .await?;

        // TODO: A wrapper that'll immediately cancel query on drop
        Ok(result_receiver)
    }

    // TODO: add timeout
    /// Waits for peers connection to the swarm and for Kademlia address registration.
    pub async fn wait_for_connected_peers(&self) -> Result<(), CheckConnectedPeersError> {
        loop {
            trace!("Starting 'CheckConnectedPeers' request.");

            let (result_sender, result_receiver) = oneshot::channel();

            self.shared
                .command_sender
                .clone()
                .send(Command::CheckConnectedPeers { result_sender })
                .await
                .map_err(|_| CheckConnectedPeersError::NodeRunnerDropped)?;

            let connected_peers_present = result_receiver
                .await
                .map_err(|_| CheckConnectedPeersError::NodeRunnerDropped)?;

            trace!("'CheckConnectedPeers' request returned {connected_peers_present}");

            if connected_peers_present {
                return Ok(());
            }

            sleep(Duration::from_millis(50)).await;
        }
    }

    /// Start announcing item by its key. Initiate 'start_providing' Kademlia operation.
    pub async fn start_announcing(
        &self,
        key: Multihash,
    ) -> Result<impl Stream<Item = ()>, AnnounceError> {
        let permit = self
            .kademlia_tasks_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("We never close a semaphore; qed");
        let (result_sender, result_receiver) = mpsc::unbounded();

        trace!(?key, "Starting 'start_announcing' request.");

        self.shared
            .command_sender
            .clone()
            .send(Command::StartAnnouncing {
                key,
                result_sender,
                permit,
            })
            .await?;

        // TODO: A wrapper that'll immediately cancel query on drop
        Ok(result_receiver)
    }

    /// Stop announcing item by its key. Initiate 'stop_providing' Kademlia operation.
    pub async fn stop_announcing(&self, key: Multihash) -> Result<(), StopAnnouncingError> {
        let (result_sender, result_receiver) = oneshot::channel();

        trace!(?key, "Starting 'stop_announcing' request.");

        self.shared
            .command_sender
            .clone()
            .send(Command::StopAnnouncing { key, result_sender })
            .await?;

        result_receiver
            .await?
            .then_some(())
            .ok_or(StopAnnouncingError::StopAnnouncing)
    }

    /// Get item providers by its key. Initiate 'providers' Kademlia operation.
    pub async fn get_providers(
        &self,
        key: Multihash,
    ) -> Result<impl Stream<Item = PeerId>, GetProvidersError> {
        let permit = self
            .kademlia_tasks_semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("We never close a semaphore; qed");
        let (result_sender, result_receiver) = mpsc::unbounded();

        trace!(?key, "Starting 'get_providers' request.");

        self.shared
            .command_sender
            .clone()
            .send(Command::GetProviders {
                key,
                result_sender,
                permit,
            })
            .await?;

        // TODO: A wrapper that'll immediately cancel query on drop
        Ok(result_receiver)
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

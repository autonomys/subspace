#[cfg(test)]
mod tests;

use crate::protocols::request_response::handlers::generic_request_handler::GenericRequest;
use crate::protocols::request_response::request_response_factory;
use crate::shared::{Command, PeerDiscovered, Shared};
use crate::utils::HandlerFn;
use crate::utils::multihash::Multihash;
use bytes::Bytes;
use event_listener_primitives::HandlerId;
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, Stream, StreamExt};
use libp2p::{Multiaddr, PeerId};
use parity_scale_codec::decode_from_bytes;
use std::sync::{Arc, Weak};
use thiserror::Error;
use tokio::sync::OwnedSemaphorePermit;
use tracing::{debug, trace};

/// Defines errors for `get-closest-peers` operation.
#[derive(Debug, Error)]
pub enum GetClosestPeersError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] mpsc::SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
}

impl From<oneshot::Canceled> for GetClosestPeersError {
    #[inline]
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::NodeRunnerDropped
    }
}

/// Defines errors for `get-closest-peers` operation.
#[derive(Debug, Error)]
pub enum GetClosestLocalPeersError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] mpsc::SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
}

impl From<oneshot::Canceled> for GetClosestLocalPeersError {
    #[inline]
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::NodeRunnerDropped
    }
}

/// Defines errors for `send-request` operation.
#[derive(Debug, Error)]
pub enum SendRequestError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] mpsc::SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
    /// Underlying protocol returned an error, impossible to get response.
    #[error("Underlying protocol returned an error: {0}")]
    ProtocolFailure(#[from] request_response_factory::RequestFailure),
    /// Underlying protocol returned an incorrect format, impossible to get response.
    #[error("Received incorrectly formatted response: {0}")]
    IncorrectResponseFormat(#[from] parity_scale_codec::Error),
}

impl From<oneshot::Canceled> for SendRequestError {
    #[inline]
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::NodeRunnerDropped
    }
}

#[derive(Debug, Error)]
pub enum ConnectedPeersError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] mpsc::SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
    /// Failed to get connected peers.
    #[error("Failed to get connected peers.")]
    ConnectedPeers,
}

impl From<oneshot::Canceled> for ConnectedPeersError {
    #[inline]
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::NodeRunnerDropped
    }
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    /// Failed to send command to the node runner
    #[error("Failed to send command to the node runner: {0}")]
    SendCommand(#[from] mpsc::SendError),
    /// Node runner was dropped
    #[error("Node runner was dropped")]
    NodeRunnerDropped,
    /// Failed to bootstrap a peer.
    #[error("Failed to bootstrap a peer.")]
    Bootstrap,
}

impl From<oneshot::Canceled> for BootstrapError {
    #[inline]
    fn from(oneshot::Canceled: oneshot::Canceled) -> Self {
        Self::NodeRunnerDropped
    }
}

/// Implementation of a network node on Subspace Network.
#[derive(Debug, Clone)]
#[must_use = "Node doesn't do anything if dropped"]
pub struct Node {
    shared: Arc<Shared>,
}

impl Node {
    pub(crate) fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }

    /// Node's own local ID.
    pub fn id(&self) -> PeerId {
        self.shared.id
    }

    async fn send_generic_request_internal<Request>(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: Request,
        acquire_permit: bool,
    ) -> Result<Request::Response, SendRequestError>
    where
        Request: GenericRequest,
    {
        let _permit = if acquire_permit {
            Some(self.shared.rate_limiter.acquire_permit().await)
        } else {
            None
        };

        let (result_sender, result_receiver) = oneshot::channel();
        let command = Command::GenericRequest {
            peer_id,
            addresses,
            protocol_name: Request::PROTOCOL_NAME,
            request: request.encode(),
            result_sender,
        };

        self.shared.command_sender.clone().send(command).await?;

        let result = result_receiver.await??;

        decode_from_bytes::<Request::Response>(Bytes::from(result)).map_err(Into::into)
    }

    /// Sends the generic request to the peer and awaits the result.
    ///
    /// Optional addresses will be used for dialing if connection to peer isn't established yet.
    pub async fn send_generic_request<Request>(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: Request,
    ) -> Result<Request::Response, SendRequestError>
    where
        Request: GenericRequest,
    {
        self.send_generic_request_internal(peer_id, addresses, request, true)
            .await
    }

    /// Get closest peers by multihash key using Kademlia DHT.
    pub async fn get_closest_peers(
        &self,
        key: Multihash,
    ) -> Result<impl Stream<Item = PeerId>, GetClosestPeersError> {
        self.get_closest_peers_internal(key, true).await
    }

    /// Get closest peers by multihash key using Kademlia DHT's local view without any network
    /// requests.
    ///
    /// Optional `source` is peer for which results will be sent as a response. Defaults to local
    /// peer ID.
    pub async fn get_closest_local_peers(
        &self,
        key: Multihash,
        source: Option<PeerId>,
    ) -> Result<Vec<(PeerId, Vec<Multiaddr>)>, GetClosestLocalPeersError> {
        let (result_sender, result_receiver) = oneshot::channel();

        self.shared
            .command_sender
            .clone()
            .send(Command::GetClosestLocalPeers {
                key,
                source,
                result_sender,
            })
            .await?;

        Ok(result_receiver.await?)
    }

    /// Get closest peers by multihash key using Kademlia DHT.
    async fn get_closest_peers_internal(
        &self,
        key: Multihash,
        acquire_permit: bool,
    ) -> Result<impl Stream<Item = PeerId>, GetClosestPeersError> {
        let permit = if acquire_permit {
            Some(self.shared.rate_limiter.acquire_permit().await)
        } else {
            None
        };

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

    /// Ban peer with specified peer ID.
    pub async fn ban_peer(&self, peer_id: PeerId) -> Result<(), mpsc::SendError> {
        self.shared
            .command_sender
            .clone()
            .send(Command::BanPeer { peer_id })
            .await
    }

    /// Dial multiaddress.
    /// It could be used to test libp2p transports bypassing protocol checks for bootstrap
    /// or listen-on addresses.
    #[doc(hidden)]
    pub async fn dial(&self, address: Multiaddr) -> Result<(), mpsc::SendError> {
        self.shared
            .command_sender
            .clone()
            .send(Command::Dial { address })
            .await
    }

    /// Node's own addresses where it listens for incoming requests.
    pub fn listeners(&self) -> Vec<Multiaddr> {
        self.shared.listeners.lock().clone()
    }

    /// Node's own addresses observed remotely.
    pub fn external_addresses(&self) -> Vec<Multiaddr> {
        self.shared.external_addresses.lock().clone()
    }

    /// Callback is called when node starts listening on new address.
    pub fn on_new_listener(&self, callback: HandlerFn<Multiaddr>) -> HandlerId {
        self.shared.handlers.new_listener.add(callback)
    }

    /// Callback is called when number of established peer connections changes.
    pub fn on_num_established_peer_connections_change(
        &self,
        callback: HandlerFn<usize>,
    ) -> HandlerId {
        self.shared
            .handlers
            .num_established_peer_connections_change
            .add(callback)
    }

    /// Returns a collection of currently connected peers.
    pub async fn connected_peers(&self) -> Result<Vec<PeerId>, ConnectedPeersError> {
        let (result_sender, result_receiver) = oneshot::channel();

        trace!("Starting `connected_peers` request");

        self.shared
            .command_sender
            .clone()
            .send(Command::ConnectedPeers { result_sender })
            .await?;

        result_receiver
            .await
            .map_err(|_| ConnectedPeersError::ConnectedPeers)
    }

    /// Returns a collection of currently connected servers (typically farmers).
    pub async fn connected_servers(&self) -> Result<Vec<PeerId>, ConnectedPeersError> {
        let (result_sender, result_receiver) = oneshot::channel();

        trace!("Starting `connected_servers` request.");

        self.shared
            .command_sender
            .clone()
            .send(Command::ConnectedServers { result_sender })
            .await?;

        result_receiver
            .await
            .map_err(|_| ConnectedPeersError::ConnectedPeers)
    }

    /// Bootstraps Kademlia network
    pub async fn bootstrap(&self) -> Result<(), BootstrapError> {
        let (result_sender, mut result_receiver) = mpsc::unbounded();

        debug!("Starting `bootstrap` request");

        self.shared
            .command_sender
            .clone()
            .send(Command::Bootstrap {
                result_sender: Some(result_sender),
            })
            .await?;

        for step in 0.. {
            let result = result_receiver.next().await;

            if result.is_some() {
                debug!(%step, "Kademlia bootstrapping...");
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Callback is called when a peer is connected.
    pub fn on_connected_peer(&self, callback: HandlerFn<PeerId>) -> HandlerId {
        self.shared.handlers.connected_peer.add(callback)
    }

    /// Callback is called when a peer is disconnected.
    pub fn on_disconnected_peer(&self, callback: HandlerFn<PeerId>) -> HandlerId {
        self.shared.handlers.disconnected_peer.add(callback)
    }

    /// Callback is called when a routable or unraoutable peer is discovered.
    pub fn on_discovered_peer(&self, callback: HandlerFn<PeerDiscovered>) -> HandlerId {
        self.shared.handlers.peer_discovered.add(callback)
    }

    /// Returns the request batch handle with common "connection permit" slot from the shared pool.
    pub async fn get_requests_batch_handle(&self) -> NodeRequestsBatchHandle {
        let _permit = self.shared.rate_limiter.acquire_permit().await;

        NodeRequestsBatchHandle {
            _permit,
            node: self.clone(),
        }
    }

    /// Downgrade to [`WeakNode`]
    pub fn downgrade(&self) -> WeakNode {
        WeakNode {
            shared: Arc::downgrade(&self.shared),
        }
    }
}

/// Weak counterpart of [`Node`]
#[derive(Debug, Clone)]
pub struct WeakNode {
    shared: Weak<Shared>,
}

impl WeakNode {
    /// Try to upgrade to [`Node`]
    pub fn upgrade(&self) -> Option<Node> {
        self.shared.upgrade().map(|shared| Node { shared })
    }
}

/// Requests handle for node operations. These operations share the same semaphore permit for
/// connection and substream limits. It generally serves for the case when we have
/// `get-closest-peers` operation followed by request-responses. This way we likely share the same
/// connection and we don't need to obtain separate semaphore permits for the operations.
pub struct NodeRequestsBatchHandle {
    node: Node,
    _permit: OwnedSemaphorePermit,
}

impl NodeRequestsBatchHandle {
    /// Get closest peers by key. Initiate 'find_node' Kademlia operation.
    pub async fn get_closest_peers(
        &self,
        key: Multihash,
    ) -> Result<impl Stream<Item = PeerId>, GetClosestPeersError> {
        self.node.get_closest_peers_internal(key, false).await
    }
    /// Sends the generic request to the peer and awaits the result.
    ///
    /// Optional addresses will be used for dialing if connection to peer isn't established yet.
    pub async fn send_generic_request<Request>(
        &self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
        request: Request,
    ) -> Result<Request::Response, SendRequestError>
    where
        Request: GenericRequest,
    {
        self.node
            .send_generic_request_internal(peer_id, addresses, request, false)
            .await
    }
}

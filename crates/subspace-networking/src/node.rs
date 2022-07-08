use crate::pieces_by_range_handler::{PiecesByRangeRequest, PiecesByRangeResponse, PiecesToPlot};
use crate::shared::{Command, CreatedSubscription, Shared};
use crate::RelayConfiguration;
use bytes::Bytes;
use event_listener_primitives::HandlerId;
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, Stream};
use libp2p::core::multihash::{Code, Multihash};
use libp2p::gossipsub::error::SubscriptionError;
use libp2p::gossipsub::Sha256Topic;
use libp2p::multiaddr::Protocol;
use libp2p::multihash::MultihashDigest;
use libp2p::{Multiaddr, PeerId};
use parity_scale_codec::Decode;
use parking_lot::Mutex;
use std::ops::Div;
use std::sync::Arc;
use subspace_core_primitives::{PieceIndexHash, U256};
use thiserror::Error;
use tracing::{debug, error, trace, warn};

const PIECES_CHANNEL_BUFFER_SIZE: usize = 20;

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
    /// Node runner was dropped, impossible to get value.
    #[error("Node runner was dropped, impossible to get value")]
    NodeRunnerDropped,
}

#[derive(Debug, Error)]
pub enum SubscribeError {
    /// Node runner was dropped, impossible to subscribe.
    #[error("Node runner was dropped, impossible to get value")]
    NodeRunnerDropped,
    /// Failed to create subscription.
    #[error("Failed to create subscription: {0}")]
    Subscription(#[from] SubscriptionError),
}

#[derive(Debug, Error)]
pub enum PublishError {
    /// Node runner was dropped, impossible to publish.
    #[error("Node runner was dropped, impossible to get value")]
    NodeRunnerDropped,
    /// Failed to publish message.
    #[error("Failed to publish message: {0}")]
    Publish(#[from] libp2p::gossipsub::error::PublishError),
}

#[derive(Debug, Error)]
pub enum GetPiecesByRangeError {
    /// Cannot find closest pieces by range.
    #[error("Cannot find closest pieces by range")]
    NoClosestPiecesFound,
    /// Node runner was dropped, impossible to get pieces by range.
    #[error("Node runner was dropped, impossible to get pieces by range")]
    NodeRunnerDropped,
}
#[derive(Debug, Error)]
pub enum SendPiecesByRangeRequestError {
    /// Node runner was dropped, impossible to send 'pieces-by-range' request.
    #[error("Node runner was dropped, impossible to send 'pieces-by-range' request")]
    NodeRunnerDropped,
    /// Underlying protocol returned an error, impossible to get 'pieces-by-range' response.
    #[error("Underlying protocol returned an error, impossible to get 'pieces-by-range' response")]
    ProtocolFailure,
    /// Underlying protocol returned an incorrect format, impossible to get 'pieces-by-range' response.
    #[error("Underlying protocol returned an incorrect format, impossible to get 'pieces-by-range' response")]
    IncorrectResponseFormat,
}

#[derive(Debug, Error)]
pub enum RelayConfigurationError {
    /// Client configuration error: expected server parent configuration.
    #[error("cannot configure relay client, parent configuration should be server")]
    ExpectedServerConfiguration,
    /// Failed to retrieve memory address, typically means networking was destroyed.
    #[error("Failed to retrieve memory address")]
    FailedToRetrieveMemoryAddress,
}

/// Implementation of a network node on Subspace Network.
#[derive(Debug, Clone)]
pub struct Node {
    shared: Arc<Shared>,
    is_relay_server: bool,
    relay_server_memory_address: Arc<Mutex<Option<Multiaddr>>>,
}

impl Node {
    pub(crate) fn new(shared: Arc<Shared>, is_relay_server: bool) -> Self {
        Self {
            shared,
            is_relay_server,
            relay_server_memory_address: Arc::new(Mutex::new(None)),
        }
    }

    /// Node's own local ID.
    pub fn id(&self) -> PeerId {
        self.shared.id
    }

    /// Configures relay-client configuration (ClientAcceptor) from this Node. It expects Node
    /// running in the relay server mode and create relay client's listening address with the proper
    /// circuit address in the format: /memory/50000/p2p/<server_peer_id>/p2p-circuit
    pub async fn configure_relay_client(
        &self,
    ) -> Result<RelayConfiguration, RelayConfigurationError> {
        if !self.is_relay_server {
            return Err(RelayConfigurationError::ExpectedServerConfiguration);
        }

        // Fast path in case address is already known
        if let Some(relay_server_memory_address) = self.relay_server_memory_address.lock().as_ref()
        {
            return Ok(RelayConfiguration::ClientAcceptor(
                relay_server_memory_address
                    .clone()
                    .with(Protocol::P2p(self.id().into()))
                    .with(Protocol::P2pCircuit),
            ));
        }

        let (address_sender, address_receiver) = oneshot::channel();
        let _handler = self.on_new_listener(Arc::new({
            let address_sender = Mutex::new(Some(address_sender));

            move |address| {
                if let Some(Protocol::Memory(port)) = address.iter().next() {
                    if let Some(address_sender) = address_sender.lock().take() {
                        let _ = address_sender.send(Multiaddr::from(Protocol::Memory(port)));
                    }
                }
            }
        }));

        // Subscription to events is in place, check if listener is already known
        for address in self.shared.listeners.lock().iter() {
            if let Some(Protocol::Memory(port)) = address.iter().next() {
                let address = Multiaddr::from(Protocol::Memory(port));
                self.relay_server_memory_address
                    .lock()
                    .replace(address.clone());

                return Ok(RelayConfiguration::ClientAcceptor(
                    address
                        .with(Protocol::P2p(self.id().into()))
                        .with(Protocol::P2pCircuit),
                ));
            }
        }

        // Otherwise for new memory listener
        let address = address_receiver
            .await
            .map_err(|_error| RelayConfigurationError::FailedToRetrieveMemoryAddress)?;

        self.relay_server_memory_address
            .lock()
            .replace(address.clone());

        Ok(RelayConfiguration::ClientAcceptor(
            address
                .with(Protocol::P2p(self.id().into()))
                .with(Protocol::P2pCircuit),
        ))
    }

    pub async fn get_value(&self, key: Multihash) -> Result<Option<Vec<u8>>, GetValueError> {
        let (result_sender, result_receiver) = oneshot::channel();

        self.shared
            .command_sender
            .clone()
            .send(Command::GetValue { key, result_sender })
            .await
            .map_err(|_error| GetValueError::NodeRunnerDropped)?;

        result_receiver
            .await
            .map_err(|_error| GetValueError::NodeRunnerDropped)
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
            .await
            .map_err(|_error| SubscribeError::NodeRunnerDropped)?;

        let CreatedSubscription {
            subscription_id,
            receiver,
        } = result_receiver
            .await
            .map_err(|_error| SubscribeError::NodeRunnerDropped)?
            .map_err(SubscribeError::Subscription)?;

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
            .await
            .map_err(|_error| PublishError::NodeRunnerDropped)?;

        result_receiver
            .await
            .map_err(|_error| PublishError::NodeRunnerDropped)?
            .map_err(PublishError::Publish)
    }

    // Sends the request to the peer and awaits the result.
    pub async fn send_pieces_by_range_request(
        &self,
        peer_id: PeerId,
        request: PiecesByRangeRequest,
    ) -> Result<PiecesByRangeResponse, SendPiecesByRangeRequestError> {
        let (result_sender, result_receiver) = oneshot::channel();

        self.shared
            .command_sender
            .clone()
            .send(Command::PiecesByRangeRequest {
                request,
                result_sender,
                peer_id,
            })
            .await
            .map_err(|_| SendPiecesByRangeRequestError::NodeRunnerDropped)?;

        let result = result_receiver
            .await
            .map_err(|_| SendPiecesByRangeRequestError::NodeRunnerDropped)?
            .map_err(|_| SendPiecesByRangeRequestError::ProtocolFailure)?;

        PiecesByRangeResponse::decode(&mut result.as_slice())
            .map_err(|_| SendPiecesByRangeRequestError::IncorrectResponseFormat)
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

    /// The method requests the DSN and returns a stream with `Piece` items.
    /// It looks for the suitable peer for the provided `PieceIndexHash` range by
    /// searching the underlying Kademlia network for the PeerId closest
    /// (by XOR-metric) to the middle of the range. After that it requests the
    /// peer for data in portions. The portion size must be defined by the peer,
    /// however it's indirectly limited by the response size of the underlying
    /// protocol.
    pub async fn get_pieces_by_range(
        &self,
        from: PieceIndexHash,
        to: PieceIndexHash,
    ) -> Result<mpsc::Receiver<PiecesToPlot>, GetPiecesByRangeError> {
        let (result_sender, result_receiver) = oneshot::channel();

        // calculate the middle of the range (big endian)
        let middle = {
            let from = U256::from_big_endian(&from.0);
            let to = U256::from_big_endian(&to.0);
            // min + (max - min) / 2
            let middle = from.div(2) + to.div(2);
            let mut buf: [u8; 32] = [0; 32];
            middle.to_big_endian(&mut buf);
            buf
        };

        // obtain closest peers to the middle of the range
        self.shared
            .command_sender
            .clone()
            .send(Command::GetClosestPeers {
                key: Code::Identity.digest(&middle),
                result_sender,
            })
            .await
            .map_err(|_| GetPiecesByRangeError::NodeRunnerDropped)?;

        let peers = result_receiver
            .await
            .map_err(|_| GetPiecesByRangeError::NodeRunnerDropped)?;

        trace!("Kademlia 'GetClosestPeers' returned {} peers", peers.len());

        // select first peer for the piece-by-range protocol
        let peer_id = *peers
            .first()
            .ok_or(GetPiecesByRangeError::NoClosestPiecesFound)?;

        trace!(%peer_id, "Peer found. Range: {:?} - {:?} ", from, to);

        // prepare stream channel
        let (mut tx, rx) = mpsc::channel::<PiecesToPlot>(PIECES_CHANNEL_BUFFER_SIZE);

        // populate resulting stream in a separate async task
        let node = self.clone();
        tokio::spawn(async move {
            // indicates the next starting point for a request
            let mut starting_index_hash = from;
            loop {
                trace!(
                    "Sending 'Piece-by-range' request to {} with {:?}",
                    peer_id,
                    starting_index_hash
                );
                // request data by range
                let response = node
                    .send_pieces_by_range_request(
                        peer_id,
                        PiecesByRangeRequest {
                            from: starting_index_hash,
                            to,
                        },
                    )
                    .await
                    .map_err(|_| SendPiecesByRangeRequestError::NodeRunnerDropped);

                // send the result to the stream and exit on any error
                match response {
                    Ok(PiecesByRangeResponse {
                        pieces,
                        next_piece_index_hash,
                    }) => {
                        // send last response data stream to the result stream
                        if !pieces.piece_indexes.is_empty() && tx.send(pieces).await.is_err() {
                            warn!("Piece-by-range request channel was closed.");
                            break;
                        }

                        // prepare the next starting point for data
                        if let Some(next_piece_index_hash) = next_piece_index_hash {
                            debug_assert_ne!(starting_index_hash, next_piece_index_hash);
                            starting_index_hash = next_piece_index_hash;
                        } else {
                            // exit loop if the last response showed no remaining data
                            break;
                        }
                    }
                    Err(err) => {
                        debug!("Piece-by-range request returned an error: {}", err);
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }
}

use crate::pieces_by_range_handler::{PiecesByRangeRequest, PiecesByRangeResponse};
use crate::shared::{Command, CreatedSubscription, ExactKademliaKey, Shared};
use bytes::Bytes;
use event_listener_primitives::HandlerId;
use futures::channel::{mpsc, oneshot};
use futures::{stream, SinkExt, Stream};
use libp2p::core::multihash::Multihash;
use libp2p::gossipsub::error::SubscriptionError;
use libp2p::gossipsub::Sha256Topic;
use libp2p::{Multiaddr, PeerId};
use parity_scale_codec::Decode;
use std::ops::{Deref, DerefMut, Div};
use std::pin::Pin;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndexHash, U256};
use thiserror::Error;
use tracing::{debug, error, trace, warn};

/// Topic subscription, will unsubscribe when last instance is dropped for a particular topic.
#[derive(Debug)]
pub struct TopicSubscription {
    topic: Option<Sha256Topic>,
    subscription_id: usize,
    command_sender: Option<mpsc::Sender<Command>>,
    receiver: mpsc::UnboundedReceiver<Bytes>,
}

impl Deref for TopicSubscription {
    type Target = mpsc::UnboundedReceiver<Bytes>;

    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}

impl DerefMut for TopicSubscription {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.receiver
    }
}

impl Drop for TopicSubscription {
    fn drop(&mut self) {
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

/// Implementation of a network node on Subspace Network.
#[derive(Debug, Clone)]
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
        Node::send_pieces_by_range_request_inner(self.shared.clone(), peer_id, request).await
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
    ) -> Result<Pin<Box<dyn Stream<Item = Piece>>>, GetPiecesByRangeError> {
        let (result_sender, result_receiver) = oneshot::channel();

        // calculate the middle of the range
        let f = U256::from_big_endian(&from.0);
        let t = U256::from_big_endian(&to.0);
        // min + (max - min) / 2
        let middle = f.div(2) + t.div(2);
        let mut buf: [u8; 32] = [0; 32]; // 32 of hash + 32 of preimage
        middle.to_big_endian(&mut buf);

        // obtain closest peers to the middle of the range
        self.shared
            .command_sender
            .clone()
            .send(Command::GetClosestPeers {
                key: ExactKademliaKey::new(buf),
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

        // prepare stream channel
        const BUFFER_SIZE: usize = 1000; // approximately 4MB
        let (mut tx, rx) = mpsc::channel::<Piece>(BUFFER_SIZE);

        // populate resulting stream in the separate async task
        let shared = self.shared.clone();
        tokio::spawn(async move {
            // indicates the next starting point for a request, initially None
            let mut next_piece_hash_index = None;
            loop {
                trace!(
                    "Sending 'Piece-by-range' request to {} with {:?}",
                    peer_id,
                    next_piece_hash_index
                );
                // request data by range and starting point
                let response = Node::send_pieces_by_range_request_inner(
                    shared.clone(),
                    peer_id,
                    PiecesByRangeRequest {
                        from,
                        to,
                        next_piece_hash_index,
                    },
                )
                .await
                .map_err(|_| SendPiecesByRangeRequestError::NodeRunnerDropped);

                // send the result to the stream and exit on any error
                match response {
                    Ok(response) => {
                        // convert response data to the stream
                        let mut chunk_stream = stream::iter(response.pieces.into_iter().map(Ok));

                        // send last response data stream to the result stream
                        if tx.send_all(&mut chunk_stream).await.is_err() {
                            warn!("Piece-by-range request channel was closed.");
                            break;
                        }

                        // prepare next starting point for data
                        next_piece_hash_index = response.next_piece_hash_index
                    }
                    Err(err) => {
                        debug!("Piece-by-range request returned an error: {}", err);
                        break;
                    }
                }

                // exit loop if the last response showed no remaining data
                if next_piece_hash_index.is_none() {
                    break;
                }
            }
        });

        Ok(Box::pin(rx))
    }

    // Sends the request to the peer and awaits the result.
    // Actual pieces-by-range implementation.
    async fn send_pieces_by_range_request_inner(
        shared: Arc<Shared>,
        peer_id: PeerId,
        request: PiecesByRangeRequest,
    ) -> Result<PiecesByRangeResponse, SendPiecesByRangeRequestError> {
        let (result_sender, result_receiver) = oneshot::channel();

        shared
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
}

#[cfg(test)]
mod test {
    use crate::{Config, PiecesByRangeResponse};
    use futures::channel::mpsc;
    use futures::StreamExt;
    use libp2p::multiaddr::Protocol;
    use std::sync::Arc;
    use std::time::Duration;
    use subspace_core_primitives::{crypto, Piece, PieceIndexHash};

    #[tokio::test]
    async fn get_pieces_by_range_protocol_smoke() {
        let piece = Piece::default();
        let expected_piece = piece.clone();

        let config_1 = Config {
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            allow_non_globals_in_dht: true,
            pieces_by_range_request_handler: Arc::new(move |_| {
                Some(PiecesByRangeResponse {
                    pieces: vec![piece.clone()],
                    next_piece_hash_index: None,
                })
            }),
            ..Config::with_generated_keypair()
        };
        let (node_1, node_runner_1) = crate::create(config_1).await.unwrap();

        let (node_1_addresses_sender, mut node_1_addresses_receiver) = mpsc::unbounded();
        node_1
            .on_new_listener(Arc::new(move |address| {
                node_1_addresses_sender
                    .unbounded_send(address.clone())
                    .unwrap();
            }))
            .detach();

        tokio::spawn(async move {
            node_runner_1.run().await;
        });

        let config_2 = Config {
            bootstrap_nodes: vec![node_1_addresses_receiver
                .next()
                .await
                .unwrap()
                .with(Protocol::P2p(node_1.id().into()))],
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            allow_non_globals_in_dht: true,
            ..Config::with_generated_keypair()
        };

        let (node_2, node_runner_2) = crate::create(config_2).await.unwrap();
        tokio::spawn(async move {
            node_runner_2.run().await;
        });

        tokio::time::sleep(Duration::from_secs(1)).await;

        let hashed_peer_id = PieceIndexHash(crypto::sha256_hash(&node_1.id().to_bytes()));

        let mut stream = node_2
            .get_pieces_by_range(hashed_peer_id, hashed_peer_id)
            .await
            .unwrap();

        let result = stream.next().await;

        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(result.unwrap(), expected_piece);
    }
}

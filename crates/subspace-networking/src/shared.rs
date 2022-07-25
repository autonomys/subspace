//! Data structures shared between node and node runner, facilitating exchange and creation of
//! queries, subscriptions, various events and shared information.

use crate::node::Node;
use crate::request_responses::RequestFailure;
use bytes::Bytes;
use event_listener_primitives::Bag;
use futures::channel::{mpsc, oneshot};
use generic_array::GenericArray;
use libp2p::core::multihash::Multihash;
use libp2p::gossipsub::error::{PublishError, SubscriptionError};
use libp2p::gossipsub::Sha256Topic;
use libp2p::kad::kbucket::{KeyBytes, PreimageIntoKeyBytes};
use libp2p::kad::record;
use libp2p::multihash::{Code, MultihashDigest};
use libp2p::{identity, Multiaddr, PeerId};
use parking_lot::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use subspace_core_primitives::crypto::sha256_hash;
use subspace_core_primitives::PUBLIC_KEY_LENGTH;
use typenum::U32;

#[derive(Debug)]
pub(crate) struct CreatedSubscription {
    /// Subscription ID to be used for unsubscribing.
    pub(crate) subscription_id: usize,
    /// Receiver side of the channel with new messages.
    pub(crate) receiver: mpsc::UnboundedReceiver<Bytes>,
}

#[derive(Debug)]
pub(crate) enum Command {
    GetValue {
        key: Multihash,
        result_sender: oneshot::Sender<Option<Vec<u8>>>,
    },
    Subscribe {
        topic: Sha256Topic,
        result_sender: oneshot::Sender<Result<CreatedSubscription, SubscriptionError>>,
    },
    Unsubscribe {
        topic: Sha256Topic,
        subscription_id: usize,
    },
    Publish {
        topic: Sha256Topic,
        message: Vec<u8>,
        result_sender: oneshot::Sender<Result<(), PublishError>>,
    },
    GetClosestPeers {
        key: Multihash,
        result_sender: oneshot::Sender<Vec<PeerId>>,
    },
    GenericRequest {
        peer_id: PeerId,
        protocol_name: &'static str,
        request: Vec<u8>,
        result_sender: oneshot::Sender<Result<Vec<u8>, RequestFailure>>,
    },
}

#[derive(Default, Debug)]
pub(crate) struct Handlers {
    #[allow(clippy::type_complexity)]
    pub(crate) new_listener: Bag<Arc<dyn Fn(&Multiaddr) + Send + Sync + 'static>, Multiaddr>,
}

#[derive(Debug)]
pub(crate) struct Shared {
    pub(crate) handlers: Handlers,
    pub(crate) id: PeerId,
    /// Addresses on which node is listening for incoming requests.
    pub(crate) listeners: Mutex<Vec<Multiaddr>>,
    pub(crate) connected_peers_count: AtomicUsize,
    /// Sender end of the channel for sending commands to the swarm.
    pub(crate) command_sender: mpsc::Sender<Command>,
    /// Sender which would stop the corresponding node runner.
    pub(crate) stop_sender: Mutex<Option<oneshot::Sender<()>>>,
    /// Parent node instance (if any) to keep alive.
    ///
    /// This is needed to ensure relay server doesn't stop, cutting this node from ability to
    /// receive incoming connections.
    pub(crate) _parent_node: Option<Node>,
}

impl Shared {
    pub(crate) fn new(
        id: PeerId,
        parent_node: Option<Node>,
        command_sender: mpsc::Sender<Command>,
        stop_sender: oneshot::Sender<()>,
    ) -> Self {
        Self {
            handlers: Handlers::default(),
            id,
            listeners: Mutex::default(),
            connected_peers_count: AtomicUsize::new(0),
            command_sender,
            stop_sender: Mutex::new(Some(stop_sender)),
            _parent_node: parent_node,
        }
    }
}

// Supports exact keys for Kademlia. It uses the Multihash as the canonical type
// and reduces all the conversions to Multihash conversion.
// It supports only Sr25519 key pairs for PeerId and Identity multihashes.
#[derive(Clone, Debug)]
pub struct IdendityHash(GenericArray<u8, U32>);

impl PreimageIntoKeyBytes<Multihash> for IdendityHash {
    fn preimage_into_key_bytes(multihash: &Multihash) -> KeyBytes<Self> {
        // Identity hasher for 32-bytes digest
        if multihash.code() == u64::from(Code::Identity)
            && multihash.digest().len() == PUBLIC_KEY_LENGTH
        {
            let array = GenericArray::from_slice(multihash.digest());
            return KeyBytes::from_unchecked(*array);
        }

        // MultihashCode::Piece, MultihashCode::PieceIndex are hashed with the
        // SHA256 similar to unknown multihash types.
        default_key_bytes_conversion(&multihash.to_bytes())
    }
}

impl PreimageIntoKeyBytes<PeerId> for IdendityHash {
    fn preimage_into_key_bytes(peer_id: &PeerId) -> KeyBytes<Self> {
        let multihash: Multihash = if let Ok(public_key) =
            identity::PublicKey::from_protobuf_encoding(peer_id.as_ref().digest())
        {
            if let identity::PublicKey::Sr25519(pk) = public_key {
                Code::Identity.digest(&pk.encode())
            } else {
                // Unsupported public key type. Expected Sr25519
                return default_key_bytes_conversion(&peer_id.to_bytes());
            }
        } else {
            // No protobuf encoding: it's PeerId::random()
            (*peer_id).into()
        };

        PreimageIntoKeyBytes::<Multihash>::preimage_into_key_bytes(&multihash)
    }
}

impl PreimageIntoKeyBytes<record::Key> for IdendityHash {
    fn preimage_into_key_bytes(record_key: &record::Key) -> KeyBytes<Self> {
        let bytes = &record_key.to_vec();

        if let Ok(multihash) = Multihash::from_bytes(bytes) {
            PreimageIntoKeyBytes::<Multihash>::preimage_into_key_bytes(&multihash)
        } else {
            // Not multihash record key.
            default_key_bytes_conversion(bytes)
        }
    }
}

impl PreimageIntoKeyBytes<Vec<u8>> for IdendityHash {
    fn preimage_into_key_bytes(bytes: &Vec<u8>) -> KeyBytes<Self> {
        if let Ok(multihash) = Multihash::from_bytes(bytes) {
            PreimageIntoKeyBytes::<Multihash>::preimage_into_key_bytes(&multihash)
        } else {
            // Not multihash vector.
            default_key_bytes_conversion(bytes)
        }
    }
}

// Default KeyBytes converter. It hashes bytes with Sha256 similar to the
// default Kademlia's `PreimageIntoKeyBytes` implementation.
#[inline]
fn default_key_bytes_conversion<T>(bytes: &[u8]) -> KeyBytes<T> {
    KeyBytes::from_unchecked(*GenericArray::from_slice(&sha256_hash(bytes)))
}

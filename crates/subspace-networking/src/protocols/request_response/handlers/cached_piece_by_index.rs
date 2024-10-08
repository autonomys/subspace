//! Helper for incoming cached piece requests.
//!
//! Request handler can be created with [`CachedPieceByIndexRequestHandler`].

use crate::protocols::request_response::handlers::generic_request_handler::{
    GenericRequest, GenericRequestHandler,
};
use derive_more::{Deref, DerefMut, From, Into};
use libp2p::kad::K_VALUE;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use multihash::Multihash;
use parity_scale_codec::{Compact, CompactLen, Decode, Encode, EncodeLike, Input, Output};
use subspace_core_primitives::pieces::{Piece, PieceIndex};

/// Cached-piece-by-index request.
///
/// This is similar to `PieceByIndexRequest`, but will only respond with cached pieces.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct CachedPieceByIndexRequest {
    /// Request key - piece index
    pub piece_index: PieceIndex,
    /// Additional pieces that requester is interested in if they are cached locally
    pub cached_pieces: Vec<PieceIndex>,
}

impl GenericRequest for CachedPieceByIndexRequest {
    const PROTOCOL_NAME: &'static str = "/subspace/cached-piece-by-index/0.1.0";
    const LOG_TARGET: &'static str = "cached-piece-by-index-request-response-handler";
    type Response = CachedPieceByIndexResponse;
}

/// Closest peers
#[derive(Debug, Default, PartialEq, Eq, Clone, From, Into, Deref, DerefMut)]
pub struct ClosestPeers(Vec<(PeerId, Vec<Multiaddr>)>);

impl Encode for ClosestPeers {
    fn size_hint(&self) -> usize {
        let mut size = Compact::compact_len(&(self.0.len() as u32));

        for (peer_id, addresses) in &self.0 {
            size += peer_id.as_ref().encoded_size();
            size += Compact::compact_len(&(addresses.len() as u32));

            for address in addresses {
                size += address.as_ref().encoded_size();
            }
        }

        size
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        Compact::from(self.0.len() as u32).encode_to(dest);

        for (peer_id, addresses) in &self.0 {
            peer_id.as_ref().encode_to(dest);
            Compact::from(addresses.len() as u32).encode_to(dest);

            for address in addresses {
                address.as_ref().encode_to(dest);
            }
        }
    }
}

impl EncodeLike for ClosestPeers {}

impl Decode for ClosestPeers {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let mut closest_peers = Vec::with_capacity(K_VALUE.get());

        let closest_peers_count = Compact::<u32>::decode(input)?.0 as usize;
        for _ in 0..closest_peers_count {
            let peer_id =
                PeerId::from_multihash(Multihash::decode(input)?).map_err(|multihash| {
                    parity_scale_codec::Error::from("Can't create `PeerId` from `Multihash`")
                        .chain(format!("Code: {}", multihash.code()))
                })?;
            let p2p = Multiaddr::from(Protocol::P2p(peer_id));
            let mut addresses = Vec::new();

            let addresses_count = Compact::<u32>::decode(input)?.0 as usize;

            for _ in 0..addresses_count {
                let address = Multiaddr::try_from(Vec::<u8>::decode(input)?).map_err(|error| {
                    parity_scale_codec::Error::from("Failed to decode `Multiaddr`")
                        .chain(error.to_string())
                })?;

                if !address.ends_with(&p2p) {
                    return Err(parity_scale_codec::Error::from(
                        "`Multiaddr` doesn't end with correct p2p suffix",
                    )
                    .chain(format!("Address {address}, PeerId {p2p}")));
                }

                addresses.push(address);
            }

            closest_peers.push((peer_id, addresses));
        }

        Ok(Self(closest_peers))
    }
}

/// Piece result contains either piece itself or the closest known peers to the piece index
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub enum PieceResult {
    /// Piece was cached locally
    Piece(Piece),
    /// Piece was not cached locally, but these are the closest known peers to the piece index
    ClosestPeers(ClosestPeers),
}

/// Cached-piece-by-index response, may be cached piece or stored in one of the farms
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct CachedPieceByIndexResponse {
    /// Piece result
    pub result: PieceResult,
    /// Additional pieces that requester is interested in and are cached locally, order from request
    /// is not preserved
    pub cached_pieces: Vec<PieceIndex>,
}

/// Cached-piece-by-index request handler
pub type CachedPieceByIndexRequestHandler = GenericRequestHandler<CachedPieceByIndexRequest>;

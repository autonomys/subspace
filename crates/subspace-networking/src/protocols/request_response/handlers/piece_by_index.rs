//! Helper for incoming piece requests.
//!
//! Request handler can be created with [`PieceByIndexRequestHandler`].

use crate::protocols::request_response::handlers::generic_request_handler::{
    GenericRequest, GenericRequestHandler,
};
use parity_scale_codec::{Decode, Encode};
use subspace_core_primitives::pieces::{Piece, PieceIndex};

/// Piece-by-index request
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct PieceByIndexRequest {
    /// Request key - piece index
    pub piece_index: PieceIndex,
    /// Additional pieces that requester is interested in if they are cached locally
    pub cached_pieces: Vec<PieceIndex>,
}

impl GenericRequest for PieceByIndexRequest {
    const PROTOCOL_NAME: &'static str = "/subspace/piece-by-index/0.1.0";
    const LOG_TARGET: &'static str = "piece-by-index-request-response-handler";
    type Response = PieceByIndexResponse;
}

impl PieceByIndexRequest {
    /// Max number of cached pieces to accept per request, equals to the number of source shards in
    /// a sector and fits nicely into a single TCP packet
    pub const RECOMMENDED_LIMIT: usize = 128;
}

/// Piece-by-index response, may be cached piece or stored in one of the farms
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct PieceByIndexResponse {
    /// Piece, if found
    pub piece: Option<Piece>,
    /// Additional pieces that requester is interested in and are cached locally, order from request
    /// is not preserved
    pub cached_pieces: Vec<PieceIndex>,
}

/// Piece-by-index request handler
pub type PieceByIndexRequestHandler = GenericRequestHandler<PieceByIndexRequest>;

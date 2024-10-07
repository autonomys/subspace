//! Helper for incoming cached piece requests.
//!
//! Request handler can be created with [`CachedPieceByIndexRequestHandler`].

use crate::protocols::request_response::handlers::generic_request_handler::{
    GenericRequest, GenericRequestHandler,
};
use parity_scale_codec::{Decode, Encode};
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

/// Cached-piece-by-index response, may be cached piece or stored in one of the farms
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct CachedPieceByIndexResponse {
    /// Piece, if found
    pub piece: Option<Piece>,
    /// Additional pieces that requester is interested in and are cached locally, order from request
    /// is not preserved
    pub cached_pieces: Vec<PieceIndex>,
}

/// Cached-piece-by-index request handler
pub type CachedPieceByIndexRequestHandler = GenericRequestHandler<CachedPieceByIndexRequest>;

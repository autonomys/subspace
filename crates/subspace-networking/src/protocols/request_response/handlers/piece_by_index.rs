//! Helper for incoming piece requests.
//!
//! Request handler can be created with [`PieceByIndexRequestHandler`].

use super::generic_request_handler::{GenericRequest, GenericRequestHandler};
use parity_scale_codec::{Decode, Encode};
use subspace_core_primitives::pieces::{Piece, PieceIndex};

/// Piece-by-index request
#[derive(Debug, Clone, Copy, Eq, PartialEq, Encode, Decode)]
pub struct PieceByIndexRequest {
    /// Request key - piece index
    pub piece_index: PieceIndex,
}

impl GenericRequest for PieceByIndexRequest {
    const PROTOCOL_NAME: &'static str = "/subspace/piece-by-index/0.1.0";
    const LOG_TARGET: &'static str = "piece-by-index-request-response-handler";
    type Response = PieceByIndexResponse;
}

/// Piece-by-index response, may be cached piece or stored in one of the farms
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct PieceByIndexResponse {
    /// Piece, if found
    pub piece: Option<Piece>,
}

/// Piece-by-index request handler
pub type PieceByIndexRequestHandler = GenericRequestHandler<PieceByIndexRequest>;

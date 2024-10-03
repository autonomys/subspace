//! Helper for incoming pieces requests.
//!
//! Handle (i.e. answer) incoming pieces requests from a remote peer received via
//! `RequestResponsesBehaviour` with generic [`GenericRequestHandler`].

use super::generic_request_handler::{GenericRequest, GenericRequestHandler};
use parity_scale_codec::{Decode, Encode};
use subspace_core_primitives::pieces::{Piece, PieceIndex};

/// Piece-by-hash protocol request.
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

/// Piece-by-hash protocol response.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct PieceByIndexResponse {
    /// Returned data.
    pub piece: Option<Piece>,
}

/// Create a new piece-by-hash request handler.
pub type PieceByIndexRequestHandler = GenericRequestHandler<PieceByIndexRequest>;

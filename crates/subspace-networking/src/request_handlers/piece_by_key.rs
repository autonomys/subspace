//! Helper for incoming pieces requests.
//!
//! Handle (i.e. answer) incoming pieces requests from a remote peer received via
//! `RequestResponsesBehaviour` with generic [`GenericRequestHandler`].

use crate::request_handlers::generic_request_handler::{GenericRequest, GenericRequestHandler};
use parity_scale_codec::{Decode, Encode};
use subspace_core_primitives::{Piece, PieceIndexHash};

/// Piece-by-hash protocol request.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct PieceByHashRequest {
    /// Request key - piece index hash
    pub piece_index_hash: PieceIndexHash,
}

impl GenericRequest for PieceByHashRequest {
    const PROTOCOL_NAME: &'static str = "/subspace/piece-by-hash/0.1.0";
    const LOG_TARGET: &'static str = "piece-by-hash-request-response-handler";
    type Response = PieceByHashResponse;
}

/// Piece-by-hash protocol response.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct PieceByHashResponse {
    /// Returned data.
    pub piece: Option<Piece>,
}

//TODO: remove attribute on the first usage
#[allow(dead_code)]
/// Create a new piece-by-hash request handler.
pub type PieceByHashRequestHandler = GenericRequestHandler<PieceByHashRequest>;

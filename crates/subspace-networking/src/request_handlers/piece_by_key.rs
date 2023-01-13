//! Helper for incoming pieces requests.
//!
//! Handle (i.e. answer) incoming pieces requests from a remote peer received via
//! `RequestResponsesBehaviour` with generic [`GenericRequestHandler`].

use crate::request_handlers::generic_request_handler::{GenericRequest, GenericRequestHandler};
use parity_scale_codec::{Decode, Encode};
use subspace_core_primitives::{Piece, PieceIndexHash};

//TODO: rename all module names if we keep this enum
#[derive(Debug, Clone, Eq, PartialEq, Copy, Encode, Decode)]
pub enum PieceKey {
    Cache(PieceIndexHash),
    ArchivalStorage(PieceIndexHash),
}

/// Piece-by-hash protocol request.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct PieceByHashRequest {
    //TODO: rename if we keep the enum
    /// Piece index hash
    pub key: PieceKey,
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

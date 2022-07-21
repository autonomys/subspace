//! Helper for incoming pieces-by-range requests.
//!
//! Handle (i.e. answer) incoming pieces-by-range requests from a remote peer received via
//! `crate::request_responses::RequestResponsesBehaviour` with generic
//! [`RequestHandler`](RequestHandler).

#[cfg(test)]
mod tests;

use crate::request_handlers::generic_request_handler::{GenericRequest, GenericRequestHandler};
use parity_scale_codec::{Decode, Encode};
use subspace_core_primitives::{FlatPieces, PieceIndex, PieceIndexHash};

/// Pieces-by-range-protocol name.
pub const PROTOCOL_NAME: &str = "/subspace/sync/pieces-by-range/0.1.0";
const LOG_TARGET: &str = "pieces-by-range-request-response-handler";

//TODO: A candidate for migrating to a separate crate.
/// Collection of pieces that potentially need to be plotted
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct PiecesToPlot {
    /// Piece indexes for each of the `pieces`
    pub piece_indexes: Vec<PieceIndex>,
    /// Pieces themselves
    pub pieces: FlatPieces,
}

/// Pieces-by-range protocol request. Assumes requests with paging.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct PiecesByRangeRequest {
    /// Start of the requested range
    pub from: PieceIndexHash,
    /// End of the requested range
    pub to: PieceIndexHash,
}

impl GenericRequest for PiecesByRangeRequest {
    const PROTOCOL_NAME: &'static str = PROTOCOL_NAME;
    const LOG_TARGET: &'static str = LOG_TARGET;
    type Response = PiecesByRangeResponse;
}

/// Pieces-by-range protocol response. Assumes requests with paging.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct PiecesByRangeResponse {
    /// Returned data.
    pub pieces: PiecesToPlot,
    /// Defines starting point (cursor) of the next request.
    /// None means no further data available.
    pub next_piece_index_hash: Option<PieceIndexHash>,
}

/// Create a new pieces-by-range request handler.
pub type PiecesByRangeRequestHandler = GenericRequestHandler<PiecesByRangeRequest>;

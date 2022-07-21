//! Helper for incoming pieces-by-range requests.
//!
//! Handle (i.e. answer) incoming pieces-by-range requests from a remote peer received via
//! `crate::request_responses::RequestResponsesBehaviour` with generic
//! [`RequestHandler`](RequestHandler).

#[cfg(test)]
mod tests;

use crate::request_handlers::generic_request_handler::{
    ExternalRequestHandler, GenericRequest, GenericRequestHandler, RequestHandlerConfig,
};
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

/// Type alias for the actual external request handler.
pub type ExternalPiecesByRangeRequestHandler = ExternalRequestHandler<PiecesByRangeRequest>;

/// Create a new object-mappings request handler.
pub(crate) fn new(
    request_handler: ExternalPiecesByRangeRequestHandler,
) -> GenericRequestHandler<PiecesByRangeRequest> {
    GenericRequestHandler::new(RequestHandlerConfig {
        protocol_name: PROTOCOL_NAME,
        log_target: LOG_TARGET,
        request_handler,
    })
}

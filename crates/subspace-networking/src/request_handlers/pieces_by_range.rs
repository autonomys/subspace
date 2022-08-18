use parity_scale_codec::{Decode, Encode};
use subspace_core_primitives::{FlatPieces, PieceIndex, PieceIndexHash};

use crate::{GenericRequest, GenericRequestHandler};

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
#[derive(Debug, Clone, Copy, Eq, PartialEq, Encode, Decode)]
pub struct PiecesByRangeRequest {
    /// Start of the requested range
    pub start: PieceIndexHash,
    /// End of the requested range
    pub end: PieceIndexHash,
}

impl GenericRequest for PiecesByRangeRequest {
    const PROTOCOL_NAME: &'static str = "/subspace/sync/pieces-by-range/0.1.0";
    const LOG_TARGET: &'static str = "pieces-by-range-request-response-handler";
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

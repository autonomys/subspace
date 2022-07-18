// Copyright (C) 2020-2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Helper for incoming pieces-by-range requests.
//!
//! Handle (i.e. answer) incoming pieces-by-range requests from a remote peer received via
//! `crate::request_responses::RequestResponsesBehaviour` with
//! [`PiecesByRangeRequestHandler`](PiecesByRangeRequestHandler).

#[cfg(test)]
mod tests;

use super::generic_request_handler::{
    ExternalRequestHandler, RequestHandler, RequestHandlerConfig,
};
use crate::request_responses::ProtocolConfig;
use parity_scale_codec::{Decode, Encode};
use subspace_core_primitives::{FlatPieces, PieceIndex, PieceIndexHash};

/// Pieces-by-range-protocol name.
pub const PROTOCOL_NAME: &str = "/subspace/sync/pieces-by-range/0.1.0";
const LOG_TARGET: &str = "pieces-by-range-request-response-handler";

//TODO: A candidate for migrating to a separate crate.
/// Collection of pieces that potentially need to be plotted
#[derive(Debug, Default, PartialEq, Eq, Clone, Encode, Decode)]
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

/// Pieces-by-range protocol response. Assumes requests with paging.
#[derive(Debug, Default, PartialEq, Eq, Clone, Encode, Decode)]
pub struct PiecesByRangeResponse {
    /// Returned data.
    pub pieces: PiecesToPlot,
    /// Defines starting point (cursor) of the next request.
    /// None means no further data available.
    pub next_piece_index_hash: Option<PieceIndexHash>,
}

/// Type alias for the actual external request handler.
pub type ExternalPiecesByRangeRequestHandler =
    ExternalRequestHandler<PiecesByRangeRequest, PiecesByRangeResponse>;

/// Create a new object-mappings request handler.
pub(crate) fn new(
    request_handler: ExternalPiecesByRangeRequestHandler,
) -> (
    RequestHandler<PiecesByRangeRequest, PiecesByRangeResponse>,
    ProtocolConfig,
) {
    RequestHandler::new(RequestHandlerConfig {
        protocol_name: PROTOCOL_NAME,
        log_target: LOG_TARGET,
        request_handler,
    })
}

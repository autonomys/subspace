// This file is part of Substrate.

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

use crate::request_responses::{
    generate_protocol_config, IncomingRequest, OutgoingResponse, ProtocolConfig,
};
use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndexHash};
use tracing::{debug, trace};
const LOG_TARGET: &str = "request-response-handler";

/// Pieces-by-range protocol request. Assumes requests with paging.
#[derive(Serialize, Deserialize, Debug)]
pub struct PiecesByRangeRequest {
    /// Start of the requested range
    pub from: PieceIndexHash,
    /// End of the requested range
    pub to: PieceIndexHash,
    /// Defines starting point of the subsequent requests. Serves like a cursor.
    /// None means starting from the beginning.
    pub next_piece_hash_index: Option<PieceIndexHash>,
}

impl TryFrom<Vec<u8>> for PiecesByRangeRequest {
    type Error = &'static str;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        bincode::deserialize(&data)
            .map_err(|_| "Invalid format: cannot deserialize PiecesByRangeRequest")
    }
}

impl From<PiecesByRangeRequest> for Vec<u8> {
    fn from(data: PiecesByRangeRequest) -> Self {
        bincode::serialize(&data).expect("Invalid format: cannot serialize PiecesByRangeRequest")
    }
}

/// Pieces-by-range protocol response. Assumes requests with paging.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct PiecesByRangeResponse {
    /// Returned data.
    pub pieces: Vec<Piece>,
    /// Defines starting point (cursor) of the next request.
    /// None means no further data avalaible.
    pub next_piece_hash_index: Option<PieceIndexHash>,
}

impl From<PiecesByRangeResponse> for Vec<u8> {
    fn from(data: PiecesByRangeResponse) -> Self {
        bincode::serialize(&data).expect("Invalid format: cannot serialize PiecesByRangeResponse")
    }
}

impl TryFrom<Vec<u8>> for PiecesByRangeResponse {
    type Error = &'static str;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        bincode::deserialize(&data)
            .map_err(|_| "Invalid format: cannot deserialize PiecesByRangeResponse")
    }
}

/// Type alias for the actual external request handler.
pub type ExternalPiecesByRangeRequestHandler =
    Arc<dyn (Fn(&PiecesByRangeRequest) -> Option<PiecesByRangeResponse>) + Send + Sync + 'static>;

/// Contains pieces-by-range request handler structure
pub struct PiecesByRangeRequestHandler {
    request_receiver: mpsc::Receiver<IncomingRequest>,
    request_handler: ExternalPiecesByRangeRequestHandler,
}

impl PiecesByRangeRequestHandler {
    /// Create a new [`PiecesByRangeRequestHandler`].
    pub fn new(request_handler: ExternalPiecesByRangeRequestHandler) -> (Self, ProtocolConfig) {
        // Could be changed after the production feedback.
        const BUFFER_SIZE: usize = 50;
        let (tx, request_receiver) = mpsc::channel(BUFFER_SIZE);

        let mut protocol_config = generate_protocol_config(protocol_name());
        protocol_config.inbound_queue = Some(tx);

        (
            Self {
                request_receiver,
                request_handler,
            },
            protocol_config,
        )
    }

    /// Run [`RequestResponseHandler`].
    pub async fn run(mut self) {
        while let Some(request) = self.request_receiver.next().await {
            let IncomingRequest {
                peer,
                payload,
                pending_response,
            } = request;

            match self.handle_request(peer, payload) {
                Ok(response_data) => {
                    let response = OutgoingResponse {
                        result: Ok(response_data),
                        sent_feedback: None,
                    };

                    match pending_response.send(response) {
                        Ok(()) => trace!(target: LOG_TARGET, "Handled request from {}.", peer,),
                        Err(_) => debug!(
                            target: LOG_TARGET,
                            "Failed to handle request from {}: {}",
                            peer,
                            PieceByRangeHandleRequestError::SendResponse,
                        ),
                    };
                }
                Err(e) => {
                    debug!(
                        target: LOG_TARGET,
                        "Failed to handle request from {}: {}", peer, e,
                    );

                    let response = OutgoingResponse {
                        result: Err(()),
                        sent_feedback: None,
                    };

                    if pending_response.send(response).is_err() {
                        debug!(
                            target: LOG_TARGET,
                            "Failed to handle request from {}: {}",
                            peer,
                            PieceByRangeHandleRequestError::SendResponse,
                        );
                    };
                }
            }
        }
    }

    // Invokes external piece-by-range protocol handler.
    fn handle_request(
        &mut self,
        peer: PeerId,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, PieceByRangeHandleRequestError> {
        trace!("Handling request from {:?}.", peer);
        let request: PiecesByRangeRequest = payload
            .try_into()
            .map_err(|_| PieceByRangeHandleRequestError::InvalidRequestFormat)?;
        let response = (self.request_handler)(&request);

        // Return the result with treating None as an empty(default) response.
        Ok(response.unwrap_or_default().into())
    }
}

#[derive(Debug, thiserror::Error)]
enum PieceByRangeHandleRequestError {
    #[error("Failed to send response.")]
    SendResponse,

    #[error("Incorret request format.")]
    InvalidRequestFormat,
}

/// Pieces-by-range-protocol name.
pub fn protocol_name() -> String {
    "/sync/pieces-by-rangev1".into()
}

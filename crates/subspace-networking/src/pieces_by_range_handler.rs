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

//TODO: fix comment
//! Helper for incoming light client requests.
//!
//! Handle (i.e. answer) incoming light client requests from a remote peer received via
//! `crate::request_responses::RequestResponsesBehaviour` with
//! [`RequestResponseHandler`](handler::RequestResponseHandler).

use crate::request_responses::{IncomingRequest, OutgoingResponse, ProtocolConfig};
use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{Piece, PieceIndexHash};
use tracing::{debug, trace};
const LOG_TARGET: &str = "request-response-handler";

#[derive(Serialize, Deserialize, Debug)]
pub struct PiecesByRangeRequest {
    pub from: PieceIndexHash,
    pub to: PieceIndexHash,
    pub next_piece_hash_index: Option<PieceIndexHash>,
}

impl From<Vec<u8>> for PiecesByRangeRequest {
    fn from(data: Vec<u8>) -> PiecesByRangeRequest {
        bincode::deserialize(&data)
            .expect("Invalid format: cannot deserialize PiecesByRangeRequest")
    }
}

impl Into<Vec<u8>> for PiecesByRangeRequest {
    fn into(self) -> Vec<u8> {
        bincode::serialize(&self).expect("Invalid format: cannot serialize PiecesByRangeRequest")
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PiecesByRangeResponse {
    pub pieces: Vec<Piece>,
    pub next_piece_hash_index: Option<PieceIndexHash>,
}

impl Into<Vec<u8>> for PiecesByRangeResponse {
    fn into(self) -> Vec<u8> {
        bincode::serialize(&self).expect("Invalid format: cannot deserialize PiecesByRangeResponse")
    }
}

impl From<Vec<u8>> for PiecesByRangeResponse {
    fn from(data: Vec<u8>) -> PiecesByRangeResponse {
        bincode::deserialize(&data).expect("Invalid format: cannot serialize PiecesByRangeResponse")
    }
}

pub type RequestHandler =
    Arc<dyn (Fn(&PiecesByRangeRequest) -> Option<PiecesByRangeResponse>) + Send + Sync + 'static>;

pub struct PiecesByRangeRequestHandler {
    request_receiver: mpsc::Receiver<IncomingRequest>,
    request_handler: RequestHandler,
}

impl PiecesByRangeRequestHandler {
    /// Create a new [`RequestResponseHandler`].
    /// TODO: protocol_id: &ProtocolId
    pub fn new(request_handler: RequestHandler) -> (Self, ProtocolConfig) {
        //TODO
        // For now due to lack of data on light client request handling in production systems, this
        // value is chosen to match the block request limit.
        let (tx, request_receiver) = mpsc::channel(20);

        let mut protocol_config = generate_protocol_config();
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
                        Ok(()) => trace!(
                            target: LOG_TARGET,
                            "Handled light client request from {}.",
                            peer,
                        ),
                        Err(_) => debug!(
                            target: LOG_TARGET,
                            "Failed to handle light client request from {}: {}",
                            peer,
                            HandleRequestError::SendResponse,
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
                            "Failed to handle light client request from {}: {}",
                            peer,
                            HandleRequestError::SendResponse,
                        );
                    };
                }
            }
        }
    }

    fn handle_request(
        &mut self,
        peer: PeerId,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, HandleRequestError> {
        println!("Handled request from {:?}. Data: {:?}", peer, payload);
        let request: PiecesByRangeRequest = payload.into();
        let response = (self.request_handler)(&request);

        Ok(response.unwrap().into()) // TODO
    }
}

#[derive(Debug, thiserror::Error)]
enum HandleRequestError {
    #[error("Failed to send response.")]
    SendResponse,
}

/// TODO
pub fn generate_protocol_config() -> ProtocolConfig {
    ProtocolConfig {
        name: generate_protocol_name().into(),
        max_request_size: 1 * 1024 * 1024,
        max_response_size: 16 * 1024 * 1024,
        request_timeout: Duration::from_secs(15),
        inbound_queue: None,
    }
}

//TODO: pub struct ProtocolId(smallvec::SmallVec<[u8; 6]>);
/// Generate the light client protocol name from chain specific protocol identifier.
pub fn generate_protocol_name() -> String {
    format!("/sync/v1")
}

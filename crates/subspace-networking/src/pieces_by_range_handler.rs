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

use crate::request_responses::{IncomingRequest, OutgoingResponse, ProtocolConfig};
use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::PeerId;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subspace_core_primitives::{Piece, PieceIndexHash};
use tracing::{debug, trace};
const LOG_TARGET: &str = "pieces-by-range-request-response-handler";

/// Pieces-by-range protocol request. Assumes requests with paging.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct PiecesByRangeRequest {
    /// Start of the requested range
    pub from: PieceIndexHash,
    /// End of the requested range
    pub to: PieceIndexHash,
    /// Defines starting point of the subsequent requests. Serves like a cursor.
    /// None means starting from the beginning.
    pub next_piece_hash_index: Option<PieceIndexHash>,
}

/// Pieces-by-range protocol response. Assumes requests with paging.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq, Clone, Encode, Decode)]
pub struct PiecesByRangeResponse {
    /// Returned data.
    pub pieces: Vec<Piece>,
    /// Defines starting point (cursor) of the next request.
    /// None means no further data avalaible.
    pub next_piece_hash_index: Option<PieceIndexHash>,
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

        let mut protocol_config = ProtocolConfig::new(protocol_name());
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
                        Ok(()) => trace!(target: LOG_TARGET, %peer, "Handled request",),
                        Err(_) => debug!(
                            target: LOG_TARGET,
                            %peer,
                            "Failed to handle request: {}",
                            PieceByRangeHandleRequestError::SendResponse
                        ),
                    };
                }
                Err(e) => {
                    debug!(target: LOG_TARGET, %e, "Failed to handle request.",);

                    let response = OutgoingResponse {
                        result: Err(()),
                        sent_feedback: None,
                    };

                    if pending_response.send(response).is_err() {
                        debug!(
                            target: LOG_TARGET,
                            %peer,
                            "Failed to handle request: {}", PieceByRangeHandleRequestError::SendResponse
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
        trace!(%peer, "Handling request...");
        let request = PiecesByRangeRequest::decode(&mut payload.as_slice())
            .map_err(|_| PieceByRangeHandleRequestError::InvalidRequestFormat)?;
        let response = (self.request_handler)(&request);

        // Return the result with treating None as an empty(default) response.
        Ok(response.unwrap_or_default().encode())
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

#[cfg(test)]
mod test {
    use crate::{Config, PiecesByRangeRequest, PiecesByRangeResponse};
    use futures::channel::{mpsc, oneshot};
    use futures::StreamExt;
    use libp2p::multiaddr::Protocol;
    use std::sync::Arc;
    use std::time::Duration;
    use subspace_core_primitives::{Piece, PieceIndexHash};

    #[tokio::test]
    async fn pieces_by_range_protocol_smoke() {
        let request = PiecesByRangeRequest {
            from: PieceIndexHash([1u8; 32]),
            to: PieceIndexHash([1u8; 32]),
            next_piece_hash_index: None,
        };

        let response = PiecesByRangeResponse {
            pieces: vec![Piece::default()],
            next_piece_hash_index: None,
        };

        let expected_request = request.clone();
        let expected_response = response.clone();

        let config_1 = Config {
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            allow_non_globals_in_dht: true,
            pieces_by_range_request_handler: Arc::new(move |req| {
                assert_eq!(*req, expected_request);

                Some(expected_response.clone())
            }),
            ..Config::with_generated_keypair()
        };
        let (node_1, node_runner_1) = crate::create(config_1).await.unwrap();

        let (node_1_addresses_sender, mut node_1_addresses_receiver) = mpsc::unbounded();
        node_1
            .on_new_listener(Arc::new(move |address| {
                node_1_addresses_sender
                    .unbounded_send(address.clone())
                    .unwrap();
            }))
            .detach();

        tokio::spawn(async move {
            node_runner_1.run().await;
        });

        let config_2 = Config {
            bootstrap_nodes: vec![node_1_addresses_receiver
                .next()
                .await
                .unwrap()
                .with(Protocol::P2p(node_1.id().into()))],
            listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            allow_non_globals_in_dht: true,
            ..Config::with_generated_keypair()
        };

        let (node_2, node_runner_2) = crate::create(config_2).await.unwrap();
        tokio::spawn(async move {
            node_runner_2.run().await;
        });

        tokio::time::sleep(Duration::from_secs(1)).await;

        let (result_sender, mut result_receiver) = oneshot::channel();
        tokio::spawn(async move {
            let resp = node_2
                .send_pieces_by_range_request(node_1.id(), request)
                .await
                .unwrap();

            result_sender.send(resp).unwrap();
        });

        tokio::time::sleep(Duration::from_secs(1)).await;

        let resp = result_receiver.try_recv().unwrap().unwrap();
        assert_eq!(resp, response);
    }
}

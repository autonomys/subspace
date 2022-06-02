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
//! [`LightClientRequestHandler`](handler::LightClientRequestHandler).

use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{Piece, PieceIndexHash};
use tracing::{debug, trace};
// use sc_network_common::{
// 	config::ProtocolId,
// 	request_responses::{IncomingRequest, OutgoingResponse, ProtocolConfig},
// };
use sc_peerset::ReputationChange;
// use sp_core::{
// 	hexdisplay::HexDisplay,
// 	storage::{ChildInfo, ChildType, PrefixedStorageKey},
// };
use crate::request_responses::{IncomingRequest, OutgoingResponse, ProtocolConfig};
const LOG_TARGET: &str = "request-response-handler";

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    pub from: PieceIndexHash,
    pub to: PieceIndexHash,
    pub next_piece_hash_index: Option<PieceIndexHash>,
}

impl From<Vec<u8>> for Request {
    fn from(data: Vec<u8>) -> Request {
        bincode::deserialize(&data).unwrap() // TODO
    }
}

impl Into<Vec<u8>> for Request {
    fn into(self) -> Vec<u8> {
        bincode::serialize(&self).unwrap() //TODO
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub pieces: Vec<Piece>,
    pub next_piece_hash_index: Option<PieceIndexHash>,
}

impl Into<Vec<u8>> for Response {
    fn into(self) -> Vec<u8> {
        bincode::serialize(&self).unwrap() //TODO
    }
}

impl From<Vec<u8>> for Response {
    fn from(data: Vec<u8>) -> Response {
        bincode::deserialize(&data).unwrap() // TODO
    }
}

pub type RequestHandler = Arc<dyn (Fn(&Request) -> Option<Response>) + Send + Sync + 'static>;

pub struct RequestResponseHandler {
    request_receiver: mpsc::Receiver<IncomingRequest>,
    request_handler: RequestHandler,
}

impl RequestResponseHandler {
    /// Create a new [`RequestResponseHandler`].
    /// TODO: protocol_id: &ProtocolId
    pub fn new(request_handler: RequestHandler) -> (Self, ProtocolConfig) {
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
                        reputation_changes: Vec::new(),
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
                        "Failed to handle light client request from {}: {}", peer, e,
                    );

                    let reputation_changes = match e {
                        HandleRequestError::BadRequest(_) => {
                            vec![ReputationChange::new(-(1 << 12), "bad request")]
                        }
                        _ => Vec::new(),
                    };

                    let response = OutgoingResponse {
                        result: Err(()),
                        reputation_changes,
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
        let request: Request = payload.into();
        let response = (self.request_handler)(&request);
        // let request = schema::v1::light::Request::decode(&payload[..])?;

        // let response = match &request.request {
        // 	Some(schema::v1::light::request::Request::RemoteCallRequest(r)) =>
        // 		self.on_remote_call_request(&peer, r)?,
        // 	Some(schema::v1::light::request::Request::RemoteReadRequest(r)) =>
        // 		self.on_remote_read_request(&peer, r)?,
        // 	Some(schema::v1::light::request::Request::RemoteHeaderRequest(_r)) =>
        // 		return Err(HandleRequestError::BadRequest("Not supported.")),
        // 	Some(schema::v1::light::request::Request::RemoteReadChildRequest(r)) =>
        // 		self.on_remote_read_child_request(&peer, r)?,
        // 	Some(schema::v1::light::request::Request::RemoteChangesRequest(_r)) =>
        // 		return Err(HandleRequestError::BadRequest("Not supported.")),
        // 	None =>
        // 		return Err(HandleRequestError::BadRequest("Remote request without request data.")),
        // };

        //let mut data = vec![38];
        // response.encode(&mut data)?;

        Ok(response.unwrap().into()) // TODO
    }

    // fn on_remote_call_request(
    // 	&mut self,
    // 	peer: &PeerId,
    // 	request: &schema::v1::light::RemoteCallRequest,
    // ) -> Result<schema::v1::light::Response, HandleRequestError> {
    // 	trace!("Remote call request from {} ({} at {:?}).", peer, request.method, request.block,);

    // 	let block = Decode::decode(&mut request.block.as_ref())?;

    // 	let proof =
    // 		match self
    // 			.client
    // 			.execution_proof(&BlockId::Hash(block), &request.method, &request.data)
    // 		{
    // 			Ok((_, proof)) => proof,
    // 			Err(e) => {
    // 				trace!(
    // 					"remote call request from {} ({} at {:?}) failed with: {}",
    // 					peer,
    // 					request.method,
    // 					request.block,
    // 					e,
    // 				);
    // 				StorageProof::empty()
    // 			},
    // 		};

    // 	let response = {
    // 		let r = schema::v1::light::RemoteCallResponse { proof: proof.encode() };
    // 		schema::v1::light::response::Response::RemoteCallResponse(r)
    // 	};

    // 	Ok(schema::v1::light::Response { response: Some(response) })
    // }
}

#[derive(Debug, thiserror::Error)]
enum HandleRequestError {
    //TODO:
    // #[error("Failed to decode request: {0}.")]
    // DecodeProto(#[from] prost::DecodeError),
    // #[error("Failed to encode response: {0}.")]
    // EncodeProto(#[from] prost::EncodeError),
    #[error("Failed to send response.")]
    SendResponse,
    /// A bad request has been received.
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    // /// Encoding or decoding of some data failed.
    // #[error("codec error: {0}")]
    // Codec(#[from] codec::Error),
}

// fn fmt_keys(first: Option<&Vec<u8>>, last: Option<&Vec<u8>>) -> String {
//     if let (Some(first), Some(last)) = (first, last) {
//         if first == last {
//             HexDisplay::from(first).to_string()
//         } else {
//             format!("{}..{}", HexDisplay::from(first), HexDisplay::from(last))
//         }
//     } else {
//         String::from("n/a")
//     }
// }

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

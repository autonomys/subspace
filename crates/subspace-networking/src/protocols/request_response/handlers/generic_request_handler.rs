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

use crate::protocols::request_response::request_response_factory::{
    IncomingRequest, OutgoingResponse, ProtocolConfig, RequestHandler,
};
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::PeerId;
use parity_scale_codec::{Decode, Encode};
use std::pin::Pin;
use std::sync::Arc;
use tracing::{debug, trace};

/// Could be changed after the production feedback.
const REQUESTS_BUFFER_SIZE: usize = 50;

/// Generic request with associated response
pub trait GenericRequest: Encode + Decode + Send + Sync + 'static {
    /// Defines request-response protocol name.
    const PROTOCOL_NAME: &'static str;
    /// Specifies log-parameters for tracing.
    const LOG_TARGET: &'static str;
    /// Response type that corresponds to this request
    type Response: Encode + Decode + Send + Sync + 'static;
}

pub type RequestHandlerFn<Request> = Arc<
    dyn (Fn(
            PeerId,
            &Request,
        )
            -> Pin<Box<dyn Future<Output = Option<<Request as GenericRequest>::Response>> + Send>>)
        + Send
        + Sync
        + 'static,
>;

/// Defines generic request-response protocol handler.
pub struct GenericRequestHandler<Request: GenericRequest> {
    request_receiver: mpsc::Receiver<IncomingRequest>,
    request_handler: RequestHandlerFn<Request>,
    protocol_config: ProtocolConfig,
}

impl<Request: GenericRequest> GenericRequestHandler<Request> {
    /// Creates new [`GenericRequestHandler`] by given handler.
    pub fn create<RH, Fut>(request_handler: RH) -> Box<dyn RequestHandler>
    where
        RH: (Fn(PeerId, &Request) -> Fut) + Send + Sync + 'static,
        Fut: Future<Output = Option<Request::Response>> + Send + 'static,
    {
        let (request_sender, request_receiver) = mpsc::channel(REQUESTS_BUFFER_SIZE);

        let mut protocol_config = ProtocolConfig::new(Request::PROTOCOL_NAME);
        protocol_config.inbound_queue = Some(request_sender);

        Box::new(Self {
            request_receiver,
            request_handler: Arc::new(move |peer_id, request| {
                Box::pin(request_handler(peer_id, request))
            }),
            protocol_config,
        })
    }

    /// Invokes external protocol handler.
    async fn handle_request(
        &mut self,
        peer: PeerId,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, RequestHandlerError> {
        trace!(%peer, protocol=Request::LOG_TARGET, "Handling request...");
        let request = Request::decode(&mut payload.as_slice())
            .map_err(|_| RequestHandlerError::InvalidRequestFormat)?;
        let response = (self.request_handler)(peer, &request).await;

        Ok(response.ok_or(RequestHandlerError::NoResponse)?.encode())
    }
}

#[async_trait]
impl<Request: GenericRequest> RequestHandler for GenericRequestHandler<Request> {
    /// Run [`RequestHandler`].
    async fn run(&mut self) {
        while let Some(request) = self.request_receiver.next().await {
            let IncomingRequest {
                peer,
                payload,
                pending_response,
            } = request;

            match self.handle_request(peer, payload).await {
                Ok(response_data) => {
                    let response = OutgoingResponse {
                        result: Ok(response_data),
                        sent_feedback: None,
                    };

                    match pending_response.send(response) {
                        Ok(()) => trace!(target = Request::LOG_TARGET, %peer, "Handled request",),
                        Err(_) => debug!(
                            target = Request::LOG_TARGET,
                            protocol = Request::PROTOCOL_NAME,
                            %peer,
                            "Failed to handle request: {}",
                            RequestHandlerError::SendResponse
                        ),
                    };
                }
                Err(e) => {
                    debug!(
                        target = Request::LOG_TARGET,
                        protocol = Request::PROTOCOL_NAME,
                        %e,
                        "Failed to handle request.",
                    );

                    let response = OutgoingResponse {
                        result: Err(()),
                        sent_feedback: None,
                    };

                    if pending_response.send(response).is_err() {
                        debug!(
                            target = Request::LOG_TARGET,
                            protocol = Request::PROTOCOL_NAME,
                            %peer,
                            "Failed to handle request: {}", RequestHandlerError::SendResponse
                        );
                    };
                }
            }
        }
    }

    fn protocol_config(&self) -> ProtocolConfig {
        self.protocol_config.clone()
    }

    fn protocol_name(&self) -> &'static str {
        Request::PROTOCOL_NAME
    }

    fn clone_box(&self) -> Box<dyn RequestHandler> {
        let (request_sender, request_receiver) = mpsc::channel(REQUESTS_BUFFER_SIZE);

        let mut protocol_config = ProtocolConfig::new(Request::PROTOCOL_NAME);
        protocol_config.inbound_queue = Some(request_sender);

        Box::new(Self {
            request_receiver,
            request_handler: Arc::clone(&self.request_handler),
            protocol_config,
        })
    }
}

#[derive(Debug, thiserror::Error)]
enum RequestHandlerError {
    #[error("Failed to send response.")]
    SendResponse,

    #[error("Incorrect request format.")]
    InvalidRequestFormat,

    #[error("No response.")]
    NoResponse,
}

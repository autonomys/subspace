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

use crate::request_responses::{
    IncomingRequest, OutgoingResponse, ProtocolConfig, RequestResponseHandler,
};
use async_trait::async_trait;
use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::PeerId;
use parity_scale_codec::{Decode, Encode};
use std::borrow::Cow;
use std::sync::Arc;
use tracing::{debug, trace};

// Could be changed after the production feedback.
const REQUESTS_BUFFER_SIZE: usize = 50;

/// Generic request with associated response
pub trait GenericRequest: Encode + Decode + 'static {
    /// Response type that corresponds to this request
    type Response: Encode + Decode + 'static;
}

/// Defines a config for the generic request handler for the request-response protocol.
pub struct RequestHandlerConfig<Request: GenericRequest> {
    /// Tracing log target
    pub log_target: &'static str,
    /// Request-response protocol name
    pub protocol_name: &'static str,
    /// Actual request-response handler.
    pub request_handler: ExternalRequestHandler<Request>,
}

/// Type alias for the actual external request handler.
pub type ExternalRequestHandler<Request> = Arc<
    dyn (Fn(&Request) -> Option<<Request as GenericRequest>::Response>) + Send + Sync + 'static,
>;

pub(crate) struct GenericRequestHandler<Request: GenericRequest> {
    request_receiver: mpsc::Receiver<IncomingRequest>,
    request_handler: ExternalRequestHandler<Request>,
    log_target: &'static str,
    protocol_name: &'static str,
    protocol_config: ProtocolConfig,
}

impl<Request: GenericRequest> GenericRequestHandler<Request> {
    pub fn new(handler_config: RequestHandlerConfig<Request>) -> Self {
        let (request_sender, request_receiver) = mpsc::channel(REQUESTS_BUFFER_SIZE);

        let mut protocol_config = ProtocolConfig::new(handler_config.protocol_name.into());
        protocol_config.inbound_queue = Some(request_sender);

        Self {
            request_receiver,
            request_handler: handler_config.request_handler,
            log_target: handler_config.log_target,
            protocol_name: handler_config.protocol_name,
            protocol_config,
        }
    }

    // Invokes external protocol handler.
    fn handle_request(
        &mut self,
        peer: PeerId,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, RequestHandlerError> {
        trace!(%peer, protocol=self.protocol_name, "Handling request...");
        let request = Request::decode(&mut payload.as_slice())
            .map_err(|_| RequestHandlerError::InvalidRequestFormat)?;
        let response = (self.request_handler)(&request);

        Ok(response.ok_or(RequestHandlerError::NoResponse)?.encode())
    }
}

#[async_trait]
impl<Request: GenericRequest> RequestResponseHandler for GenericRequestHandler<Request> {
    /// Run [`RequestHandler`].
    async fn run(&mut self) {
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
                        Ok(()) => trace!(target = self.log_target, %peer, "Handled request",),
                        Err(_) => debug!(
                            target = self.log_target,
                            protocol = self.protocol_name,
                            %peer,
                            "Failed to handle request: {}",
                            RequestHandlerError::SendResponse
                        ),
                    };
                }
                Err(e) => {
                    debug!(
                        target = self.log_target,
                        protocol = self.protocol_name,
                        %e,
                        "Failed to handle request.",
                    );

                    let response = OutgoingResponse {
                        result: Err(()),
                        sent_feedback: None,
                    };

                    if pending_response.send(response).is_err() {
                        debug!(
                            target = self.log_target,
                            protocol = self.protocol_name,
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

    fn protocol_name(&self) -> Cow<'static, str> {
        self.protocol_name.into()
    }

    fn clone_box(&self) -> Box<dyn RequestResponseHandler> {
        Box::new(Self::new(RequestHandlerConfig {
            log_target: self.log_target,
            protocol_name: self.protocol_name,
            request_handler: Arc::clone(&self.request_handler),
        }))
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

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

//! Helper for incoming object mappings requests.
//!
//! Handle (i.e. answer) incoming object mappings requests from a remote peer received via
//! `crate::request_responses::RequestResponsesBehaviour` with
//! [`ObjectMappingsRequestHandler`](ObjectMappingsRequestHandler).

use super::generic_request_handler::{
    ExternalRequestHandler, RequestHandler, RequestHandlerConfig,
};
use crate::request_responses::ProtocolConfig;
use parity_scale_codec::{Decode, Encode};
use subspace_core_primitives::objects::GlobalObject;
use subspace_core_primitives::Sha256Hash;

/// Pieces-by-range-protocol name.
pub const PROTOCOL_NAME: &str = "/subspace/object-mappings/0.1.0";
const LOG_TARGET: &str = "object-mappings-request-response-handler";

/// Object-mapping protocol request.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct ObjectMappingsRequest {
    /// Object hash (32-bytes)
    pub object_hash: Sha256Hash,
}

/// Object-mapping protocol request.
#[derive(Debug, Default, PartialEq, Eq, Clone, Encode, Decode)]
pub struct ObjectMappingsResponse {
    /// Returned data.
    pub object_mapping: Option<GlobalObject>,
}

/// Type alias for the actual external request handler.
pub type ExternalObjectMappingsRequestHandler =
    ExternalRequestHandler<ObjectMappingsRequest, ObjectMappingsResponse>;

/// Create a new object-mappings request handler.
pub(crate) fn new(
    request_handler: ExternalObjectMappingsRequestHandler,
) -> (
    RequestHandler<ObjectMappingsRequest, ObjectMappingsResponse>,
    ProtocolConfig,
) {
    RequestHandler::new(RequestHandlerConfig {
        protocol_name: PROTOCOL_NAME,
        log_target: LOG_TARGET,
        request_handler,
    })
}

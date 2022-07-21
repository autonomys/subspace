//! Helper for incoming object mappings requests.
//!
//! Handle (i.e. answer) incoming object mappings requests from a remote peer received via
//! `crate::request_responses::RequestResponsesBehaviour` with generic
//! [`RequestHandler`](RequestHandler).

use crate::request_handlers::generic_request_handler::{
    ExternalRequestHandler, GenericRequest, GenericRequestHandler, RequestHandlerConfig,
};
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

impl GenericRequest for ObjectMappingsRequest {
    type Response = ObjectMappingsResponse;
}

/// Object-mapping protocol request.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct ObjectMappingsResponse {
    /// Returned data.
    pub object_mapping: Option<GlobalObject>,
}

/// Type alias for the actual external request handler.
pub type ExternalObjectMappingsRequestHandler = ExternalRequestHandler<ObjectMappingsRequest>;

/// Create a new object-mappings request handler.
pub(crate) fn new(
    request_handler: ExternalObjectMappingsRequestHandler,
) -> GenericRequestHandler<ObjectMappingsRequest> {
    GenericRequestHandler::new(RequestHandlerConfig {
        protocol_name: PROTOCOL_NAME,
        log_target: LOG_TARGET,
        request_handler,
    })
}

//! Helper for incoming object mappings requests.
//!
//! Handle (i.e. answer) incoming object mappings requests from a remote peer received via
//! `crate::request_responses::RequestResponsesBehaviour` with generic
//! [`RequestHandler`](RequestHandler).

use crate::request_handlers::generic_request_handler::{
    GenericRequest, GenericRequestHandler, RequestHandlerConfig,
};
use crate::request_responses::RequestResponseHandler;
use parity_scale_codec::{Decode, Encode};
use std::sync::Arc;
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

/// Create a new object-mappings request handler.
pub fn new_object_mappings_request_handler<F>(request_handler: F) -> Box<dyn RequestResponseHandler>
where
    F: (Fn(&ObjectMappingsRequest) -> Option<ObjectMappingsResponse>) + Send + Sync + 'static,
{
    Box::new(GenericRequestHandler::new(RequestHandlerConfig {
        protocol_name: PROTOCOL_NAME,
        log_target: LOG_TARGET,
        request_handler: Arc::new(request_handler),
    }))
}

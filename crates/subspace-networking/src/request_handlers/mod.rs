mod generic_request_handler;
pub(crate) mod object_mappings;
pub(crate) mod pieces_by_range;

use crate::request_responses::RequestResponseHandlerRunner;
pub use object_mappings::ExternalObjectMappingsRequestHandler;
pub use pieces_by_range::ExternalPiecesByRangeRequestHandler;
use std::sync::Arc;

/// Defines supported request-response protocol types. Each type requires a related protocol handler.
/// Empty protocol handler will result in the default protocol handler (return None) and is useful
/// in request-only (client-only) scenarios.
#[derive(Clone)]
pub enum RpcProtocol {
    ObjectMappings(Option<ExternalObjectMappingsRequestHandler>),
    PiecesByRange(Option<ExternalPiecesByRangeRequestHandler>),
}

impl RpcProtocol {
    // Returns an instantiated request-response handler reference for the request-response protocol
    // factory. It treats an empty inner protocol handler (None) as the default one (returns None on
    // each request).
    pub(crate) fn into_request_response_handler(self) -> Box<dyn RequestResponseHandlerRunner> {
        match self {
            RpcProtocol::ObjectMappings(handler) => Box::new(object_mappings::new(
                handler.unwrap_or_else(|| Arc::new(|_| None)),
            )),
            RpcProtocol::PiecesByRange(handler) => Box::new(pieces_by_range::new(
                handler.unwrap_or_else(|| Arc::new(|_| None)),
            )),
        }
    }
}

//! Helper for incoming root block requests.
//!
//! Handle (i.e. answer) incoming root blocks requests from a remote peer received via
//! `RequestResponsesBehaviour` with generic [`GenericRequestHandler`].

use crate::request_handlers::generic_request_handler::{GenericRequest, GenericRequestHandler};
use parity_scale_codec::{Decode, Encode};
use subspace_core_primitives::{RootBlock, SegmentIndex};

/// Root block by segment indexes protocol request.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct RootBlockRequest {
    /// Request key - piece index hash
    pub segment_indexes: Vec<SegmentIndex>,
}

impl GenericRequest for RootBlockRequest {
    const PROTOCOL_NAME: &'static str = "/subspace/segment-headers-by-indexes/0.1.0";
    const LOG_TARGET: &'static str = "segment-headers-by-indexes-request-response-handler";
    type Response = RootBlockResponse;
}

/// Root block by segment indexes protocol response.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct RootBlockResponse {
    /// Returned data.
    pub root_blocks: Vec<Option<RootBlock>>,
}

//TODO: remove attribute on the first usage
#[allow(dead_code)]
/// Create a new root-block-by-segment-indexes request handler.
pub type RootBlockBySegmentIndexesRequestHandler = GenericRequestHandler<RootBlockRequest>;

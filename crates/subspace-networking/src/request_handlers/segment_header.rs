//! Helper for incoming segment header requests.
//!
//! Handle (i.e. answer) incoming segment headers requests from a remote peer received via
//! `RequestResponsesBehaviour` with generic [`GenericRequestHandler`].

use crate::request_handlers::generic_request_handler::{GenericRequest, GenericRequestHandler};
use parity_scale_codec::{Decode, Encode};
use subspace_core_primitives::{SegmentHeader, SegmentIndex};

/// Segment header by segment indexes protocol request.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub enum SegmentHeaderRequest {
    SegmentIndexes {
        segment_indexes: Vec<SegmentIndex>,
    },
    /// Defines how many segment headers to return.
    LastSegmentHeaders {
        segment_header_number: u64,
    },
}

impl GenericRequest for SegmentHeaderRequest {
    const PROTOCOL_NAME_TEMPLATE: &'static str = "/subspace/{}/segment-headers-by-indexes/0.1.0";
    const LOG_TARGET: &'static str = "segment-headers-by-indexes-request-response-handler";
    type Response = SegmentHeaderResponse;
}

/// Segment header by segment indexes protocol response.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct SegmentHeaderResponse {
    /// Returned data.
    pub segment_headers: Vec<SegmentHeader>,
}

//TODO: remove attribute on the first usage
#[allow(dead_code)]
/// Create a new segment-header-by-segment-indexes request handler.
pub type SegmentHeaderBySegmentIndexesRequestHandler = GenericRequestHandler<SegmentHeaderRequest>;

//! Helper for incoming segment header requests.
//!
//! Handle (i.e. answer) incoming segment headers requests from a remote peer received via
//! `RequestResponsesBehaviour` with generic [`GenericRequestHandler`].

use super::generic_request_handler::{GenericRequest, GenericRequestHandler};
use parity_scale_codec::{Decode, Encode};
use std::sync::Arc;
use subspace_core_primitives::segments::{SegmentHeader, SegmentIndex};

/// Segment header by segment indexes protocol request.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub enum SegmentHeaderRequest {
    /// Segment headers by segment indexes.
    SegmentIndexes {
        /// Segment indexes to get.
        // TODO: Use `Arc<[SegmentIndex]>` once
        //  https://github.com/paritytech/parity-scale-codec/issues/633 is resolved
        segment_indexes: Arc<Vec<SegmentIndex>>,
    },
    /// Defines how many segment headers to return, segments will be in ascending order.
    LastSegmentHeaders {
        /// Number of segment headers to return.
        limit: u32,
    },
}

impl GenericRequest for SegmentHeaderRequest {
    const PROTOCOL_NAME: &'static str = "/subspace/segment-headers-by-indexes/0.1.0";
    const LOG_TARGET: &'static str = "segment-headers-by-indexes-request-response-handler";
    type Response = SegmentHeaderResponse;
}

/// Segment header by segment indexes protocol response.
#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct SegmentHeaderResponse {
    /// Returned data.
    pub segment_headers: Vec<SegmentHeader>,
}

/// Create a new segment-header-by-segment-indexes request handler.
pub type SegmentHeaderBySegmentIndexesRequestHandler = GenericRequestHandler<SegmentHeaderRequest>;

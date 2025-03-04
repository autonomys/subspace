//! Common types.

use sc_network::RequestFailure;

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestResponseErr {
    #[error("RequestResponseErr::DecodeFailed: {response_len}/{err:?}")]
    DecodeFailed {
        response_len: usize,
        err: parity_scale_codec::Error,
    },

    #[error("RequestResponseErr::RequestFailure {0:?}")]
    RequestFailure(RequestFailure),

    #[error("Network not initialized")]
    NetworkUninitialized,

    #[error("RequestResponseErr::Canceled")]
    Canceled,
}

/// Relay error codes.
#[derive(Debug, thiserror::Error, strum_macros::AsRefStr)]
pub(crate) enum RelayError {
    #[error("Block header: {0}")]
    BlockHeader(String),

    #[error("Block indexed body: {0}")]
    BlockIndexedBody(String),

    #[error("Block justifications: {0}")]
    BlockJustifications(String),

    #[error("Block hash: {0}")]
    BlockHash(String),

    #[error("Block body: {0}")]
    BlockBody(String),

    #[error("Block extrinsics not found: {0}")]
    BlockExtrinsicsNotFound(String),

    #[error("Unexpected number of resolved entries: {expected}, {actual}")]
    ResolveMismatch { expected: usize, actual: usize },

    #[error("Resolved entry not found: {0}")]
    ResolvedNotFound(usize),

    #[error("Request/response error: {0}")]
    RequestResponse(#[from] RequestResponseErr),
}

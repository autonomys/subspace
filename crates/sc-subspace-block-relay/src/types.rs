//! Common types.

use codec::{Decode, Encode};
use sc_network::RequestFailure;

/// The relay protocol identifier.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Encode, Decode)]
pub(crate) enum RelayProtocol {
    #[codec(index = 0)]
    CompactBlock,
    // Next protocol goes here.
    // #[codec(index = 1)]
}

/// The relay protocol version.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Encode, Decode)]
pub(crate) struct RelayVersion {
    /// The protocol identifier.
    protocol: RelayProtocol,

    /// The sub version within the protocol implementation.
    protocol_version: u64,
}

impl RelayVersion {
    /// Creates the version.
    pub(crate) fn new(protocol: RelayProtocol, protocol_version: u64) -> Self {
        Self {
            protocol,
            protocol_version,
        }
    }
}

/// Message type that can be encoded with version info.
pub(crate) trait VersionEncodable {
    /// Type specific encoding.
    fn encode(&self, version: &RelayVersion) -> Vec<u8> {
        todo!()
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestResponseErr {
    #[error("RequestResponseErr::DecodeFailed: {response_len}/{err:?}")]
    DecodeFailed {
        response_len: usize,
        err: codec::Error,
    },

    #[error("RequestResponseErr::RequestFailure {0:?}")]
    RequestFailure(RequestFailure),

    #[error("Network not initialized")]
    NetworkUninitialized,

    #[error("RequestResponseErr::Canceled")]
    Canceled,
}

/// Relay error codes.
#[derive(Debug, thiserror::Error)]
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

    #[error("Unexpected initial request")]
    UnexpectedInitialRequest,

    #[error("Unexpected initial response")]
    UnexpectedInitialResponse,

    #[error("Unexpected protocol request")]
    UnexpectedProtocolRequest,

    #[error("Unexpected protocol response")]
    UnexpectedProtocolRespone,

    #[error("Request/response error: {0}")]
    RequestResponse(#[from] RequestResponseErr),
}

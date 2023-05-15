//! Common utils.

use codec::{self, Decode};
use futures::channel::oneshot::{self, Canceled};
use parking_lot::Mutex;
use sc_network::request_responses::IfDisconnected;
use sc_network::types::ProtocolName;
use sc_network::{NetworkRequest, NetworkService, OutboundFailure, PeerId, RequestFailure};
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

type NetworkHandle<Block> = Arc<NetworkService<Block, <Block as BlockT>::Hash>>;

/// Wrapper to work around the circular dependency in substrate:
/// `build_network()` requires the block relay to be passed in,
/// which internally needs the network handle. `set()` is
/// used to fill in the network after the network is created.
pub struct NetworkWrapper<Block: BlockT> {
    network: Mutex<Option<NetworkHandle<Block>>>,
}

impl<Block: BlockT> NetworkWrapper<Block> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            network: Mutex::new(None),
        }
    }
    pub fn set(&self, network: NetworkHandle<Block>) {
        *self.network.lock() = Some(network);
    }

    pub fn get(&self) -> Option<NetworkHandle<Block>> {
        self.network.lock().as_ref().cloned()
    }
}

/// Helper for request response.
#[derive(Clone)]
pub(crate) struct RequestResponseWrapper<Block: BlockT> {
    protocol_name: ProtocolName,
    who: PeerId,
    network: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
}

impl<Block: BlockT> RequestResponseWrapper<Block> {
    pub(crate) fn new(
        protocol_name: ProtocolName,
        who: PeerId,
        network: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
    ) -> Self {
        Self {
            protocol_name,
            who,
            network,
        }
    }

    /// Performs the request response
    pub(crate) async fn request_response(
        &self,
        request: Vec<u8>,
    ) -> Result<Result<Vec<u8>, RequestFailure>, Canceled> {
        let (tx, rx) = oneshot::channel();
        self.network.start_request(
            self.who,
            self.protocol_name.clone(),
            request,
            tx,
            IfDisconnected::ImmediateError,
        );

        rx.await
    }
}

/// Extracts `RspType` from the result of request/response
pub(crate) fn decode_response<RspType: Decode>(
    result: Result<Result<Vec<u8>, RequestFailure>, Canceled>,
) -> Result<RspType, RequestResponseErr> {
    match result {
        Ok(Ok(bytes)) => {
            let resp_len = bytes.len();
            let response: Result<RspType, _> = Decode::decode(&mut bytes.as_ref());
            response.map_err(|err| RequestResponseErr::DecodeFailed { resp_len, err })
        }
        Ok(Err(err)) => Err(RequestResponseErr::RequestFailure(err)),
        Err(_) => Err(RequestResponseErr::Canceled),
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestResponseErr {
    #[error("RequestResponseErr::DecodeFailed: {resp_len}/{err:?}")]
    DecodeFailed { resp_len: usize, err: codec::Error },

    #[error("RequestResponseErr::RequestFailure {0:?}")]
    RequestFailure(RequestFailure),

    #[error("RequestResponseErr::Canceled")]
    Canceled,
}

impl From<RequestResponseErr> for Result<Result<Vec<u8>, RequestFailure>, oneshot::Canceled> {
    fn from(err: RequestResponseErr) -> Self {
        match err {
            RequestResponseErr::DecodeFailed { .. } => {
                Ok(Err(RequestFailure::Network(OutboundFailure::Timeout)))
            }
            RequestResponseErr::RequestFailure(err) => Ok(Err(err)),
            RequestResponseErr::Canceled => Err(oneshot::Canceled),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RelayError {
    #[error("Network not initialized")]
    NetworkUninitialized,

    #[error("Invalid block attributes: {0}")]
    InvalidBlockAttributes(codec::Error),

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

impl From<RelayError> for Result<Result<Vec<u8>, RequestFailure>, oneshot::Canceled> {
    fn from(err: RelayError) -> Self {
        match err {
            RelayError::RequestResponse(rr_err) => rr_err.into(),
            _ => Ok(Err(RequestFailure::Network(OutboundFailure::Timeout))),
        }
    }
}

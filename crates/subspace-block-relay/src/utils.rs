//! Common utils.

use codec::{self, Decode, Encode};
use futures::channel::oneshot;
use parking_lot::Mutex;
use sc_network::request_responses::IfDisconnected;
use sc_network::types::ProtocolName;
use sc_network::{NetworkRequest, OutboundFailure, PeerId, RequestFailure};
use std::sync::Arc;

type NetworkRequestService = Arc<dyn NetworkRequest + Send + Sync + 'static>;

/// Wrapper to work around the circular dependency in substrate:
/// `build_network()` requires the block relay to be passed in,
/// which internally needs the network handle. `set()` is
/// used to fill in the network after the network is created.
pub struct NetworkWrapper {
    network: Mutex<Option<NetworkRequestService>>,
}

impl NetworkWrapper {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            network: Mutex::new(None),
        }
    }
    pub fn set(&self, network: NetworkRequestService) {
        *self.network.lock() = Some(network);
    }

    pub fn get(&self) -> Option<NetworkRequestService> {
        self.network.lock().as_ref().cloned()
    }
}

/// Helper for request response.
#[derive(Clone)]
pub(crate) struct RequestResponseWrapper {
    protocol_name: ProtocolName,
    who: PeerId,
    network: Arc<dyn NetworkRequest + Send + Sync + 'static>,
}

impl RequestResponseWrapper {
    pub(crate) fn new(
        protocol_name: ProtocolName,
        who: PeerId,
        network: Arc<dyn NetworkRequest + Send + Sync + 'static>,
    ) -> Self {
        Self {
            protocol_name,
            who,
            network,
        }
    }

    /// Performs the request
    pub(crate) async fn request<Request, Response>(
        &self,
        request: Request,
    ) -> Result<Response, RequestResponseErr>
    where
        Request: Encode,
        Response: Decode,
    {
        let (tx, rx) = oneshot::channel();
        self.network.start_request(
            self.who,
            self.protocol_name.clone(),
            request.encode(),
            tx,
            IfDisconnected::ImmediateError,
        );

        let response_bytes = rx
            .await
            .map_err(|_cancelled| RequestResponseErr::Canceled)?
            .map_err(RequestResponseErr::RequestFailure)?;

        let response_len = response_bytes.len();
        Response::decode(&mut response_bytes.as_ref())
            .map_err(|err| RequestResponseErr::DecodeFailed { response_len, err })
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

//! Common utils.

use codec::{self, Decode, Encode};
use futures::channel::oneshot;
use parking_lot::Mutex;
use sc_network::request_responses::IfDisconnected;
use sc_network::types::ProtocolName;
use sc_network::{NetworkRequest, PeerId, RequestFailure};
use std::sync::Arc;

type NetworkRequestService = Arc<dyn NetworkRequest + Send + Sync + 'static>;

/// Wrapper to work around the circular dependency in substrate:
/// `build_network()` requires the block relay to be passed in,
/// which internally needs the network handle. `set()` is
/// used to fill in the network after the network is created.
pub struct NetworkWrapper {
    network: Mutex<Option<NetworkRequestService>>,
}

impl Default for NetworkWrapper {
    fn default() -> Self {
        Self {
            network: Mutex::new(None),
        }
    }
}

impl NetworkWrapper {
    pub fn set(&self, network: NetworkRequestService) {
        *self.network.lock() = Some(network);
    }

    pub(crate) fn network_peer_handle<RequestMsg: Encode>(
        &self,
        protocol_name: ProtocolName,
        who: PeerId,
    ) -> Result<NetworkPeerHandle<RequestMsg>, RequestResponseErr> {
        match self.network.lock().as_ref().cloned() {
            Some(network) => Ok(NetworkPeerHandle::new(protocol_name, who, network)),
            None => Err(RequestResponseErr::NetworkUninitialized),
        }
    }
}

/// Network handle that allows making requests to specific peer and protocol.
/// `RequestMsg` is the format of the request message sent on the wire.
#[derive(Clone)]
pub(crate) struct NetworkPeerHandle<RequestMsg: Encode> {
    protocol_name: ProtocolName,
    who: PeerId,
    network: NetworkRequestService,
    _p: std::marker::PhantomData<RequestMsg>,
}

impl<RequestMsg: Encode> NetworkPeerHandle<RequestMsg> {
    fn new(protocol_name: ProtocolName, who: PeerId, network: NetworkRequestService) -> Self {
        Self {
            protocol_name,
            who,
            network,
            _p: Default::default(),
        }
    }

    /// Performs the request, where the request can be transformed into
    /// the network format `RequestMsg`.
    pub(crate) async fn request<Request, Response>(
        &self,
        request: Request,
    ) -> Result<Response, RequestResponseErr>
    where
        Request: Into<RequestMsg>,
        Response: Decode,
    {
        let (tx, rx) = oneshot::channel();
        self.network.start_request(
            self.who,
            self.protocol_name.clone(),
            Request::into(request).encode(),
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

    #[error("Network not initialized")]
    NetworkUninitialized,

    #[error("RequestResponseErr::Canceled")]
    Canceled,
}

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

//! Common utils.

use crate::NetworkStub;
use async_trait::async_trait;
use codec::{Decode, Encode};
use futures::channel::oneshot::{self, Canceled};
use parking_lot::Mutex;
use sc_network::request_responses::IfDisconnected;
use sc_network::types::ProtocolName;
use sc_network::{NetworkRequest, NetworkService, OutboundFailure, PeerId, RequestFailure};
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

type NetworkHandle<Block> = Arc<NetworkService<Block, <Block as BlockT>::Hash>>;

/// The message sent to the server as part of the request/response.
#[derive(Encode, Decode)]
pub(crate) struct ServerMessage {
    /// The serialized messages
    pub(crate) message: Vec<u8>,

    /// If the message is meant for the protocol component on the server side.
    pub(crate) is_protocol_message: bool,
}

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

/// Network stub for request response.
#[derive(Clone)]
pub(crate) struct NetworkStubImpl<Block: BlockT> {
    protocol_name: ProtocolName,
    who: PeerId,
    network: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
}

impl<Block: BlockT> NetworkStubImpl<Block> {
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
}

#[async_trait]
impl<Block: BlockT> NetworkStub for NetworkStubImpl<Block> {
    async fn request_response(
        &self,
        request: Vec<u8>,
        is_protocol_message: bool,
    ) -> Result<Result<Vec<u8>, RequestFailure>, Canceled> {
        let msg = ServerMessage {
            message: request,
            is_protocol_message,
        };

        let (tx, rx) = oneshot::channel();
        self.network.start_request(
            self.who,
            self.protocol_name.clone(),
            msg.encode(),
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
            response.map_err(|err| {
                RequestResponseErr::DecodeFailed(format!("Request/response: {resp_len}, {err:?}"))
            })
        }
        Ok(Err(err)) => Err(RequestResponseErr::RequestFailure(err)),
        Err(_) => Err(RequestResponseErr::Canceled),
    }
}

#[derive(Debug)]
pub(crate) enum RequestResponseErr {
    DecodeFailed(String),
    RequestFailure(RequestFailure),
    Canceled,
}

impl From<RequestResponseErr> for Result<Result<Vec<u8>, RequestFailure>, oneshot::Canceled> {
    fn from(err: RequestResponseErr) -> Self {
        match err {
            RequestResponseErr::DecodeFailed(_) => {
                Ok(Err(RequestFailure::Network(OutboundFailure::Timeout)))
            }
            RequestResponseErr::RequestFailure(err) => Ok(Err(err)),
            RequestResponseErr::Canceled => Err(oneshot::Canceled),
        }
    }
}

#[derive(Debug)]
pub(crate) enum RelayError {
    Internal(String),
    RequestResponse(RequestResponseErr),
}

impl From<String> for RelayError {
    fn from(msg: String) -> Self {
        Self::Internal(msg)
    }
}

impl From<RequestResponseErr> for RelayError {
    fn from(err: RequestResponseErr) -> Self {
        Self::RequestResponse(err)
    }
}

impl From<RelayError> for Result<Result<Vec<u8>, RequestFailure>, oneshot::Canceled> {
    fn from(err: RelayError) -> Self {
        match err {
            RelayError::Internal(_) => Ok(Err(RequestFailure::Network(OutboundFailure::Timeout))),
            RelayError::RequestResponse(rr_err) => rr_err.into(),
        }
    }
}

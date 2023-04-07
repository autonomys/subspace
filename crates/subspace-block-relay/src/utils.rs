use codec::{Decode, Encode};
use futures::channel::oneshot;
use sc_network::request_responses::IfDisconnected;
use sc_network::types::ProtocolName;
use sc_network::{OutboundFailure, PeerId, RequestFailure};
use sc_network_sync::service::network::NetworkServiceHandle;

#[derive(Debug)]
pub enum RequestResponseErr {
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
pub enum RelayError {
    Internal(String),
    RequestResponseErr,
}

impl From<String> for RelayError {
    fn from(msg: String) -> Self {
        Self::Internal(msg)
    }
}

impl From<RelayError> for Result<Result<Vec<u8>, RequestFailure>, oneshot::Canceled> {
    fn from(err: RelayError) -> Self {
        match err {
            RelayError::Internal(_) => Ok(Err(RequestFailure::Network(OutboundFailure::Timeout))),
            RelayError::RequestResponseErr => err.into(),
        }
    }
}

/// Helper to perform the request response sequence.
#[derive(Clone)]
pub struct RequestResponseStub {
    protocol_name: ProtocolName,
    who: PeerId,
    network: NetworkServiceHandle,
}

impl RequestResponseStub {
    pub(crate) fn new(
        protocol_name: ProtocolName,
        who: PeerId,
        network: NetworkServiceHandle,
    ) -> Self {
        Self {
            protocol_name,
            who,
            network,
        }
    }

    /// Performs the request/response with the given types
    pub(crate) async fn request_response<ReqType, RspType>(
        &self,
        request: ReqType,
    ) -> Result<RspType, RequestResponseErr>
    where
        ReqType: Encode,
        RspType: Decode,
    {
        let (tx, rx) = oneshot::channel();
        self.network.start_request(
            self.who,
            self.protocol_name.clone(),
            request.encode(),
            tx,
            IfDisconnected::ImmediateError,
        );

        let ret = rx.await;
        match ret {
            Ok(Ok(bytes)) => {
                let response: Result<RspType, _> = Decode::decode(&mut bytes.as_ref());
                response.map_err(|err| RequestResponseErr::DecodeFailed(format!("{err:?}")))
            }
            Ok(Err(err)) => Err(RequestResponseErr::RequestFailure(err)),
            Err(err) => Err(RequestResponseErr::Canceled),
        }
    }
}

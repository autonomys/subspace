use codec::{Decode, Encode};
use futures::channel::oneshot;
use sc_network::request_responses::IfDisconnected;
use sc_network::types::ProtocolName;
use sc_network::{OutboundFailure, PeerId, RequestFailure};
use sc_network_sync::service::network::NetworkServiceHandle;

/// Helper to perform the request response sequence.
#[derive(Clone)]
pub struct RequestResponseStub {
    protocol_name: ProtocolName,
    who: PeerId,
    network: NetworkServiceHandle,
}

pub enum RequestResponseErr {
    RequestFailure(RequestFailure),
    Canceled,
}

impl From<RequestResponseErr> for Result<Result<Vec<u8>, RequestFailure>, oneshot::Canceled> {
    fn from(response_err: RequestResponseErr) -> Self {
        match response_err {
            RequestResponseErr::RequestFailure(err) => Ok(Err(err)),
            RequestResponseErr::Canceled => Err(oneshot::Canceled),
        }
    }
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
                response.map_err(|_| {
                    RequestResponseErr::RequestFailure(RequestFailure::Network(
                        OutboundFailure::Timeout,
                    ))
                })
            }
            Ok(Err(err)) => Err(RequestResponseErr::RequestFailure(err)),
            Err(err) => Err(RequestResponseErr::Canceled),
        }
    }
}

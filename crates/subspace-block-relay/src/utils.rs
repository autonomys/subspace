use codec::{Decode, Encode};
use futures::channel::oneshot;
use sc_network::request_responses::IfDisconnected;
use sc_network::types::ProtocolName;
use sc_network::{OutboundFailure, PeerId, RequestFailure};
use sc_network_sync::service::network::NetworkServiceHandle;

/// Helper to perform the request response sequence.
#[derive(Clone)]
pub(crate) struct RequestResponseStub {
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
    ) -> Result<Result<RspType, RequestFailure>, oneshot::Canceled>
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
                let response: RspType = match Decode::decode(&mut bytes.as_ref()) {
                    Ok(response) => response,
                    _ => return Ok(Err(RequestFailure::Network(OutboundFailure::Timeout))),
                };
                Ok(Ok(response))
            }
            Ok(Err(err)) => {
                return Ok(Err(err)) as Result<Result<RspType, RequestFailure>, oneshot::Canceled>;
            }
            Err(err) => {
                return Err(err) as Result<Result<RspType, RequestFailure>, oneshot::Canceled>;
            }
        }
    }
}

/// Helper to perform request/response.
pub(crate) fn request_response<ReqType, RspType>(
    who: PeerId,
    request: ReqType,
    network: NetworkServiceHandle,
) -> Result<Result<RspType, RequestFailure>, oneshot::Canceled>
where
    ReqType: Encode,
    RspType: Decode,
{
    /*
    let (tx, rx) = oneshot::channel();
    network.start_request(
        who,
        self.protocol_name.clone(),
        request,
        tx,
        IfDisconnected::ImmediateError,
    );
    rx.await

     */

    Err(oneshot::Canceled)
}

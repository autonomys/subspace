use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::{DispatchError, DispatchResult};

/// Endpoint as defined in the formal spec.
/// Endpoint is an application that can send and receive messages from other domains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum Endpoint {
    /// Id of the endpoint on a specific domain.
    Id(u64),
}

/// Endpoint request or response payload.
pub type EndpointPayload = Vec<u8>;

/// Request sent by src_endpoint to dst_endpoint.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct EndpointRequest {
    pub src_endpoint: Endpoint,
    pub dst_endpoint: Endpoint,
    pub payload: EndpointPayload,
}

/// Response for the message request.
pub type EndpointResponse = Result<EndpointPayload, DispatchError>;

/// Sender provides abstraction on sending messages to other domains.
pub trait Sender<DomainId> {
    /// sends a message to dst_domain_id.
    fn send_message(dst_domain_id: DomainId, req: EndpointRequest) -> DispatchResult;
}

/// Handler to
///  - handle message request from other domains.
///  - handle requested message responses from other domains.
pub trait EndpointHandler<DomainId> {
    /// Triggered by pallet-messenger when a new inbox message is received and bound for this handler.
    fn message(&self, src_domain_id: DomainId, req: EndpointRequest) -> EndpointResponse;

    /// Triggered by pallet-messenger when a response for a request is received from dst_domain_id.
    fn message_response(
        &self,
        dst_domain_id: DomainId,
        req: EndpointRequest,
        resp: EndpointResponse,
    ) -> DispatchResult;
}

use codec::{Decode, Encode};
use frame_support::Parameter;
use scale_info::TypeInfo;
use sp_domains::DomainId;
use sp_runtime::traits::Member;
use sp_runtime::{sp_std, DispatchError, DispatchResult};
use sp_std::vec::Vec;

/// Represents a particular endpoint in a given Execution environment.
pub type EndpointId = u64;

/// Endpoint as defined in the formal spec.
/// Endpoint is an application that can send and receive messages from other domains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum Endpoint {
    /// Id of the endpoint on a specific domain.
    Id(EndpointId),
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
pub trait Sender<AccountId> {
    /// Unique Id of the message between dst_domain and src_domain.
    type MessageId: Parameter + Member + Copy;
    /// Sends a message to dst_domain_id.
    fn send_message(
        sender: &AccountId,
        dst_domain_id: DomainId,
        req: EndpointRequest,
    ) -> Result<Self::MessageId, DispatchError>;
}

/// Handler to
///  - handle message request from other domains.
///  - handle requested message responses from other domains.
pub trait EndpointHandler<MessageId> {
    /// Triggered by pallet-messenger when a new inbox message is received and bound for this handler.
    fn message(
        &self,
        src_domain_id: DomainId,
        message_id: MessageId,
        req: EndpointRequest,
    ) -> EndpointResponse;

    /// Triggered by pallet-messenger when a response for a request is received from dst_domain_id.
    fn message_response(
        &self,
        dst_domain_id: DomainId,
        message_id: MessageId,
        req: EndpointRequest,
        resp: EndpointResponse,
    ) -> DispatchResult;
}

/// Trait that can provide info for a given domain.
/// This trait is implemented by pallet-receipts since it tracks the necessary info
/// on Core domains in System domain runtime.
/// For other runtimes, this is simply a no-op.
pub trait DomainInfo<Number, Hash, StateRoot> {
    /// Returns the best known number of a given domain.
    fn domain_best_number(domain_id: DomainId) -> Option<Number>;
    /// Returns the known state root of a specific block.
    fn domain_state_root(domain_id: DomainId, number: Number, hash: Hash) -> Option<StateRoot>;
}

impl<Number, Hash, StateRoot> DomainInfo<Number, Hash, StateRoot> for () {
    fn domain_best_number(_domain_id: DomainId) -> Option<Number> {
        None
    }

    fn domain_state_root(_domain_id: DomainId, _number: Number, _hash: Hash) -> Option<StateRoot> {
        None
    }
}

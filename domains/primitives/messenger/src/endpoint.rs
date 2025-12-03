#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use frame_support::Parameter;
use frame_support::weights::Weight;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::DecodeWithMemTracking;
use sp_domains::ChainId;
use sp_runtime::traits::Member;
use sp_runtime::{DispatchError, DispatchResult};

/// Represents a particular endpoint in a given Execution environment.
pub type EndpointId = u64;

/// Endpoint as defined in the formal spec.
/// Endpoint is an application that can send and receive messages from other chains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, DecodeWithMemTracking)]
pub enum Endpoint {
    /// Id of the endpoint on a specific chain.
    Id(EndpointId),
}

/// Endpoint request or response payload.
pub type EndpointPayload = Vec<u8>;

/// Fee collected on src_chain for execution of XDM on both the src and dst chains.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct CollectedFee<Balance> {
    /// Collected execution fee for src_chain.
    pub src_chain_fee: Balance,
    /// Collected execution fee for dst_chain.
    pub dst_chain_fee: Balance,
}

/// Request sent by src_endpoint to dst_endpoint.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct EndpointRequest {
    pub src_endpoint: Endpoint,
    pub dst_endpoint: Endpoint,
    pub payload: EndpointPayload,
}

/// Request sent by src_endpoint to dst_endpoint with collected Fee
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct EndpointRequestWithCollectedFee<Balance> {
    pub req: EndpointRequest,
    pub collected_fee: CollectedFee<Balance>,
}

impl<Balance> From<EndpointRequestWithCollectedFee<Balance>> for EndpointRequest {
    fn from(value: EndpointRequestWithCollectedFee<Balance>) -> Self {
        value.req
    }
}

impl<Balance: Default> From<EndpointRequest> for EndpointRequestWithCollectedFee<Balance> {
    fn from(value: EndpointRequest) -> Self {
        EndpointRequestWithCollectedFee {
            req: value,
            collected_fee: CollectedFee::default(),
        }
    }
}

/// Response for the message request.
pub type EndpointResponse = Result<EndpointPayload, DispatchError>;

/// Sender provides abstraction on sending messages to other chains.
pub trait Sender<AccountId> {
    /// Unique Id of the message between dst_chain and src_chain.
    type MessageId: Parameter + Member + Copy + Default;
    /// Sends a message to dst_chain_id.
    fn send_message(
        sender: &AccountId,
        dst_chain_id: ChainId,
        req: EndpointRequest,
    ) -> Result<Self::MessageId, DispatchError>;

    /// Only used in benchmark to prepare for a upcoming `send_message` call to
    /// ensure it will succeed.
    #[cfg(feature = "runtime-benchmarks")]
    fn unchecked_open_channel(dst_chain_id: ChainId) -> Result<(), DispatchError>;
}

/// Handler to
///  - handle message request from other chains.
///  - handle requested message responses from other chains.
pub trait EndpointHandler<MessageId> {
    /// Triggered by pallet-messenger when a new inbox message is received and bound for this handler.
    fn message(
        &self,
        src_chain_id: ChainId,
        message_id: MessageId,
        req: EndpointRequest,
        // if pre_checks failed, implementation should reject the transfer
        pre_check_result: DispatchResult,
    ) -> EndpointResponse;

    /// Return the maximal possible consume weight of `message`
    fn message_weight(&self) -> Weight;

    /// Triggered by pallet-messenger when a response for a request is received from dst_chain_id.
    fn message_response(
        &self,
        dst_chain_id: ChainId,
        message_id: MessageId,
        req: EndpointRequest,
        resp: EndpointResponse,
    ) -> DispatchResult;

    /// Return the maximal possible consume weight of `message_response`
    fn message_response_weight(&self) -> Weight;
}

#[cfg(feature = "runtime-benchmarks")]
pub struct BenchmarkEndpointHandler;

#[cfg(feature = "runtime-benchmarks")]
impl<MessageId> EndpointHandler<MessageId> for BenchmarkEndpointHandler {
    fn message(
        &self,
        _src_chain_id: ChainId,
        _message_id: MessageId,
        _req: EndpointRequest,
        _pre_check_result: DispatchResult,
    ) -> EndpointResponse {
        Ok(Vec::new())
    }

    fn message_weight(&self) -> Weight {
        Weight::zero()
    }

    fn message_response(
        &self,
        _dst_chain_id: ChainId,
        _message_id: MessageId,
        _req: EndpointRequest,
        _resp: EndpointResponse,
    ) -> DispatchResult {
        Ok(())
    }

    fn message_response_weight(&self) -> Weight {
        Weight::zero()
    }
}

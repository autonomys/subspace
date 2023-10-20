use crate::endpoint::{Endpoint, EndpointRequest, EndpointResponse};
use codec::{Decode, Encode, FullCodec, MaxEncodedLen};
use frame_support::storage::generator::StorageMap;
use frame_support::Identity;
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_core::storage::StorageKey;
use sp_domains::verification::StorageProofVerifier;
use sp_domains::DomainId;
use sp_runtime::app_crypto::sp_core::U256;
use sp_runtime::{sp_std, DispatchError};
use sp_std::marker::PhantomData;
use sp_std::vec::Vec;
use sp_trie::StorageProof;

/// Channel identity.
pub type ChannelId = U256;

/// Nonce used as an identifier and ordering of messages within a channel.
/// Nonce is always increasing.
pub type Nonce = U256;

/// Unique Id of a message between two chains.
pub type MessageId = (ChannelId, Nonce);

/// Fee model to send a request and receive a response from another chain.
#[derive(Default, Debug, Encode, Decode, Clone, Copy, Eq, PartialEq, TypeInfo)]
pub struct FeeModel<Balance> {
    /// Fee to relay message from one chain to another
    pub relay_fee: Balance,
}

/// Parameters for a new channel between two chains.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Copy)]
pub struct InitiateChannelParams<Balance> {
    pub max_outgoing_messages: u32,
    pub fee_model: FeeModel<Balance>,
}

/// Defines protocol requests performed on chains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum ProtocolMessageRequest<Balance> {
    /// Request to open a channel with foreign chain.
    ChannelOpen(InitiateChannelParams<Balance>),
    /// Request to close an open channel with foreign chain.
    ChannelClose,
}

/// Defines protocol requests performed on chains.
pub type ProtocolMessageResponse = Result<(), DispatchError>;

/// Protocol message that encompasses  request or its response.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum RequestResponse<Request, Response> {
    Request(Request),
    Response(Response),
}

/// Payload of the message
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum Payload<Balance> {
    /// Protocol message.
    Protocol(RequestResponse<ProtocolMessageRequest<Balance>, ProtocolMessageResponse>),
    /// Endpoint message.
    Endpoint(RequestResponse<EndpointRequest, EndpointResponse>),
}

/// Versioned message payload
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum VersionedPayload<Balance> {
    V0(Payload<Balance>),
}

/// Message weight tag used to indicate the consumed weight when handling the message
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Default)]
pub enum MessageWeightTag {
    ProtocolChannelOpen,
    ProtocolChannelClose,
    EndpointRequest(Endpoint),
    EndpointResponse(Endpoint),
    #[default]
    None,
}

impl MessageWeightTag {
    // Construct the weight tag for outbox message based on the outbox payload
    pub fn outbox<Balance>(outbox_payload: &VersionedPayload<Balance>) -> Self {
        match outbox_payload {
            VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(
                ProtocolMessageRequest::ChannelOpen(_),
            ))) => MessageWeightTag::ProtocolChannelOpen,
            VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(
                ProtocolMessageRequest::ChannelClose,
            ))) => MessageWeightTag::ProtocolChannelClose,
            VersionedPayload::V0(Payload::Endpoint(RequestResponse::Request(endpoint_req))) => {
                MessageWeightTag::EndpointRequest(endpoint_req.dst_endpoint.clone())
            }
            _ => MessageWeightTag::None,
        }
    }

    // Construct the weight tag for inbox response based on the weight tag of the request
    // message and the response payload
    pub fn inbox_response<Balance>(
        req_type: MessageWeightTag,
        resp_payload: &VersionedPayload<Balance>,
    ) -> Self {
        match (req_type, resp_payload) {
            (
                MessageWeightTag::ProtocolChannelOpen,
                VersionedPayload::V0(Payload::Protocol(RequestResponse::Response(Ok(_)))),
            ) => MessageWeightTag::ProtocolChannelOpen,
            (
                MessageWeightTag::EndpointRequest(endpoint),
                VersionedPayload::V0(Payload::Endpoint(RequestResponse::Response(_))),
            ) => MessageWeightTag::EndpointResponse(endpoint),
            _ => MessageWeightTag::None,
        }
    }
}

/// Identifier of a chain.
#[derive(
    Clone,
    Copy,
    Debug,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Encode,
    Decode,
    TypeInfo,
    Serialize,
    Deserialize,
    MaxEncodedLen,
)]
pub enum ChainId {
    Consensus,
    Domain(DomainId),
}

impl ChainId {
    #[inline]
    pub fn consensus_chain_id() -> Self {
        Self::Consensus
    }

    #[inline]
    pub fn is_consensus_chain(&self) -> bool {
        match self {
            ChainId::Consensus => true,
            ChainId::Domain(_) => false,
        }
    }
}

impl From<u32> for ChainId {
    #[inline]
    fn from(x: u32) -> Self {
        Self::Domain(DomainId::new(x))
    }
}

impl From<DomainId> for ChainId {
    #[inline]
    fn from(x: DomainId) -> Self {
        Self::Domain(x)
    }
}

/// Message contains information to be sent to or received from another chain.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Message<Balance> {
    /// Chain which initiated this message.
    pub src_chain_id: ChainId,
    /// Chain this message is intended for.
    pub dst_chain_id: ChainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Payload of the message
    pub payload: VersionedPayload<Balance>,
    /// Last delivered message response nonce on src_chain.
    pub last_delivered_message_response_nonce: Option<Nonce>,
}

/// Block info used as part of the Cross chain message proof.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct BlockInfo<Number, Hash> {
    /// Block number of the chain.
    pub block_number: Number,
    /// Block hash of the chain.
    pub block_hash: Hash,
}

/// Proof combines the storage proofs to validate messages.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Proof<BlockNumber, BlockHash, StateRoot> {
    /// Consensus chain block info when proof was constructed
    pub consensus_chain_block_info: BlockInfo<BlockNumber, BlockHash>,
    /// State root of Consensus chain at above number and block hash.
    /// This is the used to extract the message from proof.
    pub consensus_chain_state_root: StateRoot,
    /// Storage proof that src chain state_root is registered on Consensus chain.
    /// This is optional when the src_chain is Consensus.
    /// BlockNumber and BlockHash is used with storage proof to validate and fetch its state root.
    pub domain_proof: Option<(BlockInfo<BlockNumber, BlockHash>, StorageProof)>,
    /// Storage proof that message is processed on src_chain.
    pub message_proof: StorageProof,
}

impl<BlockNumber: Default, BlockHash: Default, StateRoot: Default>
    Proof<BlockNumber, BlockHash, StateRoot>
{
    #[cfg(feature = "runtime-benchmarks")]
    pub fn dummy() -> Self {
        Proof {
            consensus_chain_block_info: BlockInfo {
                block_number: Default::default(),
                block_hash: Default::default(),
            },
            consensus_chain_state_root: Default::default(),
            domain_proof: None,
            message_proof: StorageProof::empty(),
        }
    }
}

/// Holds the Block info and state roots from which a proof was constructed.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct ExtractedStateRootsFromProof<BlockNumber, BlockHash, StateRoot> {
    /// Consensus chain block info when proof was constructed
    pub consensus_chain_block_info: BlockInfo<BlockNumber, BlockHash>,
    /// State root of Consensus chain at above number and block hash.
    pub consensus_chain_state_root: StateRoot,
    /// Storage proof that src chain state_root is registered on Consensus chain.
    /// This is optional when the src_chain is the consensus chain.
    /// BlockNumber and BlockHash is used with storage proof to validate and fetch its state root.
    pub domain_info: Option<(DomainId, BlockInfo<BlockNumber, BlockHash>, StateRoot)>,
}

/// Cross Domain message contains Message and its proof on src_chain.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct CrossDomainMessage<BlockNumber, BlockHash, StateRoot> {
    /// Chain which initiated this message.
    pub src_chain_id: ChainId,
    /// Chain this message is intended for.
    pub dst_chain_id: ChainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Proof of message processed on src_chain.
    pub proof: Proof<BlockNumber, BlockHash, StateRoot>,
    /// The message weight tag
    pub weight_tag: MessageWeightTag,
}

impl<BlockNumber, BlockHash, StateRoot> CrossDomainMessage<BlockNumber, BlockHash, StateRoot> {
    /// Extracts state roots.
    /// If the chain proof is present, then then we construct the trie and extract chain state root.
    pub fn extract_state_roots_from_proof<Hashing>(
        &self,
    ) -> Option<ExtractedStateRootsFromProof<BlockNumber, BlockHash, StateRoot>>
    where
        Hashing: hash_db::Hasher,
        StateRoot: Clone + Decode + Into<Hashing::Out> + FullCodec + TypeInfo + 'static,
        BlockNumber: Clone + FullCodec + TypeInfo + 'static,
        BlockHash: Clone + FullCodec + TypeInfo + 'static,
    {
        let xdm_proof = self.proof.clone();
        let consensus_chain_state_root = xdm_proof.consensus_chain_state_root.clone();
        let mut extracted_state_roots = ExtractedStateRootsFromProof {
            consensus_chain_block_info: xdm_proof.consensus_chain_block_info,
            consensus_chain_state_root: xdm_proof.consensus_chain_state_root,
            domain_info: None,
        };

        // verify intermediate domain proof and retrieve state root of the message.
        let domain_proof = xdm_proof.domain_proof;
        match self.src_chain_id {
            // if the src_chain is a consensus chain, return the state root as is since message is on consensus runtime
            ChainId::Consensus if domain_proof.is_none() => Some(extracted_state_roots),
            // if the src_chain is a domain, then return the state root of the domain by verifying the domain proof.
            ChainId::Domain(domain_id) if domain_proof.is_some() => {
                let (domain_info, domain_state_root_proof) =
                    domain_proof.expect("checked for existence value above");
                let domain_state_root_key = DomainStateRootStorage::<_, _, StateRoot>::storage_key(
                    domain_id,
                    domain_info.block_number.clone(),
                    domain_info.block_hash.clone(),
                );

                let domain_state_root =
                    match StorageProofVerifier::<Hashing>::get_decoded_value::<StateRoot>(
                        &consensus_chain_state_root.into(),
                        domain_state_root_proof,
                        domain_state_root_key,
                    ) {
                        Ok(result) => result,
                        Err(err) => {
                            log::error!(
                                target: "runtime::messenger",
                                "Failed to verify Domain proof: {:?}",
                                err
                            );
                            return None;
                        }
                    };

                extracted_state_roots.domain_info =
                    Some((domain_id, domain_info, domain_state_root));

                Some(extracted_state_roots)
            }
            _ => None,
        }
    }
}

/// Message with storage key to generate storage proof using the backend.
#[derive(Debug, Encode, Decode, TypeInfo, Clone, Eq, PartialEq)]
pub struct BlockMessageWithStorageKey {
    /// Chain which initiated this message.
    pub src_chain_id: ChainId,
    /// Chain this message is intended for.
    pub dst_chain_id: ChainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Storage key to generate proof for using proof backend.
    pub storage_key: Vec<u8>,
    /// The message weight tag
    pub weight_tag: MessageWeightTag,
}

/// Set of messages with storage keys to be relayed in a given block..
#[derive(Default, Debug, Encode, Decode, TypeInfo, Clone, Eq, PartialEq)]
pub struct BlockMessagesWithStorageKey {
    pub outbox: Vec<BlockMessageWithStorageKey>,
    pub inbox_responses: Vec<BlockMessageWithStorageKey>,
}

impl<BlockNumber, BlockHash, StateRoot> CrossDomainMessage<BlockNumber, BlockHash, StateRoot> {
    pub fn from_relayer_msg_with_proof(
        r_msg: BlockMessageWithStorageKey,
        proof: Proof<BlockNumber, BlockHash, StateRoot>,
    ) -> Self {
        CrossDomainMessage {
            src_chain_id: r_msg.src_chain_id,
            dst_chain_id: r_msg.dst_chain_id,
            channel_id: r_msg.channel_id,
            nonce: r_msg.nonce,
            proof,
            weight_tag: r_msg.weight_tag,
        }
    }
}

/// This is a representation of actual StateRoots storage in pallet-domains.
/// Any change in key or value there should be changed here accordingly.
pub struct DomainStateRootStorage<Number, Hash, StateRoot>(PhantomData<(Number, Hash, StateRoot)>);

impl<Number, Hash, StateRoot> StorageMap<(DomainId, Number, Hash), StateRoot>
    for DomainStateRootStorage<Number, Hash, StateRoot>
where
    Number: FullCodec + TypeInfo + 'static,
    Hash: FullCodec + TypeInfo + 'static,
    StateRoot: FullCodec + TypeInfo + 'static,
{
    type Query = Option<StateRoot>;
    type Hasher = Identity;

    fn module_prefix() -> &'static [u8] {
        "Domains".as_ref()
    }

    fn storage_prefix() -> &'static [u8] {
        "StateRoots".as_ref()
    }

    fn from_optional_value_to_query(v: Option<StateRoot>) -> Self::Query {
        v
    }

    fn from_query_to_optional_value(v: Self::Query) -> Option<StateRoot> {
        v
    }
}

impl<Number, Hash, StateRoot> DomainStateRootStorage<Number, Hash, StateRoot>
where
    Number: FullCodec + TypeInfo + 'static,
    Hash: FullCodec + TypeInfo + 'static,
    StateRoot: FullCodec + TypeInfo + 'static,
{
    pub fn storage_key(domain_id: DomainId, number: Number, hash: Hash) -> StorageKey {
        StorageKey(Self::storage_map_final_key::<(DomainId, Number, Hash)>((
            domain_id, number, hash,
        )))
    }
}

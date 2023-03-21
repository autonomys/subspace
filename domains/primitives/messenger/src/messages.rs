use crate::endpoint::{EndpointRequest, EndpointResponse};
use crate::verification::StorageProofVerifier;
use codec::{Decode, Encode, FullCodec};
use frame_support::pallet_prelude::NMapKey;
use frame_support::storage::generator::StorageNMap;
use frame_support::{log, Twox64Concat};
use scale_info::TypeInfo;
use sp_core::storage::StorageKey;
use sp_domains::DomainId;
use sp_runtime::app_crypto::sp_core::U256;
use sp_runtime::traits::CheckedAdd;
use sp_runtime::{sp_std, DispatchError};
use sp_std::marker::PhantomData;
use sp_std::vec::Vec;
use sp_trie::StorageProof;

/// Channel identity.
pub type ChannelId = U256;

/// Nonce used as an identifier and ordering of messages within a channel.
/// Nonce is always increasing.
pub type Nonce = U256;

/// Unique Id of a message between two domains.
pub type MessageId = (ChannelId, Nonce);

/// Execution Fee to execute a send or receive request.
#[derive(Default, Debug, Encode, Decode, Clone, Copy, Eq, PartialEq, TypeInfo)]
pub struct ExecutionFee<Balance> {
    /// Fee paid to the relayer pool for the execution.
    pub relayer_pool_fee: Balance,
    /// Fee paid to the network for computation.
    pub compute_fee: Balance,
}

/// Fee model to send a request and receive a response from another domain.
/// A user of the endpoint will pay
///     - outbox_fee on src_domain
///     - inbox_fee on dst_domain
/// The reward is distributed to
///     - src_domain relayer pool when the response is received
///     - dst_domain relayer pool when the response acknowledgement from src_domain.
#[derive(Default, Debug, Encode, Decode, Clone, Copy, Eq, PartialEq, TypeInfo)]
pub struct FeeModel<Balance> {
    /// Fee paid by the endpoint user for any outgoing message.
    pub outbox_fee: ExecutionFee<Balance>,
    /// Fee paid by the endpoint user any incoming message.
    pub inbox_fee: ExecutionFee<Balance>,
}

impl<Balance: CheckedAdd> FeeModel<Balance> {
    pub fn outbox_fee(&self) -> Option<Balance> {
        self.outbox_fee
            .compute_fee
            .checked_add(&self.outbox_fee.relayer_pool_fee)
    }

    pub fn inbox_fee(&self) -> Option<Balance> {
        self.inbox_fee
            .compute_fee
            .checked_add(&self.inbox_fee.relayer_pool_fee)
    }
}

/// Parameters for a new channel between two domains.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Copy)]
pub struct InitiateChannelParams<Balance> {
    pub max_outgoing_messages: u32,
    pub fee_model: FeeModel<Balance>,
}

/// Defines protocol requests performed on domains.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub enum ProtocolMessageRequest<Balance> {
    /// Request to open a channel with foreign domain.
    ChannelOpen(InitiateChannelParams<Balance>),
    /// Request to close an open channel with foreign domain.
    ChannelClose,
}

/// Defines protocol requests performed on domains.
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

/// Message contains information to be sent to or received from another domain
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Message<Balance> {
    /// Domain which initiated this message.
    pub src_domain_id: DomainId,
    /// Domain this message is intended for.
    pub dst_domain_id: DomainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Payload of the message
    pub payload: VersionedPayload<Balance>,
    /// Last delivered message response nonce on src_domain.
    pub last_delivered_message_response_nonce: Option<Nonce>,
}

/// Domain block info used as part of the Cross domain message proof.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct DomainBlockInfo<Number, Hash> {
    /// Block number of the domain.
    pub block_number: Number,
    /// Block hash of the domain.
    pub block_hash: Hash,
}

/// Proof combines the storage proofs to validate messages.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct Proof<BlockNumber, BlockHash, StateRoot> {
    /// System domain block info when proof was constructed
    pub system_domain_block_info: DomainBlockInfo<BlockNumber, BlockHash>,
    /// State root of System domain at above number and block hash.
    /// This is the used to extract the message from proof.
    pub system_domain_state_root: StateRoot,
    /// Storage proof that src core domain state_root is registered on System domain.
    /// This is optional when the src_domain is the system domain.
    /// BlockNumber and BlockHash is used with storage proof to validate and fetch its state root.
    pub core_domain_proof: Option<(DomainBlockInfo<BlockNumber, BlockHash>, StorageProof)>,
    /// Storage proof that message is processed on src_domain.
    pub message_proof: StorageProof,
}

/// Holds the Block info and state roots from which a proof was constructed.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct ExtractedStateRootsFromProof<BlockNumber, BlockHash, StateRoot> {
    /// System domain block info when proof was constructed
    pub system_domain_block_info: DomainBlockInfo<BlockNumber, BlockHash>,
    /// State root of System domain at above number and block hash.
    pub system_domain_state_root: StateRoot,
    /// Storage proof that src core domain state_root is registered on System domain.
    /// This is optional when the src_domain is the system domain.
    /// BlockNumber and BlockHash is used with storage proof to validate and fetch its state root.
    pub core_domain_info: Option<(DomainId, DomainBlockInfo<BlockNumber, BlockHash>, StateRoot)>,
}

/// Cross Domain message contains Message and its proof on src_domain.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct CrossDomainMessage<BlockNumber, BlockHash, StateRoot> {
    /// Domain which initiated this message.
    pub src_domain_id: DomainId,
    /// Domain this message is intended for.
    pub dst_domain_id: DomainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Proof of message processed on src_domain.
    pub proof: Proof<BlockNumber, BlockHash, StateRoot>,
}

impl<BlockNumber, BlockHash, StateRoot> CrossDomainMessage<BlockNumber, BlockHash, StateRoot> {
    /// Extracts state roots.
    /// If the core domain proof is present, then then we construct the trie and extract core domain state root.
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
        let system_domain_state_root = xdm_proof.system_domain_state_root.clone();
        let mut extracted_state_roots = ExtractedStateRootsFromProof {
            system_domain_block_info: xdm_proof.system_domain_block_info,
            system_domain_state_root: xdm_proof.system_domain_state_root,
            core_domain_info: None,
        };

        // verify intermediate core domain proof and retrieve state root of the message.
        let core_domain_state_root_proof = xdm_proof.core_domain_proof;
        // if the src_domain is a system domain, return the state root as is since message is on system domain runtime
        if self.src_domain_id.is_system() && core_domain_state_root_proof.is_none() {
            Some(extracted_state_roots)
        }
        // if the src_domain is a core domain, then return the state root of the core domain by verifying the core domain proof.
        else if self.src_domain_id.is_core() && core_domain_state_root_proof.is_some() {
            let (domain_info, core_domain_state_root_proof) =
                core_domain_state_root_proof.expect("checked for existence value above");
            let core_domain_state_root_key =
                CoreDomainStateRootStorage::<_, _, StateRoot>::storage_key(
                    self.src_domain_id,
                    domain_info.block_number.clone(),
                    domain_info.block_hash.clone(),
                );
            let core_domain_state_root =
                match StorageProofVerifier::<Hashing>::verify_and_get_value::<StateRoot>(
                    &system_domain_state_root.into(),
                    core_domain_state_root_proof,
                    core_domain_state_root_key,
                ) {
                    Ok(result) => result,
                    Err(err) => {
                        log::error!(
                            target: "runtime::messenger",
                            "Failed to verify Core domain proof: {:?}",
                            err
                        );
                        return None;
                    }
                };

            extracted_state_roots.core_domain_info =
                Some((self.src_domain_id, domain_info, core_domain_state_root));

            Some(extracted_state_roots)
        } else {
            None
        }
    }
}

/// Relayer message with storage key to generate storage proof using the backend.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq)]
pub struct RelayerMessageWithStorageKey {
    /// Domain which initiated this message.
    pub src_domain_id: DomainId,
    /// Domain this message is intended for.
    pub dst_domain_id: DomainId,
    /// ChannelId the message was sent through.
    pub channel_id: ChannelId,
    /// Message nonce within the channel.
    pub nonce: Nonce,
    /// Storage key to generate proof for using proof backend.
    pub storage_key: Vec<u8>,
}

/// Set of messages with storage keys to be relayed by a given relayer.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq)]
pub struct RelayerMessagesWithStorageKey {
    pub outbox: Vec<RelayerMessageWithStorageKey>,
    pub inbox_responses: Vec<RelayerMessageWithStorageKey>,
}

impl<BlockNumber, BlockHash, StateRoot> CrossDomainMessage<BlockNumber, BlockHash, StateRoot> {
    pub fn from_relayer_msg_with_proof(
        r_msg: RelayerMessageWithStorageKey,
        proof: Proof<BlockNumber, BlockHash, StateRoot>,
    ) -> Self {
        CrossDomainMessage {
            src_domain_id: r_msg.src_domain_id,
            dst_domain_id: r_msg.dst_domain_id,
            channel_id: r_msg.channel_id,
            nonce: r_msg.nonce,
            proof,
        }
    }
}

type KeyGenerator<Number, Hash> = (
    NMapKey<Twox64Concat, DomainId>,
    NMapKey<Twox64Concat, Number>,
    NMapKey<Twox64Concat, Hash>,
);

/// This is a representation of actual StateRoots storage in pallet-receipts.
/// Any change in key or value there should be changed here accordingly.
pub struct CoreDomainStateRootStorage<Number, Hash, StateRoot>(
    PhantomData<(Number, Hash, StateRoot)>,
);

impl<Number, Hash, StateRoot> StorageNMap<KeyGenerator<Number, Hash>, StateRoot>
    for CoreDomainStateRootStorage<Number, Hash, StateRoot>
where
    Number: FullCodec + TypeInfo + 'static,
    Hash: FullCodec + TypeInfo + 'static,
    StateRoot: FullCodec + TypeInfo + 'static,
{
    type Query = Option<StateRoot>;

    fn module_prefix() -> &'static [u8] {
        "Receipts".as_ref()
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

impl<Number, Hash, StateRoot> CoreDomainStateRootStorage<Number, Hash, StateRoot>
where
    Number: FullCodec + TypeInfo + 'static,
    Hash: FullCodec + TypeInfo + 'static,
    StateRoot: FullCodec + TypeInfo + 'static,
{
    pub fn storage_key(domain_id: DomainId, number: Number, hash: Hash) -> StorageKey {
        StorageKey(
            Self::storage_n_map_final_key::<KeyGenerator<Number, Hash>, _>((
                domain_id, number, hash,
            )),
        )
    }
}

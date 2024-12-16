use codec::{Decode, Encode};
use frame_support::PalletError;
use scale_info::TypeInfo;
use sp_core::storage::StorageKey;
use sp_core::H256;
use sp_domains::proof_provider_and_verifier::{
    StorageProofVerifier, VerificationError as StorageProofVerificationError,
};
use sp_domains::{
    DomainAllowlistUpdates, DomainId, DomainSudoCall, DomainsDigestItem, OpaqueBundle, RuntimeId,
    RuntimeObject,
};
use sp_runtime::generic::Digest;
use sp_runtime::traits::{Block as BlockT, HashingFor, Header as HeaderT, NumberFor};
use sp_runtime_interface::pass_by;
use sp_runtime_interface::pass_by::PassBy;
use sp_std::marker::PhantomData;
use sp_std::vec::Vec;
use sp_trie::StorageProof;
use subspace_core_primitives::Randomness;
use subspace_runtime_primitives::{Balance, BlockTransactionByteFee, Moment};

#[cfg(feature = "std")]
use sc_client_api::ProofProvider;

#[cfg(feature = "std")]
#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    #[error("Failed to generate storage proof")]
    StorageProof,
    #[error("Failed to get storage key")]
    StorageKey,
}

#[derive(Debug, PartialEq, Eq, Encode, Decode, PalletError, TypeInfo)]
pub enum VerificationError {
    InvalidBundleStorageProof,
    RuntimeCodeNotFound,
    UnexpectedDomainRuntimeUpgrade,
    InvalidInherentExtrinsicStorageProof(StorageProofVerificationError),
    TimestampStorageProof(StorageProofVerificationError),
    SuccessfulBundlesStorageProof(StorageProofVerificationError),
    TransactionByteFeeStorageProof(StorageProofVerificationError),
    DomainAllowlistUpdatesStorageProof(StorageProofVerificationError),
    BlockDigestStorageProof(StorageProofVerificationError),
    RuntimeRegistryStorageProof(StorageProofVerificationError),
    DynamicCostOfStorageStorageProof(StorageProofVerificationError),
    DigestStorageProof(StorageProofVerificationError),
    BlockFeesStorageProof(StorageProofVerificationError),
    TransfersStorageProof(StorageProofVerificationError),
    ExtrinsicStorageProof(StorageProofVerificationError),
    DomainSudoCallStorageProof(StorageProofVerificationError),
    MmrRootStorageProof(StorageProofVerificationError),
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub enum FraudProofStorageKeyRequest<Number> {
    InvalidInherentExtrinsicData,
    Timestamp,
    SuccessfulBundles(DomainId),
    TransactionByteFee,
    DomainAllowlistUpdates(DomainId),
    BlockDigest,
    RuntimeRegistry(RuntimeId),
    DynamicCostOfStorage,
    DomainSudoCall(DomainId),
    MmrRoot(Number),
}

impl<Number> FraudProofStorageKeyRequest<Number> {
    fn into_error(self, err: StorageProofVerificationError) -> VerificationError {
        match self {
            Self::InvalidInherentExtrinsicData => {
                VerificationError::InvalidInherentExtrinsicStorageProof(err)
            }
            Self::Timestamp => VerificationError::TimestampStorageProof(err),
            Self::SuccessfulBundles(_) => VerificationError::SuccessfulBundlesStorageProof(err),
            Self::TransactionByteFee => VerificationError::TransactionByteFeeStorageProof(err),
            Self::DomainAllowlistUpdates(_) => {
                VerificationError::DomainAllowlistUpdatesStorageProof(err)
            }
            Self::BlockDigest => VerificationError::BlockDigestStorageProof(err),
            Self::RuntimeRegistry(_) => VerificationError::RuntimeRegistryStorageProof(err),
            Self::DynamicCostOfStorage => VerificationError::DynamicCostOfStorageStorageProof(err),
            FraudProofStorageKeyRequest::DomainSudoCall(_) => {
                VerificationError::DomainSudoCallStorageProof(err)
            }
            Self::MmrRoot(_) => VerificationError::MmrRootStorageProof(err),
        }
    }
}

/// Trait to get storage keys in the runtime i.e. when verifying the storage proof
pub trait FraudProofStorageKeyProvider<Number> {
    fn storage_key(req: FraudProofStorageKeyRequest<Number>) -> Vec<u8>;
}

impl<Number> FraudProofStorageKeyProvider<Number> for () {
    fn storage_key(_req: FraudProofStorageKeyRequest<Number>) -> Vec<u8> {
        Default::default()
    }
}

/// Trait to get storage keys in the client i.e. when generating the storage proof
pub trait FraudProofStorageKeyProviderInstance<Number> {
    fn storage_key(&self, req: FraudProofStorageKeyRequest<Number>) -> Option<Vec<u8>>;
}

macro_rules! impl_storage_proof {
    ($name:ident) => {
        impl From<StorageProof> for $name {
            fn from(sp: StorageProof) -> Self {
                $name(sp)
            }
        }
        impl From<$name> for StorageProof {
            fn from(p: $name) -> StorageProof {
                p.0
            }
        }
    };
}

pub trait BasicStorageProof<Block: BlockT>:
    Into<StorageProof> + From<StorageProof> + Clone
{
    type StorageValue: Decode;
    type Key = ();

    fn storage_key_request(key: Self::Key) -> FraudProofStorageKeyRequest<NumberFor<Block>>;

    #[cfg(feature = "std")]
    fn generate<
        PP: ProofProvider<Block>,
        SKPI: FraudProofStorageKeyProviderInstance<NumberFor<Block>>,
    >(
        proof_provider: &PP,
        block_hash: Block::Hash,
        key: Self::Key,
        storage_key_provider: &SKPI,
    ) -> Result<Self, GenerationError> {
        let storage_key = storage_key_provider
            .storage_key(Self::storage_key_request(key))
            .ok_or(GenerationError::StorageKey)?;
        let storage_proof = proof_provider
            .read_proof(block_hash, &mut [storage_key.as_slice()].into_iter())
            .map_err(|_| GenerationError::StorageProof)?;
        Ok(storage_proof.into())
    }

    fn verify<SKP: FraudProofStorageKeyProvider<NumberFor<Block>>>(
        self,
        key: Self::Key,
        state_root: &Block::Hash,
    ) -> Result<Self::StorageValue, VerificationError> {
        let storage_key_req = Self::storage_key_request(key);
        let storage_key = SKP::storage_key(storage_key_req.clone());
        StorageProofVerifier::<HashingFor<Block>>::get_decoded_value::<Self::StorageValue>(
            state_root,
            self.into(),
            StorageKey(storage_key),
        )
        .map_err(|err| storage_key_req.into_error(err))
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct SuccessfulBundlesProof(StorageProof);

impl_storage_proof!(SuccessfulBundlesProof);
impl<Block: BlockT> BasicStorageProof<Block> for SuccessfulBundlesProof {
    type StorageValue = Vec<H256>;
    type Key = DomainId;
    fn storage_key_request(key: Self::Key) -> FraudProofStorageKeyRequest<NumberFor<Block>> {
        FraudProofStorageKeyRequest::SuccessfulBundles(key)
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct DomainChainsAllowlistUpdateStorageProof(StorageProof);

impl_storage_proof!(DomainChainsAllowlistUpdateStorageProof);
impl<Block: BlockT> BasicStorageProof<Block> for DomainChainsAllowlistUpdateStorageProof {
    type StorageValue = DomainAllowlistUpdates;
    type Key = DomainId;
    fn storage_key_request(key: Self::Key) -> FraudProofStorageKeyRequest<NumberFor<Block>> {
        FraudProofStorageKeyRequest::DomainAllowlistUpdates(key)
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct TimestampStorageProof(StorageProof);

impl_storage_proof!(TimestampStorageProof);
impl<Block: BlockT> BasicStorageProof<Block> for TimestampStorageProof {
    type StorageValue = Moment;
    fn storage_key_request(_key: Self::Key) -> FraudProofStorageKeyRequest<NumberFor<Block>> {
        FraudProofStorageKeyRequest::Timestamp
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct DynamicCostOfStorageProof(StorageProof);

impl_storage_proof!(DynamicCostOfStorageProof);
impl<Block: BlockT> BasicStorageProof<Block> for DynamicCostOfStorageProof {
    type StorageValue = bool;
    fn storage_key_request(_key: Self::Key) -> FraudProofStorageKeyRequest<NumberFor<Block>> {
        FraudProofStorageKeyRequest::DynamicCostOfStorage
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct ConsensusTransactionByteFeeProof(StorageProof);

impl_storage_proof!(ConsensusTransactionByteFeeProof);
impl<Block: BlockT> BasicStorageProof<Block> for ConsensusTransactionByteFeeProof {
    type StorageValue = BlockTransactionByteFee<Balance>;
    fn storage_key_request(_key: Self::Key) -> FraudProofStorageKeyRequest<NumberFor<Block>> {
        FraudProofStorageKeyRequest::TransactionByteFee
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct BlockDigestProof(StorageProof);

impl_storage_proof!(BlockDigestProof);
impl<Block: BlockT> BasicStorageProof<Block> for BlockDigestProof {
    type StorageValue = Digest;
    fn storage_key_request(_key: Self::Key) -> FraudProofStorageKeyRequest<NumberFor<Block>> {
        FraudProofStorageKeyRequest::BlockDigest
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct DomainSudoCallStorageProof(StorageProof);

impl_storage_proof!(DomainSudoCallStorageProof);
impl<Block: BlockT> BasicStorageProof<Block> for DomainSudoCallStorageProof {
    type StorageValue = DomainSudoCall;
    type Key = DomainId;
    fn storage_key_request(key: Self::Key) -> FraudProofStorageKeyRequest<NumberFor<Block>> {
        FraudProofStorageKeyRequest::DomainSudoCall(key)
    }
}

// TODO: get the runtime id from pallet-domains since it won't change for a given domain
// The domain runtime code with storage proof
//
// NOTE: usually we should use the parent consensus block hash to `generate` or `verify` the
// domain runtime code because the domain's `set_code` extrinsic is always the last extrinsic
// to execute thus the domain runtime code will take effect in the next domain block, in other
// word the domain runtime code of the parent consensus block is the one used when constructing
// the `ExecutionReceipt`.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct DomainRuntimeCodeProof(StorageProof);

impl_storage_proof!(DomainRuntimeCodeProof);
impl<Block: BlockT> BasicStorageProof<Block> for DomainRuntimeCodeProof {
    type StorageValue = RuntimeObject<NumberFor<Block>, Block::Hash>;
    type Key = RuntimeId;
    fn storage_key_request(key: Self::Key) -> FraudProofStorageKeyRequest<NumberFor<Block>> {
        FraudProofStorageKeyRequest::RuntimeRegistry(key)
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct OpaqueBundleWithProof<Number, Hash, DomainHeader: HeaderT, Balance> {
    pub bundle: OpaqueBundle<Number, Hash, DomainHeader, Balance>,
    pub bundle_index: u32,
    pub bundle_storage_proof: SuccessfulBundlesProof,
}

impl<Number, Hash, DomainHeader, Balance> OpaqueBundleWithProof<Number, Hash, DomainHeader, Balance>
where
    Number: Encode,
    Hash: Encode,
    DomainHeader: HeaderT,
    Balance: Encode,
{
    #[cfg(feature = "std")]
    #[allow(clippy::let_and_return)]
    pub fn generate<
        Block: BlockT,
        PP: ProofProvider<Block>,
        SKP: FraudProofStorageKeyProviderInstance<NumberFor<Block>>,
    >(
        storage_key_provider: &SKP,
        proof_provider: &PP,
        domain_id: DomainId,
        block_hash: Block::Hash,
        bundle: OpaqueBundle<Number, Hash, DomainHeader, Balance>,
        bundle_index: u32,
    ) -> Result<Self, GenerationError> {
        let bundle_storage_proof = SuccessfulBundlesProof::generate(
            proof_provider,
            block_hash,
            domain_id,
            storage_key_provider,
        )?;

        Ok(OpaqueBundleWithProof {
            bundle,
            bundle_index,
            bundle_storage_proof,
        })
    }

    /// Verify if the `bundle` does commit to the given `state_root`
    pub fn verify<Block: BlockT, SKP: FraudProofStorageKeyProvider<NumberFor<Block>>>(
        &self,
        domain_id: DomainId,
        state_root: &Block::Hash,
    ) -> Result<(), VerificationError> {
        let successful_bundles_at: Vec<H256> =
            <SuccessfulBundlesProof as BasicStorageProof<Block>>::verify::<SKP>(
                self.bundle_storage_proof.clone(),
                domain_id,
                state_root,
            )?;

        successful_bundles_at
            .get(self.bundle_index as usize)
            .filter(|b| **b == self.bundle.hash())
            .ok_or(VerificationError::InvalidBundleStorageProof)?;

        Ok(())
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct MaybeDomainRuntimeUpgradedProof {
    pub block_digest: BlockDigestProof,
    pub new_domain_runtime_code: Option<DomainRuntimeCodeProof>,
}

impl MaybeDomainRuntimeUpgradedProof {
    /// Generate the `MaybeDomainRuntimeUpgradedProof`, it is the caller's responsibility to check
    /// if the domain runtime is upgraded at `block_hash` if so the `maybe_runtime_id` should be `Some`.
    #[cfg(feature = "std")]
    #[allow(clippy::let_and_return)]
    pub fn generate<
        Block: BlockT,
        PP: ProofProvider<Block>,
        SKP: FraudProofStorageKeyProviderInstance<NumberFor<Block>>,
    >(
        storage_key_provider: &SKP,
        proof_provider: &PP,
        block_hash: Block::Hash,
        maybe_runtime_id: Option<RuntimeId>,
    ) -> Result<Self, GenerationError> {
        let block_digest =
            BlockDigestProof::generate(proof_provider, block_hash, (), storage_key_provider)?;
        let new_domain_runtime_code = if let Some(runtime_id) = maybe_runtime_id {
            Some(DomainRuntimeCodeProof::generate(
                proof_provider,
                block_hash,
                runtime_id,
                storage_key_provider,
            )?)
        } else {
            None
        };
        Ok(MaybeDomainRuntimeUpgradedProof {
            block_digest,
            new_domain_runtime_code,
        })
    }

    pub fn verify<Block: BlockT, SKP: FraudProofStorageKeyProvider<NumberFor<Block>>>(
        &self,
        runtime_id: RuntimeId,
        state_root: &Block::Hash,
    ) -> Result<Option<Vec<u8>>, VerificationError> {
        let block_digest = <BlockDigestProof as BasicStorageProof<Block>>::verify::<SKP>(
            self.block_digest.clone(),
            (),
            state_root,
        )?;

        let runtime_upgraded = block_digest
            .logs
            .iter()
            .filter_map(|log| log.as_domain_runtime_upgrade())
            .any(|upgraded_runtime_id| upgraded_runtime_id == runtime_id);

        match (runtime_upgraded, self.new_domain_runtime_code.as_ref()) {
            (true, None) | (false, Some(_)) => {
                Err(VerificationError::UnexpectedDomainRuntimeUpgrade)
            }
            (false, None) => Ok(None),
            (true, Some(runtime_code_proof)) => {
                let mut runtime_obj = <DomainRuntimeCodeProof as BasicStorageProof<Block>>::verify::<
                    SKP,
                >(
                    runtime_code_proof.clone(), runtime_id, state_root
                )?;
                let code = runtime_obj
                    .raw_genesis
                    .take_runtime_code()
                    .ok_or(VerificationError::RuntimeCodeNotFound)?;
                Ok(Some(code))
            }
        }
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidInherentExtrinsicData {
    /// Extrinsics shuffling seed, derived from block randomness
    pub extrinsics_shuffling_seed: Randomness,
}

impl PassBy for InvalidInherentExtrinsicData {
    type PassBy = pass_by::Codec<Self>;
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidInherentExtrinsicDataProof(StorageProof);

impl_storage_proof!(InvalidInherentExtrinsicDataProof);
impl<Block: BlockT> BasicStorageProof<Block> for InvalidInherentExtrinsicDataProof {
    type StorageValue = InvalidInherentExtrinsicData;
    fn storage_key_request(_key: Self::Key) -> FraudProofStorageKeyRequest<NumberFor<Block>> {
        FraudProofStorageKeyRequest::InvalidInherentExtrinsicData
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidInherentExtrinsicProof {
    /// Block timestamp storage proof
    pub timestamp_proof: TimestampStorageProof,

    /// Optional domain runtime code upgrade storage proof
    pub maybe_domain_runtime_upgrade_proof: MaybeDomainRuntimeUpgradedProof,

    /// Boolean indicating if dynamic cost of storage was used (but as a storage proof)
    pub dynamic_cost_of_storage_proof: DynamicCostOfStorageProof,

    /// Transaction fee storage proof
    pub consensus_chain_byte_fee_proof: ConsensusTransactionByteFeeProof,

    /// Change in the allowed chains storage proof
    pub domain_chain_allowlist_proof: DomainChainsAllowlistUpdateStorageProof,
}

/// The verified data from an `InvalidInherentExtrinsicProof`
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct InvalidInherentExtrinsicVerified {
    pub timestamp: Moment,
    pub maybe_domain_runtime_upgrade: Option<Vec<u8>>,
    pub consensus_transaction_byte_fee: Balance,
    pub domain_chain_allowlist: DomainAllowlistUpdates,
}

impl InvalidInherentExtrinsicProof {
    #[cfg(feature = "std")]
    #[allow(clippy::let_and_return)]
    pub fn generate<
        Block: BlockT,
        PP: ProofProvider<Block>,
        SKP: FraudProofStorageKeyProviderInstance<NumberFor<Block>>,
    >(
        storage_key_provider: &SKP,
        proof_provider: &PP,
        domain_id: DomainId,
        block_hash: Block::Hash,
        maybe_runtime_id: Option<RuntimeId>,
    ) -> Result<Self, GenerationError> {
        let timestamp_proof =
            TimestampStorageProof::generate(proof_provider, block_hash, (), storage_key_provider)?;
        let maybe_domain_runtime_upgrade_proof = MaybeDomainRuntimeUpgradedProof::generate(
            storage_key_provider,
            proof_provider,
            block_hash,
            maybe_runtime_id,
        )?;
        let dynamic_cost_of_storage_proof = DynamicCostOfStorageProof::generate(
            proof_provider,
            block_hash,
            (),
            storage_key_provider,
        )?;
        let consensus_chain_byte_fee_proof = ConsensusTransactionByteFeeProof::generate(
            proof_provider,
            block_hash,
            (),
            storage_key_provider,
        )?;
        let domain_chain_allowlist_proof = DomainChainsAllowlistUpdateStorageProof::generate(
            proof_provider,
            block_hash,
            domain_id,
            storage_key_provider,
        )?;

        Ok(Self {
            timestamp_proof,
            maybe_domain_runtime_upgrade_proof,
            dynamic_cost_of_storage_proof,
            consensus_chain_byte_fee_proof,
            domain_chain_allowlist_proof,
        })
    }

    pub fn verify<Block: BlockT, SKP: FraudProofStorageKeyProvider<NumberFor<Block>>>(
        &self,
        domain_id: DomainId,
        runtime_id: RuntimeId,
        state_root: &Block::Hash,
    ) -> Result<InvalidInherentExtrinsicVerified, VerificationError> {
        let timestamp = <TimestampStorageProof as BasicStorageProof<Block>>::verify::<SKP>(
            self.timestamp_proof.clone(),
            (),
            state_root,
        )?;

        let maybe_domain_runtime_upgrade = self
            .maybe_domain_runtime_upgrade_proof
            .verify::<Block, SKP>(runtime_id, state_root)?;

        let dynamic_cost_of_storage =
            <DynamicCostOfStorageProof as BasicStorageProof<Block>>::verify::<SKP>(
                self.dynamic_cost_of_storage_proof.clone(),
                (),
                state_root,
            )?;
        let consensus_transaction_byte_fee = if dynamic_cost_of_storage {
            let raw_transaction_byte_fee =
                <ConsensusTransactionByteFeeProof as BasicStorageProof<Block>>::verify::<SKP>(
                    self.consensus_chain_byte_fee_proof.clone(),
                    (),
                    state_root,
                )?;

            sp_domains::DOMAIN_STORAGE_FEE_MULTIPLIER * raw_transaction_byte_fee.next
        } else {
            Balance::from(1u32)
        };

        let domain_chain_allowlist =
            <DomainChainsAllowlistUpdateStorageProof as BasicStorageProof<Block>>::verify::<SKP>(
                self.domain_chain_allowlist_proof.clone(),
                domain_id,
                state_root,
            )?;

        Ok(InvalidInherentExtrinsicVerified {
            timestamp,
            maybe_domain_runtime_upgrade,
            consensus_transaction_byte_fee,
            domain_chain_allowlist,
        })
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct MmrRootStorageProof<MmrHash> {
    storage_proof: StorageProof,
    _phantom_data: PhantomData<MmrHash>,
}

impl<MmrHash> From<StorageProof> for MmrRootStorageProof<MmrHash> {
    fn from(storage_proof: StorageProof) -> Self {
        MmrRootStorageProof {
            storage_proof,
            _phantom_data: Default::default(),
        }
    }
}

impl<MmrHash> From<MmrRootStorageProof<MmrHash>> for StorageProof {
    fn from(p: MmrRootStorageProof<MmrHash>) -> StorageProof {
        p.storage_proof
    }
}

impl<Block: BlockT, MmrHash: Decode + Clone> BasicStorageProof<Block>
    for MmrRootStorageProof<MmrHash>
{
    type StorageValue = MmrHash;
    type Key = NumberFor<Block>;
    fn storage_key_request(key: Self::Key) -> FraudProofStorageKeyRequest<NumberFor<Block>> {
        FraudProofStorageKeyRequest::MmrRoot(key)
    }
}

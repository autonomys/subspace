use crate::DomainInherentExtrinsicData;
use codec::{Decode, Encode};
use frame_support::PalletError;
use scale_info::TypeInfo;
use sp_core::storage::StorageKey;
use sp_core::H256;
use sp_domains::proof_provider_and_verifier::{
    StorageProofVerifier, VerificationError as StorageProofVerificationError,
};
use sp_domains::{
    DomainAllowlistUpdates, DomainId, DomainsDigestItem, OpaqueBundle, RuntimeId, RuntimeObject,
};
use sp_runtime::generic::Digest;
use sp_runtime::traits::{Block as BlockT, HashingFor, Header as HeaderT, NumberFor};
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
    StorageProof(StorageProofVerificationError),
}

impl From<StorageProofVerificationError> for VerificationError {
    fn from(err: StorageProofVerificationError) -> Self {
        Self::StorageProof(err)
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub enum FraudProofStorageKeyRequest {
    BlockRandomness,
    Timestamp,
    SuccessfulBundles(DomainId),
    TransactionByteFee,
    DomainAllowlistUpdates(DomainId),
    BlockDigest,
    RuntimeRegistry(RuntimeId),
    DynamicCostOfStorage,
}

/// Trait to get storage keys in the runtime i.e. when verifying the storage proof
pub trait FraudProofStorageKeyProvider {
    fn storage_key(req: FraudProofStorageKeyRequest) -> Vec<u8>;
}

impl FraudProofStorageKeyProvider for () {
    fn storage_key(_req: FraudProofStorageKeyRequest) -> Vec<u8> {
        Default::default()
    }
}

/// Trait to get storage keys in the client i.e. when generating the storage proof
pub trait FraudProofStorageKeyProviderInstance {
    fn storage_key(&self, req: FraudProofStorageKeyRequest) -> Option<Vec<u8>>;
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

    fn storage_key_request(key: Self::Key) -> FraudProofStorageKeyRequest;

    #[cfg(feature = "std")]
    fn generate<PP: ProofProvider<Block>, SKPI: FraudProofStorageKeyProviderInstance>(
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

    fn verify<SKP: FraudProofStorageKeyProvider>(
        self,
        key: Self::Key,
        state_root: &Block::Hash,
    ) -> Result<Self::StorageValue, VerificationError> {
        let storage_key = SKP::storage_key(Self::storage_key_request(key));
        Ok(
            StorageProofVerifier::<HashingFor<Block>>::get_decoded_value::<Self::StorageValue>(
                state_root,
                self.into(),
                StorageKey(storage_key),
            )?,
        )
    }
}

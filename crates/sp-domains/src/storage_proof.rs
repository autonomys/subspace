use crate::{DomainId, OpaqueBundle, RuntimeId, RuntimeObject};
use frame_support::storage::generator::StorageMap;
use frame_support::{Identity, PalletError};
use hash_db::Hasher;
use parity_scale_codec::{Decode, Encode, FullCodec};
use scale_info::TypeInfo;
use sp_core::storage::StorageKey;
use sp_core::H256;
use sp_runtime::traits::{Block as BlockT, HashingFor, NumberFor};
use sp_std::marker::PhantomData;
use sp_std::vec::Vec;
use sp_trie::{read_trie_value, LayoutV1, StorageProof};

#[cfg(feature = "std")]
use sc_client_api::ProofProvider;

/// Verification error.
#[derive(Debug, PartialEq, Eq, Encode, Decode, PalletError, TypeInfo)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum VerificationError {
    #[cfg_attr(feature = "thiserror", error("The expected state root doesn't exist"))]
    InvalidStateRoot,
    #[cfg_attr(feature = "thiserror", error("The given storage proof is invalid"))]
    InvalidProof,
    #[cfg_attr(
        feature = "thiserror",
        error("Value doesn't exist in the Db for the given key")
    )]
    MissingValue,
    #[cfg_attr(feature = "thiserror", error("Failed to decode value."))]
    FailedToDecode,
    #[cfg_attr(
        feature = "thiserror",
        error("The given bundle storage proof is invalid")
    )]
    InvalidBundleStorageProof,
    #[cfg_attr(
        feature = "thiserror",
        error("The given domain runtime code storage proof is invalid")
    )]
    InvalidDomainRuntimeCodeStorageProof,
}

pub struct StorageProofVerifier<H: Hasher>(PhantomData<H>);

impl<H: Hasher> StorageProofVerifier<H> {
    pub fn verify_and_get_value<V: Decode>(
        state_root: &H::Out,
        proof: StorageProof,
        key: StorageKey,
    ) -> Result<V, VerificationError> {
        let db = proof.into_memory_db::<H>();
        let val = read_trie_value::<LayoutV1<H>, _>(&db, state_root, key.as_ref(), None, None)
            .map_err(|_| VerificationError::InvalidProof)?
            .ok_or(VerificationError::MissingValue)?;

        let decoded = V::decode(&mut &val[..]).map_err(|_| VerificationError::FailedToDecode)?;

        Ok(decoded)
    }
}

/// This is a representation of actual `SuccessfulBundle` storage in pallet-domains.
/// Any change in key or value there should be changed here accordingly.
pub struct SuccessfulBundlesStorage;
impl StorageMap<DomainId, Vec<H256>> for SuccessfulBundlesStorage {
    type Query = Vec<H256>;
    type Hasher = Identity;

    fn module_prefix() -> &'static [u8] {
        "Domains".as_ref()
    }

    fn storage_prefix() -> &'static [u8] {
        "SuccessfulBundles".as_ref()
    }

    fn from_optional_value_to_query(v: Option<Vec<H256>>) -> Self::Query {
        v.unwrap_or(Default::default())
    }

    fn from_query_to_optional_value(v: Self::Query) -> Option<Vec<H256>> {
        Some(v)
    }
}

#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct OpaqueBundleWithProof<Number, Hash, DomainNumber, DomainHash, Balance> {
    /// The targetted bundle
    pub bundle: OpaqueBundle<Number, Hash, DomainNumber, DomainHash, Balance>,
    /// The index of the bundle
    pub bundle_index: u32,
    /// Storage witness of the targetted valid bundle
    pub bundle_storage_proof: StorageProof,
}

impl<Number, Hash, DomainNumber, DomainHash, Balance>
    OpaqueBundleWithProof<Number, Hash, DomainNumber, DomainHash, Balance>
where
    Number: Encode,
    Hash: Encode,
    DomainNumber: Encode,
    DomainHash: Encode,
    Balance: Encode,
{
    /// Generate `OpaqueBundleWithProof`
    ///
    /// - `block_hash`: the hash of the block that included the `bundle` in the `SuccessfulBundles` state
    /// - `bundle`: the bundle included in `block_hash`
    /// - `bundle_index`: the index of the `bundle` in the `SuccessfulBundles` state
    #[cfg(feature = "std")]
    #[allow(clippy::let_and_return)]
    pub fn generate<Block: BlockT, PP: ProofProvider<Block>>(
        proof_provider: &PP,
        domain_id: DomainId,
        block_hash: Block::Hash,
        bundle: OpaqueBundle<Number, Hash, DomainNumber, DomainHash, Balance>,
        bundle_index: u32,
    ) -> Result<Self, sp_blockchain::Error> {
        let bundle_storage_proof = {
            let key = SuccessfulBundlesStorage::storage_map_final_key(domain_id);
            let proof = proof_provider.read_proof(block_hash, &mut [key.as_slice()].into_iter())?;
            proof
        };
        Ok(OpaqueBundleWithProof {
            bundle,
            bundle_index,
            bundle_storage_proof,
        })
    }

    /// Verify if the `bundle` does commit to the given `state_root`
    pub fn verify<Block: BlockT>(
        &self,
        domain_id: DomainId,
        state_root: &Block::Hash,
    ) -> Result<(), VerificationError> {
        let storage_key = SuccessfulBundlesStorage::storage_map_final_key(domain_id);
        let successful_bundles_at: Vec<H256> =
            StorageProofVerifier::<HashingFor<Block>>::verify_and_get_value(
                state_root,
                self.bundle_storage_proof.clone(),
                StorageKey(storage_key),
            )?;

        successful_bundles_at
            .get(self.bundle_index as usize)
            .filter(|b| **b == self.bundle.hash())
            .ok_or(VerificationError::InvalidBundleStorageProof)?;

        Ok(())
    }
}

/// This is a representation of actual `DomainRuntimeMap` storage in pallet-domains.
/// Any change in key or value there should be changed here accordingly.
pub struct DomainRuntimeMapStorage;
impl StorageMap<DomainId, RuntimeId> for DomainRuntimeMapStorage {
    type Query = Option<RuntimeId>;
    type Hasher = Identity;

    fn module_prefix() -> &'static [u8] {
        "Domains".as_ref()
    }

    fn storage_prefix() -> &'static [u8] {
        "DomainRuntimeMap".as_ref()
    }

    fn from_optional_value_to_query(v: Option<RuntimeId>) -> Self::Query {
        v
    }

    fn from_query_to_optional_value(v: Self::Query) -> Option<RuntimeId> {
        v
    }
}

/// This is a representation of actual `RuntimeRegistry` storage in pallet-domains.
/// Any change in key or value there should be changed here accordingly.
pub struct RuntimeRegistryStorage<Number, Hash>(PhantomData<(Number, Hash)>);
impl<Number, Hash> StorageMap<RuntimeId, RuntimeObject<Number, Hash>>
    for RuntimeRegistryStorage<Number, Hash>
where
    Number: FullCodec + TypeInfo + 'static,
    Hash: FullCodec + TypeInfo + 'static,
{
    type Query = Option<RuntimeObject<Number, Hash>>;
    type Hasher = Identity;

    fn module_prefix() -> &'static [u8] {
        "Domains".as_ref()
    }

    fn storage_prefix() -> &'static [u8] {
        "RuntimeRegistry".as_ref()
    }

    fn from_optional_value_to_query(v: Option<RuntimeObject<Number, Hash>>) -> Self::Query {
        v
    }

    fn from_query_to_optional_value(v: Self::Query) -> Option<RuntimeObject<Number, Hash>> {
        v
    }
}

// The domain runtime code with storage proof
//
// NOTE: usually we should use the parent consensus block hash to `generate` or `verify` the
// domain runtime code because the domain's `set_code` extrinsic is always the last extrinsic
// to execute thus the domain runtime code will take effect in the next domain block, in other
// word the domain runtime code of the parent consensus block is the one used when construting
// the `ExecutionReceipt`.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, TypeInfo)]
pub struct DomainRuntimeCodeWithProof {
    /// Storage witness of the `domain_id` -> `runtime_id` in the `DomainRuntimeMap` state
    pub domain_runtime_storage_proof: StorageProof,
    /// Storage witness of the `RuntimeObject` in the `RuntimeRegistry` state
    pub runtime_registry_storage_proof: StorageProof,
}

impl DomainRuntimeCodeWithProof {
    /// Generate `DomainRuntimeCodeWithProof`
    ///
    /// - `runtime_id`: the `RuntimeId` of the domain runtime
    /// - `block_hash`: the consensus block hash used to get domain runtime code
    ///
    /// NOTE: `block_hash` usually should be the parent hash of `ER::consensus_block_hash`
    /// see the comment of `DomainRuntimeCodeWithProof` for more detail.
    #[cfg(feature = "std")]
    #[allow(clippy::let_and_return)]
    pub fn generate<Block: BlockT, PP: ProofProvider<Block>>(
        proof_provider: &PP,
        domain_id: DomainId,
        runtime_id: RuntimeId,
        block_hash: Block::Hash,
    ) -> Result<Self, sp_blockchain::Error> {
        let domain_runtime_storage_proof = {
            let key = DomainRuntimeMapStorage::storage_map_final_key(domain_id);
            let proof = proof_provider.read_proof(block_hash, &mut [key.as_slice()].into_iter())?;
            proof
        };
        let runtime_registry_storage_proof = {
            let key =
                RuntimeRegistryStorage::<NumberFor<Block>, Block::Hash>::storage_map_final_key(
                    runtime_id,
                );
            let proof = proof_provider.read_proof(block_hash, &mut [key.as_slice()].into_iter())?;
            proof
        };
        Ok(DomainRuntimeCodeWithProof {
            domain_runtime_storage_proof,
            runtime_registry_storage_proof,
        })
    }

    /// Verify if the domain runtime code does commit to the given `state_root`
    ///
    /// NOTE: `state_root` usually should be the state root of the parent block
    /// of `ER::consensus_block_hash`, see the comment of `DomainRuntimeCodeWithProof`
    /// for more detail.
    pub fn verify<Block: BlockT>(
        &self,
        domain_id: DomainId,
        state_root: &Block::Hash,
    ) -> Result<Vec<u8>, VerificationError> {
        let runtime_id = {
            let storage_key = DomainRuntimeMapStorage::storage_map_final_key(domain_id);
            StorageProofVerifier::<HashingFor<Block>>::verify_and_get_value::<RuntimeId>(
                state_root,
                self.domain_runtime_storage_proof.clone(),
                StorageKey(storage_key),
            )?
        };

        let runtime_obj = {
            let storage_key =
                RuntimeRegistryStorage::<NumberFor<Block>, Block::Hash>::storage_map_final_key(
                    runtime_id,
                );

            StorageProofVerifier::<HashingFor<Block>>::verify_and_get_value::<
                RuntimeObject<NumberFor<Block>, Block::Hash>,
            >(
                state_root,
                self.runtime_registry_storage_proof.clone(),
                StorageKey(storage_key),
            )?
        };

        Ok(runtime_obj.code)
    }
}

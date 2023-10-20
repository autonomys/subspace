use crate::ExecutionReceipt;
use frame_support::PalletError;
use hash_db::Hasher;
use parity_scale_codec::{Compact, Decode, Encode};
use scale_info::TypeInfo;
use sp_core::storage::StorageKey;
use sp_runtime::traits::{Block, NumberFor};
use sp_std::fmt::Debug;
use sp_std::marker::PhantomData;
use sp_std::vec::Vec;
use sp_trie::{read_trie_value, LayoutV1, StorageProof};

/// Verification error.
#[derive(Debug, PartialEq, Eq, Encode, Decode, PalletError, TypeInfo)]
pub enum VerificationError {
    /// Emits when the given storage proof is invalid.
    InvalidProof,
    /// Value doesn't exist in the Db for the given key.
    MissingValue,
    /// Failed to decode value.
    FailedToDecode,
    /// Invalid bundle digest
    InvalidBundleDigest,
}

/// Type that provides utilities to verify the storage proof.
pub struct StorageProofVerifier<H: Hasher>(PhantomData<H>);

impl<H: Hasher> StorageProofVerifier<H> {
    /// Extracts the value against a given key and returns a decoded value.
    pub fn get_decoded_value<V: Decode>(
        state_root: &H::Out,
        proof: StorageProof,
        key: StorageKey,
    ) -> Result<V, VerificationError> {
        let val = Self::get_bare_value(state_root, proof, key)?;
        let decoded = V::decode(&mut &val[..]).map_err(|_| VerificationError::FailedToDecode)?;

        Ok(decoded)
    }

    /// Returns the value against a given key.
    pub fn get_bare_value(
        state_root: &H::Out,
        proof: StorageProof,
        key: StorageKey,
    ) -> Result<Vec<u8>, VerificationError> {
        let db = proof.into_memory_db::<H>();
        let val = read_trie_value::<LayoutV1<H>, _>(&db, state_root, key.as_ref(), None, None)
            .map_err(|_| VerificationError::InvalidProof)?
            .ok_or(VerificationError::MissingValue)?;

        Ok(val)
    }

    /// Verifies the given storage proof and checks the expected_value matches the extracted value from the proof.
    pub fn verify_storage_proof(
        proof: StorageProof,
        root: &H::Out,
        expected_value: Vec<u8>,
        storage_key: StorageKey,
    ) -> bool
    where
        H: Hasher,
    {
        if let Ok(got_data) = StorageProofVerifier::<H>::get_bare_value(root, proof, storage_key) {
            expected_value == got_data
        } else {
            false
        }
    }

    /// Constructs the storage key from a given enumerated index.
    pub fn enumerated_storage_key(index: u32) -> StorageKey {
        StorageKey(Compact(index).encode())
    }
}

pub fn verify_invalid_total_rewards_fraud_proof<
    CBlock,
    DomainNumber,
    DomainHash,
    Balance,
    Hashing,
>(
    bad_receipt: ExecutionReceipt<
        NumberFor<CBlock>,
        CBlock::Hash,
        DomainNumber,
        DomainHash,
        Balance,
    >,
    storage_proof: &StorageProof,
) -> Result<(), VerificationError>
where
    CBlock: Block,
    Balance: PartialEq + Decode,
    Hashing: Hasher<Out = CBlock::Hash>,
    DomainHash: Encode,
{
    let state_root = bad_receipt.final_state_root.encode();
    let state_root = CBlock::Hash::decode(&mut state_root.as_slice())
        .map_err(|_| VerificationError::FailedToDecode)?;
    let storage_key = StorageKey(crate::fraud_proof::operator_block_rewards_final_key());
    let storage_proof = storage_proof.clone();

    let total_rewards = StorageProofVerifier::<Hashing>::get_decoded_value::<Balance>(
        &state_root,
        storage_proof,
        storage_key,
    )
    .map_err(|_| VerificationError::InvalidProof)?;

    // if the rewards matches, then this is an invalid fraud proof since rewards must be different.
    if bad_receipt.total_rewards == total_rewards {
        return Err(VerificationError::InvalidProof);
    }

    Ok(())
}

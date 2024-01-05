use frame_support::PalletError;
use hash_db::Hasher;
#[cfg(feature = "std")]
use parity_scale_codec::Codec;
use parity_scale_codec::{Compact, Decode, Encode};
use scale_info::TypeInfo;
use sp_core::storage::StorageKey;
#[cfg(feature = "std")]
use sp_state_machine::prove_read;
#[cfg(feature = "std")]
use sp_state_machine::TrieBackendBuilder;
use sp_std::fmt::Debug;
use sp_std::marker::PhantomData;
use sp_std::vec::Vec;
use sp_trie::{read_trie_value, LayoutV1, StorageProof};
#[cfg(feature = "std")]
use trie_db::{DBValue, TrieDBMutBuilder, TrieLayout, TrieMut};

/// Verification error.
#[derive(Debug, PartialEq, Eq, Encode, Decode, PalletError, TypeInfo)]
pub enum VerificationError {
    /// Emits when the given storage proof is invalid.
    InvalidProof,
    /// Value doesn't exist in the Db for the given key.
    MissingValue,
    /// Failed to decode value.
    FailedToDecode,
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

    /// Constructs the storage key from a given enumerated index.
    pub fn enumerated_storage_key(index: u32) -> StorageKey {
        StorageKey(Compact(index).encode())
    }
}

#[cfg(feature = "std")]
type MemoryDB<T> = memory_db::MemoryDB<
    <T as TrieLayout>::Hash,
    memory_db::HashKey<<T as TrieLayout>::Hash>,
    DBValue,
>;

/// Type that provides utilities to generate the storage proof.
#[cfg(feature = "std")]
pub struct StorageProofProvider<Layout>(PhantomData<Layout>);

#[cfg(feature = "std")]
impl<Layout> StorageProofProvider<Layout>
where
    Layout: TrieLayout,
    <Layout::Hash as Hasher>::Out: Codec,
{
    /// Generate storage proof for given index from the trie constructed from `input`.
    ///
    /// Returns `None` if the given `index` out of range or fail to generate the proof.
    pub fn generate_enumerated_proof_of_inclusion(
        input: &[Vec<u8>],
        index: u32,
    ) -> Option<StorageProof> {
        if input.len() <= index as usize {
            return None;
        }

        let input: Vec<_> = input
            .iter()
            .enumerate()
            .map(|(i, v)| (Compact(i as u32).encode(), v))
            .collect();

        let (db, root) = {
            let mut db = <MemoryDB<Layout>>::default();
            let mut root = Default::default();
            {
                let mut trie = <TrieDBMutBuilder<Layout>>::new(&mut db, &mut root).build();
                for (key, value) in input {
                    trie.insert(&key, value).ok()?;
                }
            }
            (db, root)
        };

        let backend = TrieBackendBuilder::new(db, root).build();
        let key = Compact(index).encode();
        prove_read(backend, &[key]).ok()
    }
}

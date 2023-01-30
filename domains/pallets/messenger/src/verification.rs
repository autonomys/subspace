use crate::{Config, StateRootOf};
use codec::{Decode, Encode};
use frame_support::pallet_prelude::NMapKey;
use frame_support::storage::generator::StorageNMap;
use frame_support::{PalletError, Twox64Concat};
use hash_db::Hasher;
use scale_info::TypeInfo;
use sp_core::storage::StorageKey;
use sp_domains::DomainId;
use sp_std::marker::PhantomData;
use sp_trie::{read_trie_value, LayoutV1, StorageProof};

/// Verification error.
#[derive(Debug, PartialEq, Eq, Encode, Decode, PalletError, TypeInfo)]
pub enum VerificationError {
    /// Emits when the expected state root doesn't exist
    InvalidStateRoot,
    /// Emits when the given storage proof is invalid.
    InvalidProof,
    /// Value doesn't exist in the Db for the given key.
    MissingValue,
    /// Failed to decode value.
    FailedToDecode,
}

pub(crate) struct StorageProofVerifier<H: Hasher>(PhantomData<H>);

impl<H: Hasher> StorageProofVerifier<H> {
    pub(crate) fn verify_and_get_value<V: Decode>(
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

type KeyGenerator<T> = (
    NMapKey<Twox64Concat, DomainId>,
    NMapKey<Twox64Concat, <T as frame_system::Config>::BlockNumber>,
    NMapKey<Twox64Concat, <T as frame_system::Config>::Hash>,
);

pub(crate) struct CoreDomainStateRootStorage<T>(PhantomData<T>);

impl<T: Config> StorageNMap<KeyGenerator<T>, StateRootOf<T>> for CoreDomainStateRootStorage<T> {
    type Query = Option<StateRootOf<T>>;

    fn module_prefix() -> &'static [u8] {
        "Receipts".as_ref()
    }

    fn storage_prefix() -> &'static [u8] {
        "StateRoots".as_ref()
    }

    fn from_optional_value_to_query(v: Option<StateRootOf<T>>) -> Self::Query {
        v
    }

    fn from_query_to_optional_value(v: Self::Query) -> Option<StateRootOf<T>> {
        v
    }
}

impl<T: Config> CoreDomainStateRootStorage<T> {
    pub(crate) fn storage_key(key: (DomainId, T::BlockNumber, T::Hash)) -> StorageKey {
        StorageKey(Self::storage_n_map_final_key::<KeyGenerator<T>, _>(key))
    }
}

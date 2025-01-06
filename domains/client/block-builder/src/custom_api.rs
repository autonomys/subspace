//! Custom API that is efficient to collect storage roots.

use codec::Codec;
use hash_db::{HashDB, Hasher, Prefix};
use sp_state_machine::{DBValue, TrieBackend, TrieBackendBuilder, TrieBackendStorage};
use std::marker::PhantomData;

/// Create a new trie backend with memory DB delta changes.
///
/// This can be used to verify any extrinsic-specific execution on the combined state of `backend`
/// and `delta`.
pub fn create_delta_backend<'a, S, H, DB>(
    backend: &'a TrieBackend<S, H>,
    delta: DB,
    post_delta_root: H::Out,
) -> TrieBackend<DeltaBackend<'a, S, H, DB>, H>
where
    S: 'a + TrieBackendStorage<H>,
    H: 'a + Hasher,
    H::Out: Codec,
    DB: HashDB<H, DBValue>,
{
    let essence = backend.essence();
    let delta_backend = DeltaBackend {
        backend: essence.backend_storage(),
        delta,
        _phantom: PhantomData::<H>,
    };
    TrieBackendBuilder::new(delta_backend, post_delta_root).build()
}

/// DeltaBackend provides the TrieBackend using main backend and some delta changes
/// that are not part of the main backend.
pub struct DeltaBackend<'a, S, H, DB>
where
    S: 'a + TrieBackendStorage<H>,
    H: 'a + Hasher,
    DB: HashDB<H, DBValue>,
{
    backend: &'a S,
    delta: DB,
    _phantom: PhantomData<H>,
}

impl<'a, S, H, DB> TrieBackendStorage<H> for DeltaBackend<'a, S, H, DB>
where
    S: 'a + TrieBackendStorage<H>,
    H: 'a + Hasher,
    DB: HashDB<H, DBValue>,
{
    fn get(&self, key: &H::Out, prefix: Prefix) -> Result<Option<DBValue>, String> {
        match HashDB::get(&self.delta, key, prefix) {
            Some(v) => Ok(Some(v)),
            None => Ok(self.backend.get(key, prefix)?),
        }
    }
}

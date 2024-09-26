//! This module provides the feature of generating and verifying the execution proof used in
//! the Subspace fraud proof mechanism.
//!
//! The execution is more fine-grained than the entire block execution, block execution hooks
//! (`initialize_block` and `finalize_block`) and any specific extrinsic execution are supported.

use crate::fraud_proof::ExecutionPhase;
use codec::Codec;
use hash_db::{HashDB, Hasher, Prefix};
use sc_client_api::backend::Backend;
use sp_api::StorageProof;
use sp_core::traits::CodeExecutor;
use sp_runtime::traits::{Block as BlockT, HashingFor};
use sp_state_machine::backend::AsTrieBackend;
use sp_state_machine::{TrieBackend, TrieBackendBuilder, TrieBackendStorage};
use sp_trie::DBValue;
use std::marker::PhantomData;
use std::sync::Arc;

/// Creates storage proof for verifying an execution without owning the whole state.
pub struct ExecutionProver<Block, B, Exec> {
    backend: Arc<B>,
    executor: Arc<Exec>,
    _phantom: PhantomData<Block>,
}

impl<Block, B, Exec> ExecutionProver<Block, B, Exec>
where
    Block: BlockT,
    B: Backend<Block>,
    Exec: CodeExecutor + 'static,
{
    /// Constructs a new instance of [`ExecutionProver`].
    pub fn new(backend: Arc<B>, executor: Arc<Exec>) -> Self {
        Self {
            backend,
            executor,
            _phantom: PhantomData::<Block>,
        }
    }

    /// Returns a storage proof which can be used to reconstruct a partial state trie to re-run
    /// the execution by someone who does not own the whole state.
    pub fn prove_execution<DB: HashDB<HashingFor<Block>, DBValue>>(
        &self,
        at: Block::Hash,
        execution_phase: &ExecutionPhase,
        call_data: &[u8],
        delta_changes: Option<(DB, Block::Hash)>,
    ) -> sp_blockchain::Result<StorageProof> {
        let state = self.backend.state_at(at)?;

        let trie_backend = state.as_trie_backend();

        let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(trie_backend);
        let runtime_code = state_runtime_code
            .runtime_code()
            .map_err(sp_blockchain::Error::RuntimeCode)?;

        // TODO: avoid using the String API specified by `execution_method()`
        // https://github.com/paritytech/substrate/discussions/11095
        if let Some((delta, post_delta_root)) = delta_changes {
            let delta_backend = create_delta_backend(trie_backend, delta, post_delta_root);
            sp_state_machine::prove_execution_on_trie_backend(
                &delta_backend,
                &mut Default::default(),
                &*self.executor,
                execution_phase.execution_method(),
                call_data,
                &runtime_code,
                &mut Default::default(),
            )
            .map(|(_ret, proof)| proof)
            .map_err(Into::into)
        } else {
            sp_state_machine::prove_execution_on_trie_backend(
                trie_backend,
                &mut Default::default(),
                &*self.executor,
                execution_phase.execution_method(),
                call_data,
                &runtime_code,
                &mut Default::default(),
            )
            .map(|(_ret, proof)| proof)
            .map_err(Into::into)
        }
    }
}

/// Create a new trie backend with memory DB delta changes.
///
/// This can be used to verify any extrinsic-specific execution on the combined state of `backend`
/// and `delta`.
fn create_delta_backend<'a, S, H, DB>(
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

struct DeltaBackend<'a, S, H, DB>
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

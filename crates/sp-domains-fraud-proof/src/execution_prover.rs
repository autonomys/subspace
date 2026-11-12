//! This module provides the feature of generating and verifying the execution proof used in
//! the Subspace fraud proof mechanism.
//!
//! The execution is more fine-grained than the entire block execution, block execution hooks
//! (`initialize_block` and `finalize_block`) and any specific extrinsic execution are supported.

use crate::fraud_proof::ExecutionPhase;
use domain_block_builder::create_delta_backend;
use sc_client_api::backend::Backend;
use sp_api::StorageProof;
use sp_core::traits::CodeExecutor;
use sp_runtime::traits::{Block as BlockT, HashingFor};
use sp_state_machine::BackendTransaction;
use sp_state_machine::backend::AsTrieBackend;
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
    pub fn prove_execution(
        &self,
        at: Block::Hash,
        execution_phase: &ExecutionPhase,
        call_data: &[u8],
        delta_changes: Option<(BackendTransaction<HashingFor<Block>>, Block::Hash)>,
    ) -> sp_blockchain::Result<StorageProof> {
        // Trusted: bounded block-processing context (fraud proof generation)
        let state = self
            .backend
            .state_at(at, sc_client_api::TrieCacheContext::Trusted)?;

        let trie_backend = state.as_trie_backend();

        let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(
            trie_backend,
            sp_state_machine::backend::TryPendingCode::Yes,
        );
        let runtime_code = state_runtime_code
            .runtime_code()
            .map_err(sp_blockchain::Error::RuntimeCode)?;

        // TODO: avoid using the String API specified by `execution_method()`
        // https://github.com/paritytech/substrate/discussions/11095
        if let Some((delta, post_delta_root)) = delta_changes {
            let delta_backend = create_delta_backend(trie_backend, &delta, post_delta_root);
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

#[cfg(test)]
mod tests {
    use sp_core::storage::{StateVersion, well_known_keys};
    use sp_core::traits::FetchRuntimeCode;
    use sp_runtime::traits::BlakeTwo256;
    use sp_state_machine::backend::{BackendRuntimeCode, TryPendingCode};
    use sp_state_machine::new_in_mem;

    #[test]
    fn pending_code_is_read_for_the_upgrade_block() {
        let old_code = vec![1u8; 32];
        let pending_code = vec![2u8; 32];
        let mut backend = new_in_mem::<BlakeTwo256>();
        backend.insert(
            vec![(
                None,
                vec![
                    (well_known_keys::CODE.to_vec(), Some(old_code.clone())),
                    (
                        well_known_keys::PENDING_CODE.to_vec(),
                        Some(pending_code.clone()),
                    ),
                ],
            )],
            StateVersion::V1,
        );

        // The upgrade block carries the new code in `:pending_code`; the prover must read it.
        let runtime_code = BackendRuntimeCode::new(&backend, TryPendingCode::Yes);
        let code = runtime_code
            .fetch_runtime_code()
            .expect("pending runtime code is present");
        assert_eq!(code.as_ref(), pending_code.as_slice());

        // The offchain path keeps the old code.
        let runtime_code = BackendRuntimeCode::new(&backend, TryPendingCode::No);
        let code = runtime_code
            .fetch_runtime_code()
            .expect("runtime code is present");
        assert_eq!(code.as_ref(), old_code.as_slice());
    }
}

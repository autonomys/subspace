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
    use super::*;
    use sc_client_api::backend::{BlockImportOperation, NewBlockState};
    use sc_client_api::in_mem;
    use sp_core::storage::{StateVersion, well_known_keys};
    use sp_core::traits::{CallContext, CodeExecutor, ReadRuntimeVersion, RuntimeCode};
    use sp_runtime::Storage;
    use sp_runtime::generic::{Block, Header};
    use sp_runtime::traits::{BlakeTwo256, Header as HeaderT};
    use sp_runtime::OpaqueExtrinsic;
    use std::sync::Mutex;

    type TestBlock = Block<Header<u32, BlakeTwo256>, OpaqueExtrinsic>;

    /// Records the runtime code the prover hands to the executor without running any wasm.
    #[derive(Clone, Default)]
    struct RecordingExecutor {
        executed_code: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl ReadRuntimeVersion for RecordingExecutor {
        fn read_runtime_version(
            &self,
            _wasm_code: &[u8],
            _ext: &mut dyn sp_core::traits::Externalities,
        ) -> Result<Vec<u8>, String> {
            Err("the prover does not read the runtime version".into())
        }
    }

    impl CodeExecutor for RecordingExecutor {
        type Error = String;

        fn call(
            &self,
            _ext: &mut dyn sp_core::traits::Externalities,
            runtime_code: &RuntimeCode,
            _method: &str,
            _data: &[u8],
            _context: CallContext,
        ) -> (Result<Vec<u8>, String>, bool) {
            let code = runtime_code
                .code_fetcher
                .fetch_runtime_code()
                .expect("the prover passes the runtime code to the executor")
                .into_owned();
            self.executed_code
                .lock()
                .expect("lock is not poisoned")
                .push(code);
            (Ok(Vec::new()), false)
        }
    }

    #[test]
    fn prover_executes_the_pending_code_of_the_upgrade_block() {
        let old_code = vec![1u8; 32];
        let pending_code = vec![2u8; 32];

        let mut genesis_storage = Storage::default();
        genesis_storage
            .top
            .insert(well_known_keys::CODE.to_vec(), old_code);
        genesis_storage
            .top
            .insert(well_known_keys::PENDING_CODE.to_vec(), pending_code.clone());

        let backend = Arc::new(in_mem::Backend::<TestBlock>::new());
        let mut operation = backend
            .begin_operation()
            .expect("in-memory block import operation is created");
        let state_root = operation
            .set_genesis_state(genesis_storage, true, StateVersion::V1)
            .expect("genesis state is set");
        let header = Header::<u32, BlakeTwo256>::new(
            0,
            Default::default(),
            state_root,
            Default::default(),
            Default::default(),
        );
        operation
            .set_block_data(header.clone(), None, None, None, NewBlockState::Final, true)
            .expect("genesis block data is set");
        backend
            .commit_operation(operation)
            .expect("genesis block is committed");

        let executor = Arc::new(RecordingExecutor::default());
        let prover = ExecutionProver::<TestBlock, _, _>::new(backend, executor.clone());
        prover
            .prove_execution(header.hash(), &ExecutionPhase::InitializeBlock, &[], None)
            .expect("execution proof is generated");

        let executed_code = executor
            .executed_code
            .lock()
            .expect("lock is not poisoned")
            .clone();
        assert_eq!(
            executed_code,
            vec![pending_code],
            "the upgrade block must be executed against `:pending_code`, not `:code`"
        );
    }
}

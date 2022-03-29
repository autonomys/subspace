//! Subspace fraud proof
//!
//! This crates provides the feature of generating and verifying the execution proof used in
//! the Subspace fraud proof mechanism. The execution is more fine-grained than the entire
//! block execution, block execution hooks (`initialize_block` and `finalize_block`) and any
//! specific extrinsic execution are supported.

#![warn(missing_docs)]

use codec::{Codec, Decode, Encode};
use hash_db::{HashDB, Hasher, Prefix};
use sc_client_api::backend;
use sc_client_api::execution_extensions::ExtensionsFactory;
use sp_api::{StateBackend, StorageProof};
use sp_core::{
    traits::{CodeExecutor, SpawnNamed},
    H256,
};
use sp_executor::{fraud_proof_ext::FraudProofExt, ExecutionPhase, FraudProof, VerificationError};
use sp_externalities::Extensions;
use sp_runtime::{
    generic::BlockId,
    traits::{BlakeTwo256, Block as BlockT, HashFor},
};
use sp_state_machine::{TrieBackend, TrieBackendStorage};
use sp_trie::DBValue;
use std::marker::PhantomData;
use std::sync::Arc;

/// Returns a storage proof which can be used to reconstruct a partial state trie to re-run
/// the execution by someone who does not own the whole state.
pub fn prove_execution<
    Block: BlockT,
    B: backend::Backend<Block>,
    Exec: CodeExecutor + 'static,
    Spawn: SpawnNamed + Send + 'static,
    DB: HashDB<HashFor<Block>, DBValue>,
>(
    backend: &Arc<B>,
    executor: &Exec,
    spawn_handle: Spawn,
    at: &BlockId<Block>,
    execution_phase: &ExecutionPhase,
    delta_changes: Option<(DB, Block::Hash)>,
) -> sp_blockchain::Result<StorageProof> {
    let state = backend.state_at(*at)?;

    let trie_backend = state.as_trie_backend().ok_or_else(|| {
        Box::new(sp_state_machine::ExecutionError::UnableToGenerateProof)
            as Box<dyn sp_state_machine::Error>
    })?;

    let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(trie_backend);
    let runtime_code = state_runtime_code
        .runtime_code()
        .map_err(sp_blockchain::Error::RuntimeCode)?;

    if let Some((delta, post_delta_root)) = delta_changes {
        let delta_backend = create_delta_backend(trie_backend, delta, post_delta_root);
        sp_state_machine::prove_execution_on_trie_backend(
            &delta_backend,
            &mut Default::default(),
            executor,
            spawn_handle,
            execution_phase.proving_method(),
            execution_phase.call_data(),
            &runtime_code,
        )
        .map(|(_ret, proof)| proof)
        .map_err(Into::into)
    } else {
        sp_state_machine::prove_execution_on_trie_backend(
            trie_backend,
            &mut Default::default(),
            executor,
            spawn_handle,
            execution_phase.proving_method(),
            execution_phase.call_data(),
            &runtime_code,
        )
        .map(|(_ret, proof)| proof)
        .map_err(Into::into)
    }
}

/// Runs the execution using the partial state constructed from the given storage proof and
/// returns the execution result.
///
/// The execution result contains the information of state root after applying the execution
/// so that it can be used to compare with the one specified in the fraud proof.
pub fn check_execution_proof<
    Block: BlockT,
    B: backend::Backend<Block>,
    Exec: CodeExecutor + 'static,
    Spawn: SpawnNamed + Send + 'static,
>(
    backend: &Arc<B>,
    executor: &Exec,
    spawn_handle: Spawn,
    at: &BlockId<Block>,
    execution_phase: &ExecutionPhase,
    pre_execution_root: H256,
    proof: StorageProof,
) -> sp_blockchain::Result<Vec<u8>> {
    let state = backend.state_at(*at)?;

    let trie_backend = state.as_trie_backend().ok_or_else(|| {
        Box::new(sp_state_machine::ExecutionError::UnableToGenerateProof)
            as Box<dyn sp_state_machine::Error>
    })?;

    let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(trie_backend);
    let runtime_code = state_runtime_code
        .runtime_code()
        .map_err(sp_blockchain::Error::RuntimeCode)?;

    sp_state_machine::execution_proof_check::<BlakeTwo256, _, _>(
        pre_execution_root,
        proof,
        &mut Default::default(),
        executor,
        spawn_handle,
        execution_phase.verifying_method(),
        execution_phase.call_data(),
        &runtime_code,
    )
    .map_err(Into::into)
}

/// Create a new trie backend with memory DB delta changes.
///
/// This can be used to verify any extrinsic-specific execution on the combined state of `backend`
/// and `delta`.
fn create_delta_backend<'a, S: 'a + TrieBackendStorage<H>, H: 'a + Hasher, DB: HashDB<H, DBValue>>(
    backend: &'a TrieBackend<S, H>,
    delta: DB,
    post_delta_root: H::Out,
) -> TrieBackend<DeltaBackend<'a, S, H, DB>, H>
where
    H::Out: Codec,
{
    let essence = backend.essence();
    let delta_backend = DeltaBackend {
        backend: essence.backend_storage(),
        delta,
        _phantom: std::marker::PhantomData::<H>,
    };
    TrieBackend::new(delta_backend, post_delta_root)
}

struct DeltaBackend<'a, S: 'a + TrieBackendStorage<H>, H: 'a + Hasher, DB: HashDB<H, DBValue>> {
    backend: &'a S,
    delta: DB,
    _phantom: std::marker::PhantomData<H>,
}

impl<'a, S: 'a + TrieBackendStorage<H>, H: 'a + Hasher, DB: HashDB<H, DBValue>>
    TrieBackendStorage<H> for DeltaBackend<'a, S, H, DB>
{
    type Overlay = S::Overlay;

    fn get(&self, key: &H::Out, prefix: Prefix) -> Result<Option<DBValue>, String> {
        match HashDB::get(&self.delta, key, prefix) {
            Some(v) => Ok(Some(v)),
            None => Ok(self.backend.get(key, prefix)?),
        }
    }
}

/// Fraud proof verifier.
pub struct ProofVerifier<Block, B, Exec, Spawn> {
    backend: Arc<B>,
    executor: Exec,
    spawn_handle: Spawn,
    _phantom: PhantomData<Block>,
}

impl<Block, B, Exec: Clone, Spawn: Clone> Clone for ProofVerifier<Block, B, Exec, Spawn> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            executor: self.executor.clone(),
            spawn_handle: self.spawn_handle.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<
        Block: BlockT,
        B: backend::Backend<Block>,
        Exec: CodeExecutor + Clone + 'static,
        Spawn: SpawnNamed + Clone + Send + 'static,
    > ProofVerifier<Block, B, Exec, Spawn>
{
    /// Constructs a new instance of [`ProofVerifier`].
    pub fn new(backend: Arc<B>, executor: Exec, spawn_handle: Spawn) -> Self {
        Self {
            backend,
            executor,
            spawn_handle,
            _phantom: PhantomData::<Block>,
        }
    }

    fn verify(&self, proof: &FraudProof) -> Result<(), VerificationError> {
        let FraudProof {
            parent_hash,
            pre_state_root,
            post_state_root,
            proof,
            execution_phase,
        } = proof;

        let at = BlockId::Hash(
            Block::Hash::decode(&mut parent_hash.encode().as_slice())
                .expect("Block Hash must be H256; qed"),
        );

        // TODO: ensure the fetched runtime code works as expected.
        let state = self
            .backend
            .state_at(at)
            .map_err(|_| VerificationError::RuntimeCodeBackend)?;

        let trie_backend = state
            .as_trie_backend()
            .ok_or(VerificationError::RuntimeCodeBackend)?;

        let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(trie_backend);
        let runtime_code = state_runtime_code
            .runtime_code()
            .map_err(VerificationError::RuntimeCode)?;

        let execution_result = sp_state_machine::execution_proof_check::<BlakeTwo256, _, _>(
            *pre_state_root,
            proof.clone(),
            &mut Default::default(),
            &self.executor,
            self.spawn_handle.clone(),
            execution_phase.verifying_method(),
            execution_phase.call_data(),
            &runtime_code,
        )
        .map_err(VerificationError::BadProof)?;

        let new_post_state_root =
            execution_phase.decode_execution_result::<Block::Header>(execution_result)?;
        let new_post_state_root = H256::decode(&mut new_post_state_root.encode().as_slice())
            .expect("Block Hash must be H256; qed");

        if new_post_state_root == *post_state_root {
            Ok(())
        } else {
            Err(VerificationError::BadPostStateRoot {
                expected: new_post_state_root,
                got: *post_state_root,
            })
        }
    }
}

impl<
        Block: BlockT,
        B: backend::Backend<Block>,
        Exec: CodeExecutor + Clone + 'static,
        Spawn: SpawnNamed + Clone + Send + 'static,
    > sp_executor::fraud_proof_ext::Externalities for ProofVerifier<Block, B, Exec, Spawn>
{
    fn verify_fraud_proof(&self, proof: &sp_executor::FraudProof) -> bool {
        match self.verify(proof) {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!(target: "fraud_proof", error = ?e, "Fraud proof verification failure");
                false
            }
        }
    }
}

impl<
        Block: BlockT,
        B: backend::Backend<Block> + 'static,
        Exec: CodeExecutor + Clone + Send + Sync,
        Spawn: SpawnNamed + Clone + Send + Sync + 'static,
    > ExtensionsFactory for ProofVerifier<Block, B, Exec, Spawn>
{
    fn extensions_for(&self, _: sp_core::offchain::Capabilities) -> Extensions {
        let mut exts = Extensions::new();
        exts.register(FraudProofExt::new(self.clone()));
        exts
    }
}

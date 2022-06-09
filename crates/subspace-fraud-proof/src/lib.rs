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
use sp_api::{ProvideRuntimeApi, StateBackend, StorageProof};
use sp_core::traits::{CodeExecutor, FetchRuntimeCode, RuntimeCode, SpawnNamed};
use sp_core::H256;
use sp_executor::{ExecutionPhase, ExecutorApi, FraudProof, VerificationError};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, HashFor};
use sp_state_machine::{TrieBackend, TrieBackendStorage};
use sp_trie::DBValue;
use std::marker::PhantomData;
use std::sync::Arc;

/// Creates storage proof for verifying an execution without owning the whole state.
pub struct ExecutionProver<Block, B, Exec> {
    backend: Arc<B>,
    executor: Arc<Exec>,
    spawn_handle: Box<dyn SpawnNamed>,
    _phantom: PhantomData<Block>,
}

impl<Block, B, Exec> ExecutionProver<Block, B, Exec>
where
    Block: BlockT,
    B: backend::Backend<Block>,
    Exec: CodeExecutor + 'static,
{
    /// Constructs a new instance of [`ExecutionProver`].
    pub fn new(backend: Arc<B>, executor: Arc<Exec>, spawn_handle: Box<dyn SpawnNamed>) -> Self {
        Self {
            backend,
            executor,
            spawn_handle,
            _phantom: PhantomData::<Block>,
        }
    }

    /// Returns a storage proof which can be used to reconstruct a partial state trie to re-run
    /// the execution by someone who does not own the whole state.
    pub fn prove_execution<DB: HashDB<HashFor<Block>, DBValue>>(
        &self,
        at: BlockId<Block>,
        execution_phase: &ExecutionPhase,
        delta_changes: Option<(DB, Block::Hash)>,
    ) -> sp_blockchain::Result<StorageProof> {
        let state = self.backend.state_at(at)?;

        let trie_backend = state.as_trie_backend().ok_or_else(|| {
            Box::new(sp_state_machine::ExecutionError::UnableToGenerateProof)
                as Box<dyn sp_state_machine::Error>
        })?;

        let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(trie_backend);
        let runtime_code = state_runtime_code
            .runtime_code()
            .map_err(sp_blockchain::Error::RuntimeCode)?;

        // TODO: avoid using the String API specified by `proving_method()`
        // https://github.com/paritytech/substrate/discussions/11095
        if let Some((delta, post_delta_root)) = delta_changes {
            let delta_backend = create_delta_backend(trie_backend, delta, post_delta_root);
            sp_state_machine::prove_execution_on_trie_backend(
                &delta_backend,
                &mut Default::default(),
                &*self.executor,
                self.spawn_handle.clone(),
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
                &*self.executor,
                self.spawn_handle.clone(),
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
    pub fn check_execution_proof(
        &self,
        at: BlockId<Block>,
        execution_phase: &ExecutionPhase,
        pre_execution_root: H256,
        proof: StorageProof,
    ) -> sp_blockchain::Result<Vec<u8>> {
        let state = self.backend.state_at(at)?;

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
            &*self.executor,
            self.spawn_handle.clone(),
            execution_phase.verifying_method(),
            execution_phase.call_data(),
            &runtime_code,
        )
        .map_err(Into::into)
    }
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
        _phantom: PhantomData::<H>,
    };
    TrieBackend::new(delta_backend, post_delta_root)
}

struct DeltaBackend<'a, S: 'a + TrieBackendStorage<H>, H: 'a + Hasher, DB: HashDB<H, DBValue>> {
    backend: &'a S,
    delta: DB,
    _phantom: PhantomData<H>,
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

struct RuntimCodeFetcher<'a> {
    wasm_bundle: &'a [u8],
}

impl<'a> FetchRuntimeCode for RuntimCodeFetcher<'a> {
    fn fetch_runtime_code(&self) -> Option<std::borrow::Cow<[u8]>> {
        Some(self.wasm_bundle.into())
    }
}

/// Fraud proof verifier.
pub struct ProofVerifier<PBlock, C, B, Exec, Spawn, Hash> {
    client: Arc<C>,
    backend: Arc<B>,
    executor: Exec,
    spawn_handle: Spawn,
    _phantom: PhantomData<(PBlock, Hash)>,
}

impl<PBlock, C, B, Exec: Clone, Spawn: Clone, Hash> Clone
    for ProofVerifier<PBlock, C, B, Exec, Spawn, Hash>
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            backend: self.backend.clone(),
            executor: self.executor.clone(),
            spawn_handle: self.spawn_handle.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<PBlock, C, B, Exec, Spawn, Hash> ProofVerifier<PBlock, C, B, Exec, Spawn, Hash>
where
    PBlock: BlockT,
    C: ProvideRuntimeApi<PBlock> + Send + Sync,
    C::Api: ExecutorApi<PBlock, Hash>,
    B: backend::Backend<PBlock>,
    Exec: CodeExecutor + Clone + 'static,
    Spawn: SpawnNamed + Clone + Send + 'static,
    Hash: Encode + Decode,
{
    /// Constructs a new instance of [`ProofVerifier`].
    pub fn new(client: Arc<C>, backend: Arc<B>, executor: Exec, spawn_handle: Spawn) -> Self {
        Self {
            client,
            backend,
            executor,
            spawn_handle,
            _phantom: PhantomData::<(PBlock, Hash)>,
        }
    }

    /// Verifies the fraud proof.
    pub fn verify(&self, proof: &FraudProof) -> Result<(), VerificationError> {
        let FraudProof {
            parent_hash,
            pre_state_root,
            post_state_root,
            proof,
            execution_phase,
            ..
        } = proof;

        let at = PBlock::Hash::decode(&mut parent_hash.encode().as_slice())
            .expect("Block Hash must be H256; qed");
        let wasm_bundle = self
            .client
            .runtime_api()
            .execution_wasm_bundle(&BlockId::Hash(at))
            .map_err(VerificationError::RuntimeApi)?;

        let code_fetcher = RuntimCodeFetcher {
            wasm_bundle: &wasm_bundle,
        };

        let runtime_code = RuntimeCode {
            code_fetcher: &code_fetcher,
            hash: b"Hash of the code does not matter in terms of the execution proof check"
                .to_vec(),
            heap_pages: None,
        };

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
            execution_phase.decode_execution_result::<PBlock::Header>(execution_result)?;
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

/// Verify fraud proof.
pub trait VerifyFraudProof {
    /// Verifies fraud proof.
    fn verify_fraud_proof(&self, proof: &sp_executor::FraudProof) -> Result<(), VerificationError>;
}

impl<PBlock, C, B, Exec, Spawn, Hash> VerifyFraudProof
    for ProofVerifier<PBlock, C, B, Exec, Spawn, Hash>
where
    PBlock: BlockT,
    C: ProvideRuntimeApi<PBlock> + Send + Sync,
    C::Api: ExecutorApi<PBlock, Hash>,
    B: backend::Backend<PBlock>,
    Exec: CodeExecutor + Clone + 'static,
    Spawn: SpawnNamed + Clone + Send + 'static,
    Hash: Encode + Decode + Send + Sync,
{
    fn verify_fraud_proof(&self, proof: &sp_executor::FraudProof) -> Result<(), VerificationError> {
        self.verify(proof)
    }
}

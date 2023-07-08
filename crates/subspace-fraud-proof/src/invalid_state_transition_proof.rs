//! Invalid state transition proof
//!
//! This module provides the feature of generating and verifying the execution proof used in
//! the Subspace fraud proof mechanism. The execution is more fine-grained than the entire
//! block execution, block execution hooks (`initialize_block` and `finalize_block`) and any
//! specific extrinsic execution are supported.

use crate::domain_extrinsics_builder::BuildDomainExtrinsics;
use crate::verifier_api::VerifierApi;
use codec::{Codec, Decode, Encode};
use domain_runtime_primitives::opaque::Block;
use hash_db::{HashDB, Hasher, Prefix};
use sc_client_api::backend;
use sp_api::{ProvideRuntimeApi, StorageProof};
use sp_core::traits::{CodeExecutor, RuntimeCode};
use sp_core::H256;
use sp_domains::fraud_proof::{ExecutionPhase, InvalidStateTransitionProof, VerificationError};
use sp_domains::DomainsApi;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, HashFor, Header as HeaderT, NumberFor};
use sp_runtime::Digest;
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
    B: backend::Backend<Block>,
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
    pub fn prove_execution<DB: HashDB<HashFor<Block>, DBValue>>(
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

        // TODO: avoid using the String API specified by `proving_method()`
        // https://github.com/paritytech/substrate/discussions/11095
        if let Some((delta, post_delta_root)) = delta_changes {
            let delta_backend = create_delta_backend(trie_backend, delta, post_delta_root);
            sp_state_machine::prove_execution_on_trie_backend(
                &delta_backend,
                &mut Default::default(),
                &*self.executor,
                execution_phase.proving_method(),
                call_data,
                &runtime_code,
                Default::default(),
            )
            .map(|(_ret, proof)| proof)
            .map_err(Into::into)
        } else {
            sp_state_machine::prove_execution_on_trie_backend(
                trie_backend,
                &mut Default::default(),
                &*self.executor,
                execution_phase.proving_method(),
                call_data,
                &runtime_code,
                Default::default(),
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
        at: Block::Hash,
        execution_phase: &ExecutionPhase,
        call_data: &[u8],
        pre_execution_root: H256,
        proof: StorageProof,
    ) -> sp_blockchain::Result<Vec<u8>> {
        let state = self.backend.state_at(at)?;

        let trie_backend = state.as_trie_backend();

        let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(trie_backend);
        let runtime_code = state_runtime_code
            .runtime_code()
            .map_err(sp_blockchain::Error::RuntimeCode)?;

        sp_state_machine::execution_proof_check::<BlakeTwo256, _>(
            pre_execution_root,
            proof,
            &mut Default::default(),
            &*self.executor,
            execution_phase.verifying_method(),
            call_data,
            &runtime_code,
        )
        .map_err(Into::into)
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
    type Overlay = S::Overlay;

    fn get(&self, key: &H::Out, prefix: Prefix) -> Result<Option<DBValue>, String> {
        match HashDB::get(&self.delta, key, prefix) {
            Some(v) => Ok(Some(v)),
            None => Ok(self.backend.get(key, prefix)?),
        }
    }
}

/// Invalid state transition proof verifier.
pub struct InvalidStateTransitionProofVerifier<
    CBlock,
    CClient,
    Exec,
    Hash,
    VerifierClient,
    DomainExtrinsicsBuilder,
> {
    consensus_client: Arc<CClient>,
    executor: Exec,
    verifier_client: VerifierClient,
    domain_extrinsics_builder: DomainExtrinsicsBuilder,
    _phantom: PhantomData<(CBlock, Hash)>,
}

impl<CBlock, CClient, Exec, Hash, VerifierClient, DomainExtrinsicsBuilder> Clone
    for InvalidStateTransitionProofVerifier<
        CBlock,
        CClient,
        Exec,
        Hash,
        VerifierClient,
        DomainExtrinsicsBuilder,
    >
where
    Exec: Clone,
    VerifierClient: Clone,
    DomainExtrinsicsBuilder: Clone,
{
    fn clone(&self) -> Self {
        Self {
            consensus_client: self.consensus_client.clone(),
            executor: self.executor.clone(),
            verifier_client: self.verifier_client.clone(),
            domain_extrinsics_builder: self.domain_extrinsics_builder.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<CBlock, CClient, Exec, Hash, VerifierClient, DomainExtrinsicsBuilder>
    InvalidStateTransitionProofVerifier<
        CBlock,
        CClient,
        Exec,
        Hash,
        VerifierClient,
        DomainExtrinsicsBuilder,
    >
where
    CBlock: BlockT,
    H256: Into<CBlock::Hash>,
    CClient: ProvideRuntimeApi<CBlock> + Send + Sync,
    CClient::Api: DomainsApi<CBlock, domain_runtime_primitives::BlockNumber, Hash>,
    Exec: CodeExecutor + Clone + 'static,
    Hash: Encode + Decode,
    VerifierClient: VerifierApi,
    DomainExtrinsicsBuilder: BuildDomainExtrinsics<CBlock>,
{
    /// Constructs a new instance of [`InvalidStateTransitionProofVerifier`].
    pub fn new(
        consensus_client: Arc<CClient>,
        executor: Exec,
        verifier_client: VerifierClient,
        domain_extrinsics_builder: DomainExtrinsicsBuilder,
    ) -> Self {
        Self {
            consensus_client,
            executor,
            verifier_client,
            domain_extrinsics_builder,
            _phantom: PhantomData::<(CBlock, Hash)>,
        }
    }

    /// Verifies the invalid state transition proof.
    pub fn verify(
        &self,
        invalid_state_transition_proof: &InvalidStateTransitionProof,
    ) -> Result<(), VerificationError> {
        self.verifier_client
            .verify_pre_state_root(invalid_state_transition_proof)?;

        self.verifier_client
            .verify_post_state_root(invalid_state_transition_proof)?;

        let InvalidStateTransitionProof {
            domain_id,
            parent_number,
            consensus_parent_hash,
            pre_state_root,
            post_state_root,
            proof,
            execution_phase,
            ..
        } = invalid_state_transition_proof;

        let domain_runtime_code = crate::domain_runtime_code::retrieve_domain_runtime_code(
            *domain_id,
            (*consensus_parent_hash).into(),
            &self.consensus_client,
        )?;

        let runtime_code = RuntimeCode {
            code_fetcher: &domain_runtime_code.as_runtime_code_fetcher(),
            hash: b"Hash of the code does not matter in terms of the execution proof check"
                .to_vec(),
            heap_pages: None,
        };

        let call_data = match execution_phase {
            ExecutionPhase::InitializeBlock { domain_parent_hash } => {
                let parent_hash =
                    <Block as BlockT>::Hash::decode(&mut domain_parent_hash.encode().as_slice())?;
                let parent_number =
                    <NumberFor<Block>>::decode(&mut parent_number.encode().as_slice())?;

                let consensus_block_number = parent_number + 1;
                let new_header = <Block as BlockT>::Header::new(
                    consensus_block_number,
                    Default::default(),
                    Default::default(),
                    parent_hash,
                    Digest::default(),
                );
                new_header.encode()
            }
            ExecutionPhase::ApplyExtrinsic(extrinsic_index) => {
                let consensus_block_hash = self
                    .verifier_client
                    .primary_hash(*domain_id, parent_number + 1)?;
                let domain_extrinsics = self
                    .domain_extrinsics_builder
                    .build_domain_extrinsics(
                        *domain_id,
                        consensus_block_hash.into(),
                        domain_runtime_code.wasm_bundle.to_vec(),
                    )
                    .map_err(|_| VerificationError::FailedToBuildDomainExtrinsics)?;
                domain_extrinsics
                    .into_iter()
                    .nth(*extrinsic_index as usize)
                    .ok_or(VerificationError::DomainExtrinsicNotFound(*extrinsic_index))?
            }
            ExecutionPhase::FinalizeBlock { .. } => Vec::new(),
        };

        let execution_result = sp_state_machine::execution_proof_check::<BlakeTwo256, _>(
            *pre_state_root,
            proof.clone(),
            &mut Default::default(),
            &self.executor,
            execution_phase.verifying_method(),
            &call_data,
            &runtime_code,
        )
        .map_err(VerificationError::BadProof)?;

        let new_post_state_root =
            execution_phase.decode_execution_result::<CBlock::Header>(execution_result)?;
        let new_post_state_root = H256::decode(&mut new_post_state_root.encode().as_slice())?;

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

/// Verifies invalid state transition proof.
pub trait VerifyInvalidStateTransitionProof {
    /// Returns `Ok(())` if given `invalid_state_transition_proof` is legitimate.
    fn verify_invalid_state_transition_proof(
        &self,
        invalid_state_transition_proof: &InvalidStateTransitionProof,
    ) -> Result<(), VerificationError>;
}

impl<CBlock, C, Exec, Hash, VerifierClient, DomainExtrinsicsBuilder>
    VerifyInvalidStateTransitionProof
    for InvalidStateTransitionProofVerifier<
        CBlock,
        C,
        Exec,
        Hash,
        VerifierClient,
        DomainExtrinsicsBuilder,
    >
where
    CBlock: BlockT,
    H256: Into<CBlock::Hash>,
    C: ProvideRuntimeApi<CBlock> + Send + Sync,
    C::Api: DomainsApi<CBlock, domain_runtime_primitives::BlockNumber, Hash>,
    Exec: CodeExecutor + Clone + 'static,
    Hash: Encode + Decode,
    VerifierClient: VerifierApi,
    DomainExtrinsicsBuilder: BuildDomainExtrinsics<CBlock>,
{
    fn verify_invalid_state_transition_proof(
        &self,
        invalid_state_transition_proof: &InvalidStateTransitionProof,
    ) -> Result<(), VerificationError> {
        self.verify(invalid_state_transition_proof)
    }
}

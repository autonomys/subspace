//! Invalid state transition proof
//!
//! This module provides the feature of generating and verifying the execution proof used in
//! the Subspace fraud proof mechanism. The execution is more fine-grained than the entire
//! block execution, block execution hooks (`initialize_block` and `finalize_block`) and any
//! specific extrinsic execution are supported.

use crate::domain_extrinsics_builder::BuildDomainExtrinsics;
use codec::{Codec, Decode, Encode};
use domain_runtime_primitives::opaque::Block;
use hash_db::{HashDB, Hasher, Prefix};
use sc_client_api::{backend, HeaderBackend};
use sp_api::{ProvideRuntimeApi, StorageProof};
use sp_core::traits::{CodeExecutor, FetchRuntimeCode, RuntimeCode, SpawnNamed};
use sp_core::H256;
use sp_domain_digests::AsPredigest;
use sp_domains::fraud_proof::{ExecutionPhase, InvalidStateTransitionProof, VerificationError};
use sp_domains::{DomainId, ExecutorApi};
use sp_receipts::ReceiptsApi;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, HashFor, Header as HeaderT, NumberFor};
use sp_runtime::{Digest, DigestItem};
use sp_state_machine::backend::AsTrieBackend;
use sp_state_machine::{TrieBackend, TrieBackendBuilder, TrieBackendStorage};
use sp_trie::DBValue;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_wasm_tools::read_core_domain_runtime_blob;

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
                self.spawn_handle.clone(),
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
                self.spawn_handle.clone(),
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

        sp_state_machine::execution_proof_check::<BlakeTwo256, _, _>(
            pre_execution_root,
            proof,
            &mut Default::default(),
            &*self.executor,
            self.spawn_handle.clone(),
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

struct RuntimCodeFetcher<'a> {
    wasm_bundle: &'a [u8],
}

impl<'a> FetchRuntimeCode for RuntimCodeFetcher<'a> {
    fn fetch_runtime_code(&self) -> Option<std::borrow::Cow<[u8]>> {
        Some(self.wasm_bundle.into())
    }
}

/// Invalid state transition proof verifier.
pub struct InvalidStateTransitionProofVerifier<
    PBlock,
    C,
    Exec,
    Spawn,
    Hash,
    PrePostStateRootVerifier,
    DomainExtrinsicsBuilder,
> {
    client: Arc<C>,
    executor: Exec,
    spawn_handle: Spawn,
    pre_post_state_root_verifier: PrePostStateRootVerifier,
    domain_extrinsics_builder: DomainExtrinsicsBuilder,
    _phantom: PhantomData<(PBlock, Hash)>,
}

impl<PBlock, C, Exec, Spawn, Hash, PrePostStateRootVerifier, DomainExtrinsicsBuilder> Clone
    for InvalidStateTransitionProofVerifier<
        PBlock,
        C,
        Exec,
        Spawn,
        Hash,
        PrePostStateRootVerifier,
        DomainExtrinsicsBuilder,
    >
where
    Exec: Clone,
    Spawn: Clone,
    PrePostStateRootVerifier: Clone,
    DomainExtrinsicsBuilder: Clone,
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            executor: self.executor.clone(),
            spawn_handle: self.spawn_handle.clone(),
            pre_post_state_root_verifier: self.pre_post_state_root_verifier.clone(),
            domain_extrinsics_builder: self.domain_extrinsics_builder.clone(),
            _phantom: self._phantom,
        }
    }
}

/// Verifies `pre_state_root` and `post_state_root` in [`InvalidStateTransitionProof`].
pub trait VerifyPrePostStateRoot {
    /// Verifies whether `pre_state_root` declared in the proof is same as the one recorded on chain.
    fn verify_pre_state_root(
        &self,
        invalid_state_transition_proof: &InvalidStateTransitionProof,
    ) -> Result<(), VerificationError>;

    /// Verifies whether `post_state_root` declared in the proof is different from the one recorded on chain.
    fn verify_post_state_root(
        &self,
        invalid_state_transition_proof: &InvalidStateTransitionProof,
    ) -> Result<(), VerificationError>;

    /// Returns the hash of primary block at height `domain_block_number`.
    fn primary_hash(
        &self,
        domain_id: DomainId,
        domain_block_number: u32,
    ) -> Result<H256, VerificationError>;
}

/// Verifier of `pre_state_root` in [`InvalidStateTransitionProof`].
///
/// `client` could be either the primary chain client or system domain client.
pub struct PrePostStateRootVerifier<Client, Block> {
    client: Arc<Client>,
    _phantom: PhantomData<Block>,
}

impl<Client, Block> Clone for PrePostStateRootVerifier<Client, Block> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<Client, Block> PrePostStateRootVerifier<Client, Block> {
    /// Constructs a new instance of [`PrePostStateRootVerifier`].
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            _phantom: Default::default(),
        }
    }
}

impl<Client, Block> VerifyPrePostStateRoot for PrePostStateRootVerifier<Client, Block>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: ReceiptsApi<Block, domain_runtime_primitives::Hash>,
{
    // TODO: It's not necessary to require `pre_state_root` in the proof and then verify, it can
    // be just retrieved by the verifier itself according the execution phase, which requires some
    // fixes in tests however, we can do this refactoring once we have or are able to construct a
    // proper `VerifyPrePostStateRoot` implementation in test.
    //
    // Related: https://github.com/subspace/subspace/pull/1240#issuecomment-1476212007
    fn verify_pre_state_root(
        &self,
        invalid_state_transition_proof: &InvalidStateTransitionProof,
    ) -> Result<(), VerificationError> {
        let InvalidStateTransitionProof {
            domain_id,
            parent_number,
            bad_receipt_hash,
            pre_state_root,
            execution_phase,
            ..
        } = invalid_state_transition_proof;

        let pre_state_root_onchain = match execution_phase {
            ExecutionPhase::InitializeBlock { domain_parent_hash } => {
                self.client.runtime_api().state_root(
                    self.client.info().best_hash,
                    *domain_id,
                    NumberFor::<Block>::from(*parent_number),
                    Block::Hash::decode(&mut domain_parent_hash.encode().as_slice())?,
                )?
            }
            ExecutionPhase::ApplyExtrinsic(trace_index_of_pre_state_root)
            | ExecutionPhase::FinalizeBlock {
                total_extrinsics: trace_index_of_pre_state_root,
            } => {
                let trace = self.client.runtime_api().execution_trace(
                    self.client.info().best_hash,
                    *domain_id,
                    *bad_receipt_hash,
                )?;

                trace.get(*trace_index_of_pre_state_root as usize).copied()
            }
        };

        match pre_state_root_onchain {
            Some(expected_pre_state_root) if expected_pre_state_root == *pre_state_root => Ok(()),
            res => {
                tracing::debug!(
                    "Invalid `pre_state_root` in InvalidStateTransitionProof for {domain_id:?}, expected: {res:?}, got: {pre_state_root:?}",
                );
                Err(VerificationError::InvalidPreStateRoot)
            }
        }
    }

    fn verify_post_state_root(
        &self,
        invalid_state_transition_proof: &InvalidStateTransitionProof,
    ) -> Result<(), VerificationError> {
        let InvalidStateTransitionProof {
            domain_id,
            bad_receipt_hash,
            execution_phase,
            post_state_root,
            ..
        } = invalid_state_transition_proof;

        let trace = self.client.runtime_api().execution_trace(
            self.client.info().best_hash,
            *domain_id,
            *bad_receipt_hash,
        )?;

        let post_state_root_onchain = match execution_phase {
            ExecutionPhase::InitializeBlock { .. } => trace
                .get(0)
                .ok_or(VerificationError::PostStateRootNotFound)?,
            ExecutionPhase::ApplyExtrinsic(trace_index_of_post_state_root)
            | ExecutionPhase::FinalizeBlock {
                total_extrinsics: trace_index_of_post_state_root,
            } => trace
                .get(*trace_index_of_post_state_root as usize + 1)
                .ok_or(VerificationError::PostStateRootNotFound)?,
        };

        if post_state_root_onchain == post_state_root {
            Err(VerificationError::SamePostStateRoot)
        } else {
            Ok(())
        }
    }

    fn primary_hash(
        &self,
        domain_id: DomainId,
        domain_block_number: u32,
    ) -> Result<H256, VerificationError> {
        self.client
            .runtime_api()
            .primary_hash(
                self.client.info().best_hash,
                domain_id,
                domain_block_number.into(),
            )?
            .and_then(|primary_hash| Decode::decode(&mut primary_hash.encode().as_slice()).ok())
            .ok_or(VerificationError::PrimaryHashNotFound)
    }
}

impl<PBlock, C, Exec, Spawn, Hash, PrePostStateRootVerifier, DomainExtrinsicsBuilder>
    InvalidStateTransitionProofVerifier<
        PBlock,
        C,
        Exec,
        Spawn,
        Hash,
        PrePostStateRootVerifier,
        DomainExtrinsicsBuilder,
    >
where
    PBlock: BlockT,
    H256: Into<PBlock::Hash>,
    C: ProvideRuntimeApi<PBlock> + Send + Sync,
    C::Api: ExecutorApi<PBlock, Hash>,
    Exec: CodeExecutor + Clone + 'static,
    Spawn: SpawnNamed + Clone + Send + 'static,
    Hash: Encode + Decode,
    PrePostStateRootVerifier: VerifyPrePostStateRoot,
    DomainExtrinsicsBuilder: BuildDomainExtrinsics<PBlock>,
{
    /// Constructs a new instance of [`InvalidStateTransitionProofVerifier`].
    pub fn new(
        client: Arc<C>,
        executor: Exec,
        spawn_handle: Spawn,
        pre_post_state_root_verifier: PrePostStateRootVerifier,
        domain_extrinsics_builder: DomainExtrinsicsBuilder,
    ) -> Self {
        Self {
            client,
            executor,
            spawn_handle,
            pre_post_state_root_verifier,
            domain_extrinsics_builder,
            _phantom: PhantomData::<(PBlock, Hash)>,
        }
    }

    /// Verifies the invalid state transition proof.
    pub fn verify(
        &self,
        invalid_state_transition_proof: &InvalidStateTransitionProof,
    ) -> Result<(), VerificationError> {
        self.pre_post_state_root_verifier
            .verify_pre_state_root(invalid_state_transition_proof)?;

        self.pre_post_state_root_verifier
            .verify_post_state_root(invalid_state_transition_proof)?;

        let InvalidStateTransitionProof {
            domain_id,
            parent_number,
            primary_parent_hash,
            pre_state_root,
            post_state_root,
            proof,
            execution_phase,
            ..
        } = invalid_state_transition_proof;

        let at = PBlock::Hash::decode(&mut primary_parent_hash.encode().as_slice())?;
        let system_wasm_bundle = self
            .client
            .runtime_api()
            .system_domain_wasm_bundle(at)
            .map_err(VerificationError::RuntimeApi)?;

        let wasm_bundle = match *domain_id {
            DomainId::SYSTEM => system_wasm_bundle,
            DomainId::CORE_PAYMENTS | DomainId::CORE_ETH_RELAY => {
                read_core_domain_runtime_blob(system_wasm_bundle.as_ref(), *domain_id)
                    .map_err(|err| {
                        VerificationError::RuntimeCode(format!(
                    "failed to read core domain {domain_id:?} runtime blob file, error {err:?}"
                ))
                    })?
                    .into()
            }
            _ => {
                return Err(VerificationError::RuntimeCode(format!(
                    "No runtime code for {domain_id:?}"
                )));
            }
        };

        let code_fetcher = RuntimCodeFetcher {
            wasm_bundle: &wasm_bundle,
        };

        let runtime_code = RuntimeCode {
            code_fetcher: &code_fetcher,
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

                let primary_number = parent_number + 1;
                let digest = if domain_id.is_system() {
                    let primary_hash = self
                        .pre_post_state_root_verifier
                        .primary_hash(*domain_id, primary_number)?;
                    Digest {
                        logs: vec![DigestItem::primary_block_info::<NumberFor<Block>, _>((
                            primary_number,
                            primary_hash,
                        ))],
                    }
                } else {
                    Default::default()
                };
                let new_header = <Block as BlockT>::Header::new(
                    primary_number,
                    Default::default(),
                    Default::default(),
                    parent_hash,
                    digest,
                );
                new_header.encode()
            }
            ExecutionPhase::ApplyExtrinsic(extrinsic_index) => {
                let primary_hash = self
                    .pre_post_state_root_verifier
                    .primary_hash(*domain_id, parent_number + 1)?;
                let domain_extrinsics = self
                    .domain_extrinsics_builder
                    .build_domain_extrinsics(*domain_id, primary_hash.into(), wasm_bundle.to_vec())
                    .map_err(|_| VerificationError::FailedToBuildDomainExtrinsics)?;
                domain_extrinsics
                    .into_iter()
                    .nth(*extrinsic_index as usize)
                    .ok_or(VerificationError::DomainExtrinsicNotFound(*extrinsic_index))?
            }
            ExecutionPhase::FinalizeBlock { .. } => Vec::new(),
        };

        let execution_result = sp_state_machine::execution_proof_check::<BlakeTwo256, _, _>(
            *pre_state_root,
            proof.clone(),
            &mut Default::default(),
            &self.executor,
            self.spawn_handle.clone(),
            execution_phase.verifying_method(),
            &call_data,
            &runtime_code,
        )
        .map_err(VerificationError::BadProof)?;

        let new_post_state_root =
            execution_phase.decode_execution_result::<PBlock::Header>(execution_result)?;
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

impl<PBlock, C, Exec, Spawn, Hash, PrePostStateRootVerifier, DomainExtrinsicsBuilder>
    VerifyInvalidStateTransitionProof
    for InvalidStateTransitionProofVerifier<
        PBlock,
        C,
        Exec,
        Spawn,
        Hash,
        PrePostStateRootVerifier,
        DomainExtrinsicsBuilder,
    >
where
    PBlock: BlockT,
    H256: Into<PBlock::Hash>,
    C: ProvideRuntimeApi<PBlock> + Send + Sync,
    C::Api: ExecutorApi<PBlock, Hash>,
    Exec: CodeExecutor + Clone + 'static,
    Spawn: SpawnNamed + Clone + Send + 'static,
    Hash: Encode + Decode,
    PrePostStateRootVerifier: VerifyPrePostStateRoot,
    DomainExtrinsicsBuilder: BuildDomainExtrinsics<PBlock>,
{
    fn verify_invalid_state_transition_proof(
        &self,
        invalid_state_transition_proof: &InvalidStateTransitionProof,
    ) -> Result<(), VerificationError> {
        self.verify(invalid_state_transition_proof)
    }
}

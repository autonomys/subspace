//! Subspace fraud proof
//!
//! This crates provides the feature of generating and verifying the execution proof used in
//! the Subspace fraud proof mechanism. The execution is more fine-grained than the entire
//! block execution, block execution hooks (`initialize_block` and `finalize_block`) and any
//! specific extrinsic execution are supported.

#![warn(missing_docs)]

mod invalid_state_transition_proof;
#[cfg(test)]
mod tests;

use codec::{Decode, Encode};
use invalid_state_transition_proof::InvalidStateTransitionProofVerifier;
pub use invalid_state_transition_proof::{
    ExecutionProver, PreStateRootVerifier, VerifyPreStateRoot,
};
use sp_api::ProvideRuntimeApi;
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_domains::fraud_proof::{FraudProof, VerificationError};
use sp_domains::ExecutorApi;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::marker::PhantomData;
use std::sync::Arc;

/// Verify fraud proof.
pub trait VerifyFraudProof<FPBlock: BlockT> {
    /// Verifies fraud proof.
    fn verify_fraud_proof(
        &self,
        proof: &FraudProof<NumberFor<FPBlock>, FPBlock::Hash>,
    ) -> Result<(), VerificationError>;
}

/// Fraud proof verifier.
pub struct ProofVerifier<FPBlock, PBlock, C, Exec, Spawn, Hash, PreStateRootVerifier> {
    invalid_state_transition_proof_verifier:
        InvalidStateTransitionProofVerifier<PBlock, C, Exec, Spawn, Hash, PreStateRootVerifier>,
    _phantom: PhantomData<FPBlock>,
}

impl<FPBlock, PBlock, C, Exec: Clone, Spawn: Clone, Hash, PreStateRootVerifier: Clone> Clone
    for ProofVerifier<FPBlock, PBlock, C, Exec, Spawn, Hash, PreStateRootVerifier>
{
    fn clone(&self) -> Self {
        Self {
            invalid_state_transition_proof_verifier: self
                .invalid_state_transition_proof_verifier
                .clone(),
            _phantom: self._phantom,
        }
    }
}

impl<FPBlock, PBlock, C, Exec, Spawn, Hash, PreStateRootVerifier>
    ProofVerifier<FPBlock, PBlock, C, Exec, Spawn, Hash, PreStateRootVerifier>
where
    FPBlock: BlockT,
    PBlock: BlockT,
    C: ProvideRuntimeApi<PBlock> + Send + Sync,
    C::Api: ExecutorApi<PBlock, Hash>,
    Exec: CodeExecutor + Clone + 'static,
    Spawn: SpawnNamed + Clone + Send + 'static,
    Hash: Encode + Decode,
    PreStateRootVerifier: VerifyPreStateRoot,
{
    /// Constructs a new instance of [`ProofVerifier`].
    pub fn new(
        client: Arc<C>,
        executor: Exec,
        spawn_handle: Spawn,
        pre_state_root_verifier: PreStateRootVerifier,
    ) -> Self {
        let invalid_state_transition_proof_verifier = InvalidStateTransitionProofVerifier::new(
            client,
            executor,
            spawn_handle,
            pre_state_root_verifier,
        );
        Self {
            invalid_state_transition_proof_verifier,
            _phantom: Default::default(),
        }
    }

    /// Verifies the fraud proof.
    pub fn verify(
        &self,
        fraud_proof: &FraudProof<NumberFor<FPBlock>, FPBlock::Hash>,
    ) -> Result<(), VerificationError> {
        match fraud_proof {
            FraudProof::InvalidStateTransition(proof) => {
                self.invalid_state_transition_proof_verifier.verify(proof)
            }
            proof => unimplemented!("Can not verify {proof:?}"),
        }
    }
}

impl<FPBlock, PBlock, C, Exec, Spawn, Hash, PreStateRootVerifier> VerifyFraudProof<FPBlock>
    for ProofVerifier<FPBlock, PBlock, C, Exec, Spawn, Hash, PreStateRootVerifier>
where
    FPBlock: BlockT,
    PBlock: BlockT,
    C: ProvideRuntimeApi<PBlock> + Send + Sync,
    C::Api: ExecutorApi<PBlock, Hash>,
    Exec: CodeExecutor + Clone + 'static,
    Spawn: SpawnNamed + Clone + Send + 'static,
    Hash: Encode + Decode + Send + Sync,
    PreStateRootVerifier: VerifyPreStateRoot,
{
    fn verify_fraud_proof(
        &self,
        proof: &FraudProof<NumberFor<FPBlock>, FPBlock::Hash>,
    ) -> Result<(), VerificationError> {
        self.verify(proof)
    }
}

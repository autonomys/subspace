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
pub use invalid_state_transition_proof::ExecutionProver;
use invalid_state_transition_proof::InvalidStateTransitionProofVerifier;
use sc_client_api::backend;
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
pub struct ProofVerifier<FPBlock, PBlock, C, B, Exec, Spawn, Hash> {
    invalid_state_transition_proof_verifier:
        InvalidStateTransitionProofVerifier<PBlock, C, B, Exec, Spawn, Hash>,
    _phantom: PhantomData<FPBlock>,
}

impl<FPBlock, PBlock, C, B, Exec: Clone, Spawn: Clone, Hash> Clone
    for ProofVerifier<FPBlock, PBlock, C, B, Exec, Spawn, Hash>
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

impl<FPBlock, PBlock, C, B, Exec, Spawn, Hash>
    ProofVerifier<FPBlock, PBlock, C, B, Exec, Spawn, Hash>
where
    FPBlock: BlockT,
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
        let invalid_state_transition_proof_verifier =
            InvalidStateTransitionProofVerifier::new(client, backend, executor, spawn_handle);
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

impl<FPBlock, PBlock, C, B, Exec, Spawn, Hash> VerifyFraudProof<FPBlock>
    for ProofVerifier<FPBlock, PBlock, C, B, Exec, Spawn, Hash>
where
    FPBlock: BlockT,
    PBlock: BlockT,
    C: ProvideRuntimeApi<PBlock> + Send + Sync,
    C::Api: ExecutorApi<PBlock, Hash>,
    B: backend::Backend<PBlock>,
    Exec: CodeExecutor + Clone + 'static,
    Spawn: SpawnNamed + Clone + Send + 'static,
    Hash: Encode + Decode + Send + Sync,
{
    fn verify_fraud_proof(
        &self,
        proof: &FraudProof<NumberFor<FPBlock>, FPBlock::Hash>,
    ) -> Result<(), VerificationError> {
        self.verify(proof)
    }
}

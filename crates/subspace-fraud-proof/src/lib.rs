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
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;

/// Verify fraud proof.
pub trait VerifyFraudProof {
    /// Verifies fraud proof.
    fn verify_fraud_proof(&self, proof: &FraudProof) -> Result<(), VerificationError>;
}

/// Fraud proof verifier.
pub struct ProofVerifier<PBlock, C, B, Exec, Spawn, Hash> {
    invalid_state_transition_proof_verifier:
        InvalidStateTransitionProofVerifier<PBlock, C, B, Exec, Spawn, Hash>,
}

impl<PBlock, C, B, Exec: Clone, Spawn: Clone, Hash> Clone
    for ProofVerifier<PBlock, C, B, Exec, Spawn, Hash>
{
    fn clone(&self) -> Self {
        Self {
            invalid_state_transition_proof_verifier: self
                .invalid_state_transition_proof_verifier
                .clone(),
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
        let invalid_state_transition_proof_verifier =
            InvalidStateTransitionProofVerifier::new(client, backend, executor, spawn_handle);
        Self {
            invalid_state_transition_proof_verifier,
        }
    }

    /// Verifies the fraud proof.
    pub fn verify(&self, fraud_proof: &FraudProof) -> Result<(), VerificationError> {
        match fraud_proof {
            FraudProof::InvalidStateTransition(proof) => {
                self.invalid_state_transition_proof_verifier.verify(proof)
            }
        }
    }
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
    fn verify_fraud_proof(&self, proof: &FraudProof) -> Result<(), VerificationError> {
        self.verify(proof)
    }
}

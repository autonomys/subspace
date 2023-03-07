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
pub use invalid_state_transition_proof::{ExecutionProver, ProofVerifier};
use sc_client_api::backend;
use sp_api::ProvideRuntimeApi;
use sp_core::traits::{CodeExecutor, SpawnNamed};
use sp_domains::fraud_proof::{FraudProof, VerificationError};
use sp_domains::ExecutorApi;
use sp_runtime::traits::Block as BlockT;

/// Verify fraud proof.
pub trait VerifyFraudProof {
    /// Verifies fraud proof.
    fn verify_fraud_proof(&self, proof: &FraudProof) -> Result<(), VerificationError>;
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

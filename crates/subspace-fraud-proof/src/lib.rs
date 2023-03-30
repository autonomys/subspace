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
use futures::channel::oneshot;
use futures::FutureExt;
use invalid_state_transition_proof::InvalidStateTransitionProofVerifier;
pub use invalid_state_transition_proof::{
    ExecutionProver, PrePostStateRootVerifier, VerifyPrePostStateRoot,
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
pub struct ProofVerifier<FPBlock, PBlock, C, Exec, Spawn, Hash, PrePostStateRootVerifier> {
    invalid_state_transition_proof_verifier:
        InvalidStateTransitionProofVerifier<PBlock, C, Exec, Spawn, Hash, PrePostStateRootVerifier>,
    _phantom: PhantomData<FPBlock>,
}

impl<FPBlock, PBlock, C, Exec: Clone, Spawn: Clone, Hash, PrePostStateRootVerifier: Clone> Clone
    for ProofVerifier<FPBlock, PBlock, C, Exec, Spawn, Hash, PrePostStateRootVerifier>
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

impl<FPBlock, PBlock, C, Exec, Spawn, Hash, PrePostStateRootVerifier>
    ProofVerifier<FPBlock, PBlock, C, Exec, Spawn, Hash, PrePostStateRootVerifier>
where
    FPBlock: BlockT,
    PBlock: BlockT,
    C: ProvideRuntimeApi<PBlock> + Send + Sync,
    C::Api: ExecutorApi<PBlock, Hash>,
    Exec: CodeExecutor + Clone + 'static,
    Spawn: SpawnNamed + Clone + Send + 'static,
    Hash: Encode + Decode,
    PrePostStateRootVerifier: VerifyPrePostStateRoot,
{
    /// Constructs a new instance of [`ProofVerifier`].
    pub fn new(
        client: Arc<C>,
        executor: Exec,
        spawn_handle: Spawn,
        pre_post_state_root_verifier: PrePostStateRootVerifier,
    ) -> Self {
        let invalid_state_transition_proof_verifier = InvalidStateTransitionProofVerifier::new(
            client,
            executor,
            spawn_handle,
            pre_post_state_root_verifier,
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

impl<FPBlock, PBlock, C, Exec, Spawn, Hash, PrePostStateRootVerifier> VerifyFraudProof<FPBlock>
    for ProofVerifier<FPBlock, PBlock, C, Exec, Spawn, Hash, PrePostStateRootVerifier>
where
    FPBlock: BlockT,
    PBlock: BlockT,
    C: ProvideRuntimeApi<PBlock> + Send + Sync,
    C::Api: ExecutorApi<PBlock, Hash>,
    Exec: CodeExecutor + Clone + 'static,
    Spawn: SpawnNamed + Clone + Send + 'static,
    Hash: Encode + Decode + Send + Sync,
    PrePostStateRootVerifier: VerifyPrePostStateRoot,
{
    fn verify_fraud_proof(
        &self,
        proof: &FraudProof<NumberFor<FPBlock>, FPBlock::Hash>,
    ) -> Result<(), VerificationError> {
        self.verify(proof)
    }
}

/// Verifies the fraud proof extracted from extrinsic in the transaction pool.
pub async fn validate_fraud_proof_in_tx_pool<Block, Verifier>(
    spawner: &dyn SpawnNamed,
    fraud_proof_verifier: Verifier,
    fraud_proof: FraudProof<NumberFor<Block>, Block::Hash>,
) -> Result<(), VerificationError>
where
    Block: BlockT,
    Verifier: VerifyFraudProof<Block> + Send + 'static,
{
    let (verified_result_sender, verified_result_receiver) = oneshot::channel();

    // Verify the fraud proof in another blocking task as it might be pretty heavy.
    spawner.spawn_blocking(
        "txpool-fraud-proof-verification",
        None,
        async move {
            let verified_result = fraud_proof_verifier.verify_fraud_proof(&fraud_proof);
            verified_result_sender
                .send(verified_result)
                .expect("Failed to send the verified fraud proof result");
        }
        .boxed(),
    );

    match verified_result_receiver.await {
        Ok(verified_result) => verified_result,
        Err(err) => Err(VerificationError::Oneshot(err.to_string())),
    }
}

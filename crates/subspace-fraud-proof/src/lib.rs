//! Subspace fraud proof

#![warn(missing_docs)]

pub mod domain_extrinsics_builder;
mod domain_runtime_code;
pub mod invalid_state_transition_proof;
pub mod invalid_transaction_proof;
// TODO: Unlock once domain test infra is workable again.
// #[cfg(test)]
// mod tests;
pub mod verifier_api;

use futures::channel::oneshot;
use futures::FutureExt;
use invalid_state_transition_proof::VerifyInvalidStateTransitionProof;
use invalid_transaction_proof::VerifyInvalidTransactionProof;
use sp_core::traits::SpawnNamed;
use sp_domains::fraud_proof::{FraudProof, VerificationError};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::marker::PhantomData;
use std::sync::Arc;

/// Verify fraud proof.
///
/// Verifier is either the primary chain client or the system domain client.
pub trait VerifyFraudProof<VerifierBlock: BlockT> {
    /// Verifies fraud proof.
    fn verify_fraud_proof(
        &self,
        proof: &FraudProof<NumberFor<VerifierBlock>, VerifierBlock::Hash>,
    ) -> Result<(), VerificationError>;
}

/// Fraud proof verifier.
pub struct ProofVerifier<VerifierBlock, ITPVerifier, ISTPVerifier> {
    invalid_transaction_proof_verifier: Arc<ITPVerifier>,
    invalid_state_transition_proof_verifier: Arc<ISTPVerifier>,
    _phantom: PhantomData<VerifierBlock>,
}

impl<VerifierBlock, ITPVerifier, ISTPVerifier> Clone
    for ProofVerifier<VerifierBlock, ITPVerifier, ISTPVerifier>
{
    fn clone(&self) -> Self {
        Self {
            invalid_transaction_proof_verifier: self.invalid_transaction_proof_verifier.clone(),
            invalid_state_transition_proof_verifier: self
                .invalid_state_transition_proof_verifier
                .clone(),
            _phantom: self._phantom,
        }
    }
}

impl<VerifierBlock, ITPVerifier, ISTPVerifier>
    ProofVerifier<VerifierBlock, ITPVerifier, ISTPVerifier>
where
    VerifierBlock: BlockT,
    ITPVerifier: VerifyInvalidTransactionProof,
    ISTPVerifier: VerifyInvalidStateTransitionProof,
{
    /// Constructs a new instance of [`ProofVerifier`].
    pub fn new(
        invalid_transaction_proof_verifier: Arc<ITPVerifier>,
        invalid_state_transition_proof_verifier: Arc<ISTPVerifier>,
    ) -> Self {
        Self {
            invalid_transaction_proof_verifier,
            invalid_state_transition_proof_verifier,
            _phantom: Default::default(),
        }
    }

    /// Verifies the fraud proof.
    pub fn verify(
        &self,
        fraud_proof: &FraudProof<NumberFor<VerifierBlock>, VerifierBlock::Hash>,
    ) -> Result<(), VerificationError> {
        match fraud_proof {
            FraudProof::InvalidStateTransition(proof) => self
                .invalid_state_transition_proof_verifier
                .verify_invalid_state_transition_proof(proof),
            FraudProof::InvalidTransaction(proof) => self
                .invalid_transaction_proof_verifier
                .verify_invalid_transaction_proof(proof),
            proof => unimplemented!("Can not verify {proof:?}"),
        }
    }
}

impl<VerifierBlock, ITPVerifier, ISTPVerifier> VerifyFraudProof<VerifierBlock>
    for ProofVerifier<VerifierBlock, ITPVerifier, ISTPVerifier>
where
    VerifierBlock: BlockT,
    ITPVerifier: VerifyInvalidTransactionProof,
    ISTPVerifier: VerifyInvalidStateTransitionProof,
{
    fn verify_fraud_proof(
        &self,
        proof: &FraudProof<NumberFor<VerifierBlock>, VerifierBlock::Hash>,
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

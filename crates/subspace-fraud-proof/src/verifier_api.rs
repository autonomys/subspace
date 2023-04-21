//! This module derives an trait [`VerifierApi`] from the runtime api `ReceiptsApi`
//! as well as the implementation to provide convenient interfaces used in the fraud
//! proof verification.

use codec::{Decode, Encode};
use sc_client_api::HeaderBackend;
use sp_api::ProvideRuntimeApi;
use sp_core::H256;
use sp_domains::fraud_proof::{ExecutionPhase, InvalidStateTransitionProof, VerificationError};
use sp_domains::DomainId;
use sp_receipts::ReceiptsApi;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::marker::PhantomData;
use std::sync::Arc;

/// This trait abstracts convenient APIs for the fraud proof verifier.
pub trait VerifierApi {
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

/// A wrapper of primary chain client/system domain client in common.
///
/// Both primary chain client and system domain client maintains the state of receipts, i.e., implements `ReceiptsApi`.
pub struct VerifierClient<Client, Block> {
    client: Arc<Client>,
    _phantom: PhantomData<Block>,
}

impl<Client, Block> Clone for VerifierClient<Client, Block> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<Client, Block> VerifierClient<Client, Block> {
    /// Constructs a new instance of [`VerifierClient`].
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            _phantom: Default::default(),
        }
    }
}

impl<Client, Block> VerifierApi for VerifierClient<Client, Block>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: ReceiptsApi<Block, domain_runtime_primitives::Hash>,
{
    // TODO: It's not necessary to require `pre_state_root` in the proof and then verify, it can
    // be just retrieved by the verifier itself according the execution phase, which requires some
    // fixes in tests however, we can do this refactoring once we have or are able to construct a
    // proper `VerifierApi` implementation in test.
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

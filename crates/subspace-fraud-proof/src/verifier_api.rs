//! This module derives an trait [`VerifierApi`] from the runtime api `SettlementApi`
//! as well as the implementation to provide convenient interfaces used in the fraud
//! proof verification.

// TODO: Remove once fraud proof v2 is implemented.
#![allow(unused)]

use codec::{Decode, Encode};
use domain_runtime_primitives::Hash;
use sc_client_api::HeaderBackend;
use sp_api::ProvideRuntimeApi;
use sp_core::H256;
use sp_domains::fraud_proof::{ExecutionPhase, InvalidStateTransitionProof, VerificationError};
use sp_domains::{DomainId, DomainsApi};
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

    /// Returns the state root of specified domain block.
    fn state_root(
        &self,
        domain_id: DomainId,
        domain_block_number: u32,
        domain_block_hash: H256,
    ) -> Result<Hash, VerificationError>;
}

/// A wrapper of primary chain client/system domain client in common.
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
    Client::Api:
        DomainsApi<Block, domain_runtime_primitives::BlockNumber, domain_runtime_primitives::Hash>,
{
    // TODO: It's not necessary to require `pre_state_root` in the proof and then verify, it can
    // be just retrieved by the verifier itself according the execution phase, which requires some
    // fixes in tests however, we can do this refactoring once we have or are able to construct a
    // proper `VerifierApi` implementation in test.
    //
    // Related: https://github.com/subspace/subspace/pull/1240#issuecomment-1476212007
    fn verify_pre_state_root(
        &self,
        _invalid_state_transition_proof: &InvalidStateTransitionProof,
    ) -> Result<(), VerificationError> {
        // TODO: Implement or remove entirely.
        Ok(())
    }

    fn verify_post_state_root(
        &self,
        _invalid_state_transition_proof: &InvalidStateTransitionProof,
    ) -> Result<(), VerificationError> {
        // TODO: Implement or remove entirely.
        Ok(())
    }

    fn primary_hash(
        &self,
        _domain_id: DomainId,
        _domain_block_number: u32,
    ) -> Result<H256, VerificationError> {
        // TODO: Remove entirely.
        Err(VerificationError::ConsensusBlockHashNotFound)
    }

    fn state_root(
        &self,
        _domain_id: DomainId,
        _domain_block_number: u32,
        _domain_block_hash: H256,
    ) -> Result<Hash, VerificationError> {
        // TODO: Implement or remove entirely.
        Err(VerificationError::DomainStateRootNotFound)
    }
}

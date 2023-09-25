//! Invalid bundle proof for the `invalid_bundles` field of the execution receipt.

use codec::{Decode, Encode};
use domain_block_preprocessor::runtime_api_light::RuntimeApiLight;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::CodeExecutor;
use sp_domains::fraud_proof::{
    InvalidBundlesFraudProof, MissingBundleAdditionalData, MissingInvalidBundleEntryFraudProof,
    VerificationError,
};
use sp_domains::storage_proof::OpaqueBundleWithProof;
use sp_domains::DomainsApi;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::U256;

/// Valid bundle proof verifier.
pub struct InvalidBundleProofVerifier<CBlock, DomainBlock, CClient, Exec> {
    consensus_client: Arc<CClient>,
    executor: Arc<Exec>,
    _phantom: PhantomData<(CBlock, DomainBlock)>,
}

impl<CBlock, DomainBlock, CClient, Exec> Clone
    for InvalidBundleProofVerifier<CBlock, DomainBlock, CClient, Exec>
{
    fn clone(&self) -> Self {
        Self {
            consensus_client: self.consensus_client.clone(),
            executor: self.executor.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<CBlock, DomainBlock, CClient, Exec>
    InvalidBundleProofVerifier<CBlock, DomainBlock, CClient, Exec>
where
    CBlock: BlockT,
    DomainBlock: BlockT,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + Send + Sync,
    CClient::Api: DomainsApi<CBlock, NumberFor<DomainBlock>, <DomainBlock as BlockT>::Hash>,
    Exec: CodeExecutor + 'static,
{
    /// Constructs a new instance of [`InvalidBundleProofVerifier`].
    pub fn new(consensus_client: Arc<CClient>, executor: Arc<Exec>) -> Self {
        Self {
            consensus_client,
            executor,
            _phantom: Default::default(),
        }
    }

    /// Verify the `InvalidBundleProof`
    pub fn verify(
        &self,
        invalid_bundle_proof: &InvalidBundlesFraudProof<
            NumberFor<CBlock>,
            CBlock::Hash,
            NumberFor<DomainBlock>,
            <DomainBlock as BlockT>::Hash,
        >,
    ) -> Result<(), VerificationError> {
        match invalid_bundle_proof {
            InvalidBundlesFraudProof::MissingInvalidBundleEntry(proof) => {
                let MissingInvalidBundleEntryFraudProof {
                    domain_id,
                    consensus_block_hash,
                    parent_domain_block_hash,
                    runtime_code_with_proof,
                    opaque_bundle_with_proof,
                    additional_data,
                    ..
                } = proof;

                let consensus_block_header = {
                    self.consensus_client
                        .header(*consensus_block_hash)?
                        .ok_or_else(|| {
                            sp_blockchain::Error::Backend(format!(
                                "Header for {consensus_block_hash} not found"
                            ))
                        })?
                };
                let parent_consensus_block_header = {
                    let parent_hash = consensus_block_header.parent_hash();
                    self.consensus_client.header(*parent_hash)?.ok_or_else(|| {
                        sp_blockchain::Error::Backend(format!("Header for {parent_hash} not found"))
                    })?
                };

                // Verify the existence of the `bundle` in the consensus chain
                opaque_bundle_with_proof
                    .verify::<CBlock>(*domain_id, consensus_block_header.state_root())?;
                let OpaqueBundleWithProof { bundle, .. } = opaque_bundle_with_proof;

                // Verify the existence of the `domain_runtime_code` in the consensus chain
                //
                // NOTE: we use the state root of the parent block to verify here, see the comment
                // of `DomainRuntimeCodeWithProof` for more detail.
                let domain_runtime_code = runtime_code_with_proof
                    .verify::<CBlock>(*domain_id, parent_consensus_block_header.state_root())?;

                let runtime_api_light =
                    RuntimeApiLight::new(self.executor.clone(), domain_runtime_code.into());

                match additional_data {
                    MissingBundleAdditionalData::OutOfRangeTx { extrinsic_index } => {
                        let opaque_extrinsic = bundle
                            .extrinsics
                            .get(*extrinsic_index as usize)
                            .ok_or(VerificationError::DomainExtrinsicNotFound(*extrinsic_index))?;

                        let extrinsic = <<DomainBlock as BlockT>::Extrinsic>::decode(
                            &mut opaque_extrinsic.encode().as_slice(),
                        )
                        .map_err(|e| VerificationError::Decode(e))?;

                        let tx_range = self
                            .consensus_client
                            .runtime_api()
                            .domain_tx_range(*consensus_block_hash, *domain_id)?;

                        let bundle_vrf_hash = U256::from_be_bytes(
                            bundle.sealed_header.header.proof_of_election.vrf_hash(),
                        );

                        let is_within_tx_range =
                            <RuntimeApiLight<Exec> as domain_runtime_primitives::DomainCoreApi<
                                DomainBlock,
                            >>::is_within_tx_range(
                                &runtime_api_light,
                                *parent_domain_block_hash,
                                &extrinsic,
                                &bundle_vrf_hash,
                                &tx_range,
                            )?;

                        if is_within_tx_range {
                            return Err(VerificationError::TxIsInRange {
                                extrinsic_index: *extrinsic_index,
                            });
                        }
                    }
                }
            }
            // TODO: Add verification for valid as invalid fraud proof here
            InvalidBundlesFraudProof::ValidAsInvalid(_) => {}
        }

        Ok(())
    }
}

/// Verifies valid bundle proof.
pub trait VerifyInvalidBundleProof<CBlock: BlockT, DomainBlock: BlockT> {
    /// Returns `Ok(())` if given `valid_bundle_proof` is legitimate.
    fn verify_invalid_bundle_proof(
        &self,
        invalid_bundle_proof: &InvalidBundlesFraudProof<
            NumberFor<CBlock>,
            CBlock::Hash,
            NumberFor<DomainBlock>,
            <DomainBlock as BlockT>::Hash,
        >,
    ) -> Result<(), VerificationError>;
}

impl<CBlock, DomainBlock, Client, Exec> VerifyInvalidBundleProof<CBlock, DomainBlock>
    for InvalidBundleProofVerifier<CBlock, DomainBlock, Client, Exec>
where
    CBlock: BlockT,
    DomainBlock: BlockT,
    Client: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + Send + Sync,
    Client::Api: DomainsApi<CBlock, NumberFor<DomainBlock>, <DomainBlock as BlockT>::Hash>,
    Exec: CodeExecutor + 'static,
{
    fn verify_invalid_bundle_proof(
        &self,
        invalid_bundle_proof: &InvalidBundlesFraudProof<
            NumberFor<CBlock>,
            CBlock::Hash,
            NumberFor<DomainBlock>,
            <DomainBlock as BlockT>::Hash,
        >,
    ) -> Result<(), VerificationError> {
        self.verify(invalid_bundle_proof)
    }
}

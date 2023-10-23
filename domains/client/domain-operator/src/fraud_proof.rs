use crate::aux_schema::BundleMismatchType;
use crate::ExecutionReceiptFor;
use codec::{Decode, Encode};
use domain_block_builder::{BlockBuilder, RecordProof};
use domain_runtime_primitives::opaque::AccountId;
use domain_runtime_primitives::DomainCoreApi;
use sc_client_api::{AuxStore, BlockBackend, ProofProvider};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domain_digests::AsPredigest;
use sp_domains::proof_provider_and_verifier::StorageProofProvider;
use sp_domains::{DomainId, DomainsApi};
use sp_domains_fraud_proof::execution_prover::ExecutionProver;
use sp_domains_fraud_proof::fraud_proof::{
    ExecutionPhase, ExtrinsicDigest, FraudProof, InvalidBundlesFraudProof,
    InvalidDomainBlockHashProof, InvalidExtrinsicsRootProof, InvalidStateTransitionProof,
    InvalidTotalRewardsProof, MissingInvalidBundleEntryFraudProof,
    ValidAsInvalidBundleEntryFraudProof, ValidBundleDigest,
};
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, HashingFor, Header as HeaderT, NumberFor};
use sp_runtime::{Digest, DigestItem};
use sp_trie::{LayoutV1, StorageProof};
use std::marker::PhantomData;
use std::sync::Arc;

/// Error type for fraud proof generation.
#[derive(Debug, thiserror::Error)]
pub enum FraudProofError {
    #[error("Invalid extrinsic index for creating the execution proof, got: {index}, max: {max}")]
    InvalidExtrinsicIndex { index: usize, max: usize },
    #[error(transparent)]
    Blockchain(#[from] sp_blockchain::Error),
    #[error(transparent)]
    RuntimeApi(#[from] sp_api::ApiError),
    #[error("Missing bundle at {bundle_index}")]
    MissingBundle { bundle_index: usize },
    #[error("Invalid bundle extrinsic at bundle index[{bundle_index}]")]
    InvalidBundleExtrinsic { bundle_index: usize },
    #[error("Fail to generate the proof of inclusion")]
    FailToGenerateProofOfInclusion,
}

pub struct FraudProofGenerator<Block, CBlock, Client, CClient, Backend, E> {
    client: Arc<Client>,
    consensus_client: Arc<CClient>,
    backend: Arc<Backend>,
    code_executor: Arc<E>,
    _phantom: PhantomData<(Block, CBlock)>,
}

impl<Block, CBlock, Client, CClient, Backend, E> Clone
    for FraudProofGenerator<Block, CBlock, Client, CClient, Backend, E>
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            consensus_client: self.consensus_client.clone(),
            backend: self.backend.clone(),
            code_executor: self.code_executor.clone(),
            _phantom: self._phantom,
        }
    }
}

type FraudProofFor<PCB, DomainHeader> =
    FraudProof<NumberFor<PCB>, <PCB as BlockT>::Hash, DomainHeader>;

impl<Block, CBlock, Client, CClient, Backend, E>
    FraudProofGenerator<Block, CBlock, Client, CClient, Backend, E>
where
    Block: BlockT,
    CBlock: BlockT,
    Client: HeaderBackend<Block>
        + BlockBackend<Block>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + ProofProvider<Block>
        + 'static,
    Client::Api:
        sp_block_builder::BlockBuilder<Block> + sp_api::ApiExt<Block> + DomainCoreApi<Block>,
    CClient: HeaderBackend<CBlock>
        + BlockBackend<CBlock>
        + ProvideRuntimeApi<CBlock>
        + ProofProvider<CBlock>
        + 'static,
    CClient::Api: DomainsApi<CBlock, Block::Header>,
    Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
    E: CodeExecutor,
{
    pub fn new(
        client: Arc<Client>,
        consensus_client: Arc<CClient>,
        backend: Arc<Backend>,
        code_executor: Arc<E>,
    ) -> Self {
        Self {
            client,
            consensus_client,
            backend,
            code_executor,
            _phantom: Default::default(),
        }
    }

    pub(crate) fn generate_invalid_total_rewards_proof<PCB>(
        &self,
        domain_id: DomainId,
        local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        bad_receipt_hash: H256,
    ) -> Result<FraudProofFor<PCB, Block::Header>, FraudProofError>
    where
        PCB: BlockT,
    {
        let block_hash = local_receipt.domain_block_hash;
        let key = sp_domains_fraud_proof::fraud_proof::operator_block_rewards_final_key();
        let proof = self
            .client
            .read_proof(block_hash, &mut [key.as_slice()].into_iter())?;
        Ok(FraudProof::InvalidTotalRewards(InvalidTotalRewardsProof {
            domain_id,
            bad_receipt_hash,
            storage_proof: proof,
        }))
    }

    pub(crate) fn generate_invalid_domain_block_hash_proof<PCB>(
        &self,
        domain_id: DomainId,
        local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        bad_receipt_hash: H256,
    ) -> Result<FraudProofFor<PCB, Block::Header>, FraudProofError>
    where
        PCB: BlockT,
    {
        let block_hash = local_receipt.domain_block_hash;
        let digest_key = sp_domains_fraud_proof::fraud_proof::system_digest_final_key();
        let digest_storage_proof = self
            .client
            .read_proof(block_hash, &mut [digest_key.as_slice()].into_iter())?;
        Ok(FraudProof::InvalidDomainBlockHash(
            InvalidDomainBlockHashProof {
                domain_id,
                bad_receipt_hash,
                digest_storage_proof,
            },
        ))
    }

    pub(crate) fn generate_invalid_bundle_field_proof<PCB>(
        &self,
        domain_id: DomainId,
        _local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        mismatch_type: BundleMismatchType,
        bundle_index: u32,
        _bad_receipt_hash: H256,
    ) -> Result<FraudProofFor<PCB, Block::Header>, FraudProofError>
    where
        PCB: BlockT,
    {
        match mismatch_type {
            // TODO: Generate a proper proof once fields are in place
            BundleMismatchType::TrueInvalid(_invalid_type) => Ok(FraudProof::InvalidBundles(
                InvalidBundlesFraudProof::ValidAsInvalid(ValidAsInvalidBundleEntryFraudProof::new(
                    domain_id,
                    bundle_index,
                )),
            )),
            // TODO: Generate a proper proof once fields are in place
            BundleMismatchType::FalseInvalid(_invalid_type) => Ok(FraudProof::InvalidBundles(
                InvalidBundlesFraudProof::MissingInvalidBundleEntry(
                    MissingInvalidBundleEntryFraudProof::new(domain_id, bundle_index),
                ),
            )),
            BundleMismatchType::Valid => Err(sp_blockchain::Error::Application(
                "Unexpected bundle mismatch type, this should not happen"
                    .to_string()
                    .into(),
            )
            .into()),
        }
    }

    pub(crate) fn generate_invalid_domain_extrinsics_root_proof<PCB>(
        &self,
        domain_id: DomainId,
        local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        bad_receipt_hash: H256,
    ) -> Result<FraudProofFor<PCB, Block::Header>, FraudProofError>
    where
        PCB: BlockT,
    {
        let consensus_block_hash = local_receipt.consensus_block_hash;
        let consensus_extrinsics = self
            .consensus_client
            .block_body(consensus_block_hash)?
            .ok_or_else(|| {
                sp_blockchain::Error::Backend(format!(
                    "BlockBody of {consensus_block_hash:?} unavailable"
                ))
            })?;

        let bundles = self
            .consensus_client
            .runtime_api()
            .extract_successful_bundles(consensus_block_hash, domain_id, consensus_extrinsics)?;

        let domain_runtime_api = self.client.runtime_api();
        let mut valid_bundle_digests = Vec::new();
        for bundle_index in local_receipt.valid_bundle_indexes() {
            let bundle =
                bundles
                    .get(bundle_index as usize)
                    .ok_or(FraudProofError::MissingBundle {
                        bundle_index: bundle_index as usize,
                    })?;

            let mut exts = Vec::with_capacity(bundle.extrinsics.len());
            for opaque_extrinsic in &bundle.extrinsics {
                let extrinsic = <<Block as BlockT>::Extrinsic>::decode(
                    &mut opaque_extrinsic.encode().as_slice(),
                )
                .map_err(|_| FraudProofError::InvalidBundleExtrinsic {
                    bundle_index: bundle_index as usize,
                })?;

                exts.push(extrinsic)
            }

            let bundle_digest = domain_runtime_api
                .extract_signer(local_receipt.domain_block_hash, exts)?
                .into_iter()
                .map(|(signer, ext)| {
                    (
                        signer,
                        ExtrinsicDigest::new::<LayoutV1<BlakeTwo256>>(ext.encode()),
                    )
                })
                .collect::<Vec<(Option<AccountId>, ExtrinsicDigest)>>();
            valid_bundle_digests.push(ValidBundleDigest {
                bundle_index,
                bundle_digest,
            });
        }

        Ok(FraudProof::InvalidExtrinsicsRoot(
            InvalidExtrinsicsRootProof {
                domain_id,
                bad_receipt_hash,
                valid_bundle_digests,
            },
        ))
    }

    pub(crate) async fn generate_invalid_state_transition_proof<PCB>(
        &self,
        domain_id: DomainId,
        local_trace_index: u32,
        local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        bad_receipt_hash: H256,
    ) -> Result<FraudProofFor<PCB, Block::Header>, FraudProofError>
    where
        PCB: BlockT,
    {
        let block_hash = local_receipt.domain_block_hash;
        let block_number = local_receipt.domain_block_number;
        let header = self.header(block_hash)?;
        let parent_header = self.header(*header.parent_hash())?;

        let prover = ExecutionProver::new(self.backend.clone(), self.code_executor.clone());

        let inherent_digests = Digest {
            logs: vec![DigestItem::consensus_block_info(
                local_receipt.consensus_block_hash,
            )],
        };

        let invalid_state_transition_proof = if local_trace_index == 0 {
            // `initialize_block` execution proof.
            let new_header = Block::Header::new(
                block_number,
                Default::default(),
                Default::default(),
                parent_header.hash(),
                inherent_digests,
            );
            let execution_phase = ExecutionPhase::InitializeBlock;
            let initialize_block_call_data = new_header.encode();

            let proof = prover.prove_execution::<sp_trie::PrefixedMemoryDB<HashingFor<Block>>>(
                parent_header.hash(),
                &execution_phase,
                &initialize_block_call_data,
                None,
            )?;

            InvalidStateTransitionProof {
                domain_id,
                bad_receipt_hash,
                proof,
                execution_phase,
            }
        } else if local_trace_index as usize == local_receipt.execution_trace.len() - 1 {
            // `finalize_block` execution proof.
            let extrinsics = self.block_body(block_hash)?;
            let execution_phase = ExecutionPhase::FinalizeBlock;
            let finalize_block_call_data = Vec::new();
            let block_builder = BlockBuilder::new(
                &*self.client,
                parent_header.hash(),
                *parent_header.number(),
                RecordProof::No,
                inherent_digests,
                &*self.backend,
                extrinsics.into(),
                None,
            )?;
            let storage_changes = block_builder.prepare_storage_changes_before_finalize_block()?;

            let delta = storage_changes.transaction;
            let post_delta_root = storage_changes.transaction_storage_root;

            let proof = prover.prove_execution(
                parent_header.hash(),
                &execution_phase,
                &finalize_block_call_data,
                Some((delta, post_delta_root)),
            )?;

            InvalidStateTransitionProof {
                domain_id,
                bad_receipt_hash,
                proof,
                execution_phase,
            }
        } else {
            // Regular extrinsic execution proof.
            let (proof, execution_phase) = self
                .create_extrinsic_execution_proof(
                    local_trace_index as usize - 1,
                    &parent_header,
                    block_hash,
                    &prover,
                    inherent_digests,
                )
                .await?;

            // TODO: proof should be a CompactProof.
            InvalidStateTransitionProof {
                domain_id,
                bad_receipt_hash,
                proof,
                execution_phase,
            }
        };

        Ok(FraudProof::InvalidStateTransition(
            invalid_state_transition_proof,
        ))
    }

    fn header(&self, hash: Block::Hash) -> Result<Block::Header, sp_blockchain::Error> {
        self.client
            .header(hash)?
            .ok_or_else(|| sp_blockchain::Error::Backend(format!("Header not found for {hash:?}")))
    }

    fn block_body(&self, at: Block::Hash) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error> {
        self.client.block_body(at)?.ok_or_else(|| {
            sp_blockchain::Error::Backend(format!("Block body not found for {at:?}"))
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_extrinsic_execution_proof(
        &self,
        extrinsic_index: usize,
        parent_header: &Block::Header,
        current_hash: Block::Hash,
        prover: &ExecutionProver<Block, Backend, E>,
        digest: Digest,
    ) -> Result<(StorageProof, ExecutionPhase), FraudProofError> {
        let extrinsics = self.block_body(current_hash)?;
        let encoded_extrinsics: Vec<_> = extrinsics.iter().map(Encode::encode).collect();

        let target_extrinsic = encoded_extrinsics.get(extrinsic_index).ok_or(
            FraudProofError::InvalidExtrinsicIndex {
                index: extrinsic_index,
                max: extrinsics.len() - 1,
            },
        )?;

        let execution_phase = {
            let proof_of_inclusion = StorageProofProvider::<
                LayoutV1<<Block::Header as HeaderT>::Hashing>,
            >::generate_enumerated_proof_of_inclusion(
                encoded_extrinsics.as_slice(),
                extrinsic_index as u32,
            )
            .ok_or(FraudProofError::FailToGenerateProofOfInclusion)?;
            ExecutionPhase::ApplyExtrinsic {
                proof_of_inclusion,
                mismatch_index: extrinsic_index as u32,
                extrinsic: target_extrinsic.clone(),
            }
        };

        let block_builder = BlockBuilder::new(
            &*self.client,
            parent_header.hash(),
            *parent_header.number(),
            RecordProof::No,
            digest,
            &*self.backend,
            extrinsics.into(),
            None,
        )?;
        let storage_changes = block_builder.prepare_storage_changes_before(extrinsic_index)?;

        let delta = storage_changes.transaction;
        let post_delta_root = storage_changes.transaction_storage_root;
        let execution_proof = prover.prove_execution(
            parent_header.hash(),
            &execution_phase,
            target_extrinsic,
            Some((delta, post_delta_root)),
        )?;

        Ok((execution_proof, execution_phase))
    }
}

/// Returns the index of first mismatch between the receipts `local` and `other` if any.
pub(crate) fn find_trace_mismatch<Hash: Copy + Eq>(
    local_trace: &[Hash],
    other_trace: &[Hash],
) -> Option<u32> {
    local_trace
        .iter()
        .enumerate()
        .zip(other_trace.iter().enumerate())
        .find_map(|((local_index, local_root), (_, other_root))| {
            if local_root != other_root {
                Some(
                    local_index
                        .try_into()
                        .expect("Trace mismatch index must fit into u32; qed"),
                )
            } else {
                None
            }
        })
}

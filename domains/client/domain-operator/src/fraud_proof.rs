use crate::aux_schema::BundleMismatchType;
use crate::ExecutionReceiptFor;
use codec::{Decode, Encode};
use domain_block_builder::{BlockBuilder, RecordProof};
use domain_runtime_primitives::opaque::AccountId;
use domain_runtime_primitives::CheckExtrinsicsValidityError;
use sc_client_api::{AuxStore, BlockBackend, ProofProvider};
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domain_digests::AsPredigest;
use sp_domains::core_api::DomainCoreApi;
use sp_domains::proof_provider_and_verifier::StorageProofProvider;
use sp_domains::{DomainId, DomainsApi, ExtrinsicDigest, HeaderHashingFor, InvalidBundleType};
use sp_domains_fraud_proof::execution_prover::ExecutionProver;
use sp_domains_fraud_proof::fraud_proof::{
    ApplyExtrinsicMismatch, ExecutionPhase, FinalizeBlockMismatch, FraudProof,
    InvalidBlockFeesProof, InvalidBundlesFraudProof, InvalidDomainBlockHashProof,
    InvalidExtrinsicsRootProof, InvalidStateTransitionProof, InvalidTransfersProof,
    ValidBundleDigest,
};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use sp_runtime::{Digest, DigestItem};
use sp_trie::LayoutV1;
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum TraceDiffType {
    Shorter,
    Longer,
    Mismatch,
}

/// Error type for fraud proof generation.
#[derive(Debug, thiserror::Error)]
pub enum FraudProofError {
    #[error(
        "Out of bounds extrinsic index for creating the fraud proof, got: {index}, max: {max}"
    )]
    OutOfBoundsExtrinsicIndex { index: usize, max: usize },
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
    #[error("Missing extrinsics in the Consesnsus block")]
    MissingConsensusExtrinsics,
    #[error("Unable to decode opaque bundle's extrinsic at index {extrinsic_index}")]
    UnableToDecodeOpaqueBundleExtrinsic {
        extrinsic_index: usize,
        decoding_error: codec::Error,
    },
    #[error(
    "Invalid extrinsic index for creating illegal tx fraud proof, \
        expected extrinsic index: {index},\
        is_true_invalid: {is_true_invalid} and validity response is: {extrinsics_validity_response:?}"
    )]
    InvalidIllegalTxFraudProofExtrinsicIndex {
        index: usize,
        is_true_invalid: bool,
        extrinsics_validity_response: Result<(), CheckExtrinsicsValidityError>,
    },
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

type FraudProofFor<CBlock, DomainHeader> =
    FraudProof<NumberFor<CBlock>, <CBlock as BlockT>::Hash, DomainHeader>;

impl<Block, CBlock, Client, CClient, Backend, E>
    FraudProofGenerator<Block, CBlock, Client, CClient, Backend, E>
where
    Block: BlockT,
    Block::Hash: Into<H256>,
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

    pub(crate) fn generate_invalid_block_fees_proof(
        &self,
        domain_id: DomainId,
        local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        bad_receipt_hash: Block::Hash,
    ) -> Result<FraudProofFor<CBlock, Block::Header>, FraudProofError> {
        let block_hash = local_receipt.domain_block_hash;
        let key = sp_domains::operator_block_fees_final_key();
        let proof = self
            .client
            .read_proof(block_hash, &mut [key.as_slice()].into_iter())?;
        Ok(FraudProof::InvalidBlockFees(InvalidBlockFeesProof {
            domain_id,
            bad_receipt_hash,
            storage_proof: proof,
        }))
    }

    pub(crate) fn generate_invalid_transfers_proof(
        &self,
        domain_id: DomainId,
        local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        bad_receipt_hash: Block::Hash,
    ) -> Result<FraudProofFor<CBlock, Block::Header>, FraudProofError> {
        let block_hash = local_receipt.domain_block_hash;
        let runtime_api = self.client.runtime_api();
        let key = runtime_api.transfers_storage_key(block_hash)?;
        let proof = self
            .client
            .read_proof(block_hash, &mut [key.as_slice()].into_iter())?;
        Ok(FraudProof::InvalidTransfers(InvalidTransfersProof {
            domain_id,
            bad_receipt_hash,
            storage_proof: proof,
        }))
    }

    pub(crate) fn generate_invalid_domain_block_hash_proof(
        &self,
        domain_id: DomainId,
        local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        bad_receipt_hash: Block::Hash,
    ) -> Result<FraudProofFor<CBlock, Block::Header>, FraudProofError> {
        let block_hash = local_receipt.domain_block_hash;
        let digest_key = sp_domains::system_digest_final_key();
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

    pub(crate) fn generate_invalid_bundle_field_proof(
        &self,
        domain_id: DomainId,
        local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        mismatch_type: BundleMismatchType,
        bundle_index: u32,
        bad_receipt_hash: Block::Hash,
    ) -> Result<FraudProofFor<CBlock, Block::Header>, FraudProofError> {
        let consensus_block_hash = local_receipt.consensus_block_hash;
        let consensus_extrinsics = self
            .consensus_client
            .block_body(consensus_block_hash)?
            .ok_or(FraudProofError::MissingConsensusExtrinsics)?;

        let bundles = self
            .consensus_client
            .runtime_api()
            .extract_successful_bundles(consensus_block_hash, domain_id, consensus_extrinsics)?;

        let bundle = bundles
            .get(bundle_index as usize)
            .ok_or(FraudProofError::MissingBundle {
                bundle_index: bundle_index as usize,
            })?;

        let (invalid_type, is_true_invalid) = match mismatch_type {
            BundleMismatchType::TrueInvalid(invalid_type) => (invalid_type, true),
            BundleMismatchType::FalseInvalid(invalid_type) => (invalid_type, false),
            BundleMismatchType::Valid => {
                return Err(sp_blockchain::Error::Application(
                    "Unexpected bundle mismatch type, this should not happen"
                        .to_string()
                        .into(),
                )
                .into());
            }
        };

        let extrinsic_index = invalid_type.extrinsic_index();
        let encoded_extrinsics: Vec<_> = bundle.extrinsics.iter().map(Encode::encode).collect();
        let proof_data = if let InvalidBundleType::IllegalTx(expected_extrinsic_index) =
            invalid_type
        {
            if expected_extrinsic_index as usize >= bundle.extrinsics.len() {
                return Err(FraudProofError::OutOfBoundsExtrinsicIndex {
                    index: expected_extrinsic_index as usize,
                    max: bundle.extrinsics.len(),
                });
            }

            let domain_block_parent_hash = *self
                .client
                .header(local_receipt.domain_block_hash)?
                .ok_or_else(|| {
                    FraudProofError::Blockchain(sp_blockchain::Error::MissingHeader(format!(
                        "{:?}",
                        local_receipt.domain_block_hash
                    )))
                })?
                .parent_hash();

            let domain_block_parent_number = self
                .client
                .block_number_from_id(&BlockId::Hash(domain_block_parent_hash))?
                .ok_or_else(|| {
                    FraudProofError::Blockchain(sp_blockchain::Error::Backend(format!(
                        "unable to get block number for domain block:{:?}",
                        domain_block_parent_hash
                    )))
                })?;

            let mut runtime_api_instance = self.client.runtime_api();
            runtime_api_instance.record_proof();
            let proof_recorder = runtime_api_instance
                .proof_recorder()
                .expect("we enabled proof recording just above; qed");

            let mut block_extrinsics = vec![];
            for (extrinsic_index, extrinsic) in bundle
                .extrinsics
                .iter()
                .enumerate()
                .take((expected_extrinsic_index + 1) as usize)
            {
                let encoded_extrinsic = extrinsic.encode();
                block_extrinsics.push(
                    <Block as BlockT>::Extrinsic::decode(&mut encoded_extrinsic.as_slice())
                        .map_err(|decoding_error| {
                            FraudProofError::UnableToDecodeOpaqueBundleExtrinsic {
                                extrinsic_index,
                                decoding_error,
                            }
                        })?,
                );
            }

            let validation_response = runtime_api_instance.check_extrinsics_and_do_pre_dispatch(
                domain_block_parent_hash,
                block_extrinsics,
                domain_block_parent_number,
                domain_block_parent_hash,
            )?;

            // If the proof is true invalid then validation response should not be Ok.
            // If the proof is false invalid then validation response should not be Err.
            // OR
            // If it is true invalid and expected extrinsic index does not match
            if (is_true_invalid == validation_response.is_ok())
                || (is_true_invalid
                    && validation_response
                        .as_ref()
                        .is_err_and(|e| e.extrinsic_index != expected_extrinsic_index))
            {
                return Err(FraudProofError::InvalidIllegalTxFraudProofExtrinsicIndex {
                    index: expected_extrinsic_index as usize,
                    is_true_invalid,
                    extrinsics_validity_response: validation_response,
                });
            }

            proof_recorder.drain_storage_proof()
        } else {
            StorageProofProvider::<
                LayoutV1<HeaderHashingFor<Block::Header>>,
            >::generate_enumerated_proof_of_inclusion(
                encoded_extrinsics.as_slice(), extrinsic_index,
            )
                .ok_or(FraudProofError::FailToGenerateProofOfInclusion)?
        };

        Ok(FraudProof::InvalidBundles(InvalidBundlesFraudProof::new(
            bad_receipt_hash,
            domain_id,
            bundle_index,
            invalid_type,
            proof_data,
            is_true_invalid,
        )))
    }

    pub(crate) fn generate_invalid_domain_extrinsics_root_proof(
        &self,
        domain_id: DomainId,
        local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        bad_receipt_hash: Block::Hash,
    ) -> Result<FraudProofFor<CBlock, Block::Header>, FraudProofError> {
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
                        ExtrinsicDigest::new::<LayoutV1<HeaderHashingFor<Block::Header>>>(
                            ext.encode(),
                        ),
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

    pub(crate) fn generate_invalid_state_transition_proof(
        &self,
        domain_id: DomainId,
        execution_phase: ExecutionPhase,
        local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        bad_receipt_trace_length: usize,
        bad_receipt_hash: Block::Hash,
    ) -> Result<FraudProofFor<CBlock, Block::Header>, FraudProofError> {
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

        let extrinsics = self.block_body(block_hash)?;
        let max_extrinsic_index = extrinsics.len() - 1;
        let encoded_extrinsics: Vec<_> = extrinsics.iter().map(Encode::encode).collect();

        let block_builder = BlockBuilder::new(
            &*self.client,
            parent_header.hash(),
            *parent_header.number(),
            RecordProof::No,
            inherent_digests.clone(),
            &*self.backend,
            extrinsics.into(),
            // NOTE: the inherent extrinsic is already contained in the above `extrinsics`, which
            // is getting from the block body, thus it is okay to pass `maybe_inherent_data` as
            // `None` and `is_gemini_3h` as `false`, the latter is only used when `maybe_inherent_data`
            // is `Some`.
            None,
            false,
        )?;

        let (storage_changes, call_data) = match &execution_phase {
            ExecutionPhase::InitializeBlock => (
                None,
                Block::Header::new(
                    block_number,
                    Default::default(),
                    Default::default(),
                    parent_header.hash(),
                    inherent_digests,
                )
                .encode(),
            ),
            ExecutionPhase::ApplyExtrinsic { mismatch, .. } => {
                let extrinsic_index = match mismatch {
                    ApplyExtrinsicMismatch::StateRoot(trace_mismatch_index) => {
                        (trace_mismatch_index - 1) as usize
                    }
                    ApplyExtrinsicMismatch::Shorter => (bad_receipt_trace_length - 1) - 1,
                };

                let target_extrinsic = encoded_extrinsics.get(extrinsic_index).ok_or(
                    FraudProofError::OutOfBoundsExtrinsicIndex {
                        index: extrinsic_index,
                        max: max_extrinsic_index,
                    },
                )?;

                (
                    Some(block_builder.prepare_storage_changes_before(extrinsic_index)?),
                    target_extrinsic.clone(),
                )
            }
            ExecutionPhase::FinalizeBlock { .. } => (
                Some(block_builder.prepare_storage_changes_before_finalize_block()?),
                Vec::new(),
            ),
        };

        let delta_changes = storage_changes.map(|storage_changes| {
            (
                storage_changes.transaction,
                storage_changes.transaction_storage_root,
            )
        });

        let execution_proof = prover.prove_execution(
            parent_header.hash(),
            &execution_phase,
            call_data.as_slice(),
            delta_changes,
        )?;

        let invalid_state_transition_proof = InvalidStateTransitionProof {
            domain_id,
            bad_receipt_hash,
            proof: execution_proof,
            execution_phase,
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

    fn generate_execution_phase(
        &self,
        local_receipt_domain_block_hash: <Block as BlockT>::Hash,
        local_trace_length: usize,
        mismatch: (TraceDiffType, u32),
    ) -> Result<ExecutionPhase, FraudProofError> {
        let extrinsics = self.block_body(local_receipt_domain_block_hash)?;
        let encoded_extrinsics: Vec<_> = extrinsics.iter().map(Encode::encode).collect();

        match mismatch {
            (_, 0) => Ok(ExecutionPhase::InitializeBlock),
            (TraceDiffType::Longer, mismatch_trace_index) => Ok(ExecutionPhase::FinalizeBlock {
                mismatch: FinalizeBlockMismatch::Longer(mismatch_trace_index),
            }),
            (TraceDiffType::Mismatch, mismatch_trace_index)
                if mismatch_trace_index as usize == local_trace_length - 1 =>
            {
                Ok(ExecutionPhase::FinalizeBlock {
                    mismatch: FinalizeBlockMismatch::StateRoot,
                })
            }
            (TraceDiffType::Mismatch, mismatch_trace_index)
            | (TraceDiffType::Shorter, mismatch_trace_index) => {
                // There is a trace root of the `initialize_block` in the head of the trace so we
                // need to minus one to get the correct `extrinsic_index`
                let extrinsic_index = mismatch_trace_index as usize - 1;

                if extrinsic_index >= encoded_extrinsics.len() {
                    return Err(FraudProofError::OutOfBoundsExtrinsicIndex {
                        index: extrinsic_index,
                        max: encoded_extrinsics.len(),
                    });
                }

                let proof_of_inclusion = StorageProofProvider::<
                    LayoutV1<<Block::Header as HeaderT>::Hashing>,
                >::generate_enumerated_proof_of_inclusion(
                    encoded_extrinsics.as_slice(),
                    extrinsic_index as u32,
                )
                .ok_or(FraudProofError::FailToGenerateProofOfInclusion)?;

                Ok(ExecutionPhase::ApplyExtrinsic {
                    extrinsic_proof: proof_of_inclusion,
                    mismatch: if mismatch.0 == TraceDiffType::Mismatch {
                        ApplyExtrinsicMismatch::StateRoot(mismatch_trace_index)
                    } else {
                        ApplyExtrinsicMismatch::Shorter
                    },
                })
            }
        }
    }

    /// Returns first mismatched ExecutionPhase between the receipts `local` and `other` if any.
    /// If local trace length > other trace length then we provide storage proof as usual but add a flag in fraud proof
    /// indicating that this is length mismatch, so we create a storage proof with ApplyExtrinsic execution phase
    /// and prove that this state transition is valid, that means execution should not stop here.
    ///
    /// if other trace length > local trace length then we create a storage proof with FinalizeBlock execution phase
    /// to prove that it is valid, so that means execution should stop here.
    pub(crate) fn find_mismatched_execution_phase(
        &self,
        local_receipt_domain_block_hash: <Block as BlockT>::Hash,
        local_trace: &[<Block as BlockT>::Hash],
        other_trace: &[<Block as BlockT>::Hash],
    ) -> Result<Option<ExecutionPhase>, FraudProofError> {
        let state_root_mismatch = local_trace
            .iter()
            .enumerate()
            .zip(other_trace.iter().enumerate())
            .find_map(|((local_index, local_root), (_, other_root))| {
                if local_root != other_root {
                    Some((TraceDiffType::Mismatch, local_index as u32))
                } else {
                    None
                }
            });

        let mismatch = if let Some(mismatch) = state_root_mismatch {
            mismatch
        } else if local_trace.len() > other_trace.len() {
            (TraceDiffType::Shorter, (other_trace.len() - 1) as u32)
        } else if local_trace.len() < other_trace.len() {
            (TraceDiffType::Longer, (local_trace.len() - 1) as u32)
        } else {
            return Ok(None);
        };

        self.generate_execution_phase(local_receipt_domain_block_hash, local_trace.len(), mismatch)
            .map(Some)
    }
}

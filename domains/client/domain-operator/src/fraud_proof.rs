use crate::utils::to_number_primitive;
use crate::{ExecutionReceiptFor, TransactionFor};
use codec::{Decode, Encode};
use domain_block_builder::{BlockBuilder, RecordProof};
use sc_client_api::{AuxStore, BlockBackend, StateBackendFor};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::fraud_proof::{ExecutionPhase, FraudProof, InvalidStateTransitionProof};
use sp_domains::DomainId;
use sp_runtime::traits::{Block as BlockT, HashFor, Header as HeaderT, NumberFor};
use sp_runtime::Digest;
use sp_trie::StorageProof;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_fraud_proof::invalid_state_transition_proof::ExecutionProver;

/// Error type for fraud proof generation.
#[derive(Debug, thiserror::Error)]
pub enum FraudProofError {
    #[error("State root not using H256")]
    InvalidStateRootType,
    #[error("Invalid trace index, got: {index}, max: {max}")]
    InvalidTraceIndex { index: usize, max: usize },
    #[error("Invalid extrinsic index for creating the execution proof, got: {index}, max: {max}")]
    InvalidExtrinsicIndex { index: usize, max: usize },
    #[error(transparent)]
    Blockchain(#[from] sp_blockchain::Error),
    #[error(transparent)]
    RuntimeApi(#[from] sp_api::ApiError),
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

impl<Block, CBlock, Client, CClient, Backend, E>
    FraudProofGenerator<Block, CBlock, Client, CClient, Backend, E>
where
    Block: BlockT,
    CBlock: BlockT,
    Client:
        HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
    Client::Api: sp_block_builder::BlockBuilder<Block>
        + sp_api::ApiExt<Block, StateBackend = StateBackendFor<Backend, Block>>,
    CClient: HeaderBackend<CBlock> + 'static,
    Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
    TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
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

    pub(crate) fn generate_invalid_state_transition_proof<PCB>(
        &self,
        domain_id: DomainId,
        local_trace_index: u32,
        local_receipt: &ExecutionReceiptFor<Block, CBlock>,
        bad_receipt_hash: H256,
    ) -> Result<FraudProof<NumberFor<PCB>, PCB::Hash>, FraudProofError>
    where
        PCB: BlockT,
    {
        let block_hash = local_receipt.domain_hash;
        let block_number = to_number_primitive(local_receipt.consensus_block_number);

        let header = self.header(block_hash)?;
        let parent_header = self.header(*header.parent_hash())?;

        // TODO: avoid the encode & decode?
        let as_h256 = |state_root: &Block::Hash| {
            H256::decode(&mut state_root.encode().as_slice())
                .map_err(|_| FraudProofError::InvalidStateRootType)
        };

        let prover = ExecutionProver::new(self.backend.clone(), self.code_executor.clone());

        let parent_number = to_number_primitive(*parent_header.number());

        let local_root = local_receipt.trace.get(local_trace_index as usize).ok_or(
            FraudProofError::InvalidTraceIndex {
                index: local_trace_index as usize,
                max: local_receipt.trace.len() - 1,
            },
        )?;

        let consensus_parent_hash = H256::decode(
            &mut self
                .consensus_client
                .header(local_receipt.consensus_block_hash)?
                .ok_or_else(|| {
                    sp_blockchain::Error::Backend(format!(
                        "Header not found for consensus block {:?}",
                        local_receipt.consensus_block_hash
                    ))
                })?
                .parent_hash()
                .encode()
                .as_slice(),
        )
        .map_err(|_| FraudProofError::InvalidStateRootType)?;

        let digest = Digest::default();

        // TODO: abstract the execution proof impl to be reusable in the test.
        let invalid_state_transition_proof = if local_trace_index == 0 {
            // `initialize_block` execution proof.
            let pre_state_root = as_h256(parent_header.state_root())?;
            let post_state_root = as_h256(local_root)?;

            // TODO: add a test to cover the entire flow of creation and verification in the production
            // environment, i.e., the generate_proof function on the executor side and the verify function
            // on the verifier side.
            let new_header = Block::Header::new(
                block_number.into(),
                Default::default(),
                Default::default(),
                parent_header.hash(),
                digest,
            );
            let execution_phase = ExecutionPhase::InitializeBlock {
                domain_parent_hash: as_h256(&parent_header.hash())?,
            };
            let initialize_block_call_data = new_header.encode();

            let proof = prover.prove_execution::<TransactionFor<Backend, Block>>(
                parent_header.hash(),
                &execution_phase,
                &initialize_block_call_data,
                None,
            )?;

            InvalidStateTransitionProof {
                domain_id,
                bad_receipt_hash,
                parent_number,
                consensus_parent_hash,
                pre_state_root,
                post_state_root,
                proof,
                execution_phase,
            }
        } else if local_trace_index as usize == local_receipt.trace.len() - 1 {
            // `finalize_block` execution proof.
            let pre_state_root = as_h256(&local_receipt.trace[local_trace_index as usize - 1])?;
            let post_state_root = as_h256(local_root)?;
            let extrinsics = self.block_body(block_hash)?;
            let execution_phase = ExecutionPhase::FinalizeBlock {
                total_extrinsics: local_trace_index - 1,
            };
            let finalize_block_call_data = Vec::new();

            let block_builder = BlockBuilder::new(
                &*self.client,
                parent_header.hash(),
                *parent_header.number(),
                RecordProof::No,
                digest,
                &*self.backend,
                extrinsics,
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
                parent_number,
                consensus_parent_hash,
                pre_state_root,
                post_state_root,
                proof,
                execution_phase,
            }
        } else {
            // Regular extrinsic execution proof.
            let pre_state_root = as_h256(&local_receipt.trace[local_trace_index as usize - 1])?;
            let post_state_root = as_h256(local_root)?;

            let (proof, execution_phase) = self.create_extrinsic_execution_proof(
                local_trace_index as usize - 1,
                &parent_header,
                block_hash,
                &prover,
                digest,
            )?;

            // TODO: proof should be a CompactProof.
            InvalidStateTransitionProof {
                domain_id,
                bad_receipt_hash,
                parent_number,
                consensus_parent_hash,
                pre_state_root,
                post_state_root,
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

    fn create_extrinsic_execution_proof(
        &self,
        extrinsic_index: usize,
        parent_header: &Block::Header,
        current_hash: Block::Hash,
        prover: &ExecutionProver<Block, Backend, E>,
        digest: Digest,
    ) -> Result<(StorageProof, ExecutionPhase), FraudProofError> {
        let extrinsics = self.block_body(current_hash)?;

        let encoded_extrinsic = extrinsics
            .get(extrinsic_index)
            .ok_or(FraudProofError::InvalidExtrinsicIndex {
                index: extrinsic_index,
                max: extrinsics.len() - 1,
            })?
            .encode();

        let execution_phase = ExecutionPhase::ApplyExtrinsic(
            extrinsic_index
                .try_into()
                .expect("extrinsic_index must fit into u32"),
        );
        let apply_extrinsic_call_data = encoded_extrinsic;

        let block_builder = BlockBuilder::new(
            &*self.client,
            parent_header.hash(),
            *parent_header.number(),
            RecordProof::No,
            digest,
            &*self.backend,
            extrinsics,
        )?;
        let storage_changes = block_builder.prepare_storage_changes_before(extrinsic_index)?;

        let delta = storage_changes.transaction;
        let post_delta_root = storage_changes.transaction_storage_root;
        let execution_proof = prover.prove_execution(
            parent_header.hash(),
            &execution_phase,
            &apply_extrinsic_call_data,
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

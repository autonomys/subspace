use crate::TransactionFor;
use cirrus_block_builder::{BlockBuilder, RecordProof};
use cirrus_primitives::{AccountId, SecondaryApi};
use codec::{Decode, Encode};
use sc_client_api::{AuxStore, BlockBackend};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::{
	traits::{CodeExecutor, SpawnNamed},
	H256,
};
use sp_executor::{ExecutionPhase, ExecutionReceipt, FraudProof};
use sp_runtime::{
	generic::BlockId,
	traits::{Block as BlockT, HashFor, Header as HeaderT, NumberFor},
};
use sp_trie::StorageProof;
use std::{marker::PhantomData, sync::Arc};
use subspace_core_primitives::BlockNumber;

/// Error type for cirrus gossip handling.
#[derive(Debug, thiserror::Error)]
pub enum FraudProofError {
	#[error("State root not using H256")]
	InvalidStateRootType,
	#[error("Invalid extrinsic index for creating the execution proof, got: {index}, max: {max}")]
	InvalidExtrinsicIndex { index: usize, max: usize },
	#[error(transparent)]
	Blockchain(#[from] sp_blockchain::Error),
	#[error(transparent)]
	RuntimeApi(#[from] sp_api::ApiError),
}

pub(crate) struct FraudProofGenerator<Block, Client, Backend, E> {
	client: Arc<Client>,
	spawner: Box<dyn SpawnNamed + Send + Sync>,
	backend: Arc<Backend>,
	code_executor: Arc<E>,
	_phantom: PhantomData<Block>,
}

impl<Block, Client, Backend, E> Clone for FraudProofGenerator<Block, Client, Backend, E> {
	fn clone(&self) -> Self {
		Self {
			client: self.client.clone(),
			spawner: self.spawner.clone(),
			backend: self.backend.clone(),
			code_executor: self.code_executor.clone(),
			_phantom: self._phantom,
		}
	}
}

impl<Block, Client, Backend, E> FraudProofGenerator<Block, Client, Backend, E>
where
	Block: BlockT,
	Client:
		HeaderBackend<Block> + BlockBackend<Block> + AuxStore + ProvideRuntimeApi<Block> + 'static,
	Client::Api: SecondaryApi<Block, AccountId>
		+ sp_block_builder::BlockBuilder<Block>
		+ sp_api::ApiExt<
			Block,
			StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
		>,
	Backend: sc_client_api::Backend<Block> + Send + Sync + 'static,
	TransactionFor<Backend, Block>: sp_trie::HashDBT<HashFor<Block>, sp_trie::DBValue>,
	E: CodeExecutor,
{
	pub(crate) fn new(
		client: Arc<Client>,
		spawner: Box<dyn SpawnNamed + Send + Sync>,
		backend: Arc<Backend>,
		code_executor: Arc<E>,
	) -> Self {
		Self { client, spawner, backend, code_executor, _phantom: Default::default() }
	}

	pub(crate) fn generate_proof<Number, PHash>(
		&self,
		block_number: NumberFor<Block>,
		local_trace_index: usize,
		local_receipt: &ExecutionReceipt<Number, PHash, Block::Hash>,
	) -> Result<FraudProof, FraudProofError> {
		let block_hash = local_receipt.secondary_hash;

		let header = self.header(block_hash)?;
		let parent_header = self.header(*header.parent_hash())?;

		// TODO: avoid the encode & decode?
		let as_h256 = |state_root: &Block::Hash| {
			H256::decode(&mut state_root.encode().as_slice())
				.map_err(|_| FraudProofError::InvalidStateRootType)
		};

		let prover = subspace_fraud_proof::ExecutionProver::new(
			self.backend.clone(),
			self.code_executor.clone(),
			self.spawner.clone() as Box<dyn SpawnNamed>,
		);

		let parent_number = TryInto::<BlockNumber>::try_into(*parent_header.number())
			.unwrap_or_else(|_| panic!("Parent number must fit into u32; qed"));

		let local_root = local_receipt.trace[local_trace_index];

		// TODO: abstract the execution proof impl to be reusable in the test.
		let fraud_proof = if local_trace_index == 0 {
			// `initialize_block` execution proof.
			let pre_state_root = as_h256(parent_header.state_root())?;
			let post_state_root = as_h256(&local_root)?;

			let new_header = Block::Header::new(
				block_number,
				Default::default(),
				Default::default(),
				parent_header.hash(),
				Default::default(),
			);
			let execution_phase =
				ExecutionPhase::InitializeBlock { call_data: new_header.encode() };

			let proof = prover.prove_execution::<TransactionFor<Backend, Block>>(
				BlockId::Hash(parent_header.hash()),
				&execution_phase,
				None,
			)?;

			FraudProof {
				parent_number,
				parent_hash: as_h256(&parent_header.hash())?,
				pre_state_root,
				post_state_root,
				proof,
				execution_phase,
			}
		} else if local_trace_index == local_receipt.trace.len() - 1 {
			// `finalize_block` execution proof.
			let pre_state_root = as_h256(&local_receipt.trace[local_trace_index - 1])?;
			let post_state_root = as_h256(&local_root)?;
			let execution_phase = ExecutionPhase::FinalizeBlock;

			let block_builder = BlockBuilder::new(
				&*self.client,
				parent_header.hash(),
				*parent_header.number(),
				RecordProof::No,
				Default::default(),
				&*self.backend,
				self.block_body(block_hash)?,
			)?;
			let storage_changes = block_builder.prepare_storage_changes_before_finalize_block()?;

			let delta = storage_changes.transaction;
			let post_delta_root = storage_changes.transaction_storage_root;

			let proof = prover.prove_execution(
				BlockId::Hash(parent_header.hash()),
				&execution_phase,
				Some((delta, post_delta_root)),
			)?;

			FraudProof {
				parent_number,
				parent_hash: as_h256(&parent_header.hash())?,
				pre_state_root,
				post_state_root,
				proof,
				execution_phase,
			}
		} else {
			// Regular extrinsic execution proof.
			let pre_state_root = as_h256(&local_receipt.trace[local_trace_index - 1])?;
			let post_state_root = as_h256(&local_root)?;

			let (proof, execution_phase) = self.create_extrinsic_execution_proof(
				local_trace_index - 1,
				&parent_header,
				block_hash,
				&prover,
			)?;

			// TODO: proof should be a CompactProof.
			FraudProof {
				parent_number,
				parent_hash: as_h256(&parent_header.hash())?,
				pre_state_root,
				post_state_root,
				proof,
				execution_phase,
			}
		};

		Ok(fraud_proof)
	}

	fn header(&self, at: Block::Hash) -> Result<Block::Header, sp_blockchain::Error> {
		self.client
			.header(BlockId::Hash(at))?
			.ok_or_else(|| sp_blockchain::Error::Backend(format!("Header not found for {:?}", at)))
	}

	fn block_body(&self, at: Block::Hash) -> Result<Vec<Block::Extrinsic>, sp_blockchain::Error> {
		self.client.block_body(&BlockId::Hash(at))?.ok_or_else(|| {
			sp_blockchain::Error::Backend(format!("Block body not found for {:?}", at))
		})
	}

	fn create_extrinsic_execution_proof(
		&self,
		extrinsic_index: usize,
		parent_header: &Block::Header,
		current_hash: Block::Hash,
		prover: &subspace_fraud_proof::ExecutionProver<Block, Backend, E>,
	) -> Result<(StorageProof, ExecutionPhase), FraudProofError> {
		let extrinsics = self.block_body(current_hash)?;

		let encoded_extrinsic = extrinsics
			.get(extrinsic_index)
			.ok_or(FraudProofError::InvalidExtrinsicIndex {
				index: extrinsic_index,
				max: extrinsics.len() - 1,
			})?
			.encode();

		let execution_phase = ExecutionPhase::ApplyExtrinsic { call_data: encoded_extrinsic };

		let block_builder = BlockBuilder::new(
			&*self.client,
			parent_header.hash(),
			*parent_header.number(),
			RecordProof::No,
			Default::default(),
			&*self.backend,
			extrinsics,
		)?;
		let storage_changes = block_builder.prepare_storage_changes_before(extrinsic_index)?;

		let delta = storage_changes.transaction;
		let post_delta_root = storage_changes.transaction_storage_root;
		let execution_proof = prover.prove_execution(
			BlockId::Hash(parent_header.hash()),
			&execution_phase,
			Some((delta, post_delta_root)),
		)?;

		Ok((execution_proof, execution_phase))
	}
}

/// Compares if the receipt `other` is the same with `local`, return a tuple of (local_index,
/// local_trace_root) if there is a mismatch.
pub(crate) fn find_trace_mismatch<Number, Hash: Copy + Eq, PHash>(
	local: &ExecutionReceipt<Number, PHash, Hash>,
	other: &ExecutionReceipt<Number, PHash, Hash>,
) -> Option<usize> {
	local.trace.iter().enumerate().zip(other.trace.iter().enumerate()).find_map(
		|((local_index, local_root), (_, other_root))| {
			if local_root != other_root {
				Some(local_index)
			} else {
				None
			}
		},
	)
}

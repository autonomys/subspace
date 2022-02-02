//! Schema for executor in the aux-db.

use codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, Result as ClientResult};
use sp_executor::ExecutionReceipt;
use sp_runtime::{
	traits::{Block as BlockT, Header as HeaderT, One, Saturating},
	SaturatedConversion,
};

const EXECUTION_RECEIPT_KEY: &[u8] = b"execution_receipt";
const EXECUTION_RECEIPT_START: &[u8] = b"execution_receipt_start";
const EXECUTION_RECEIPT_BLOCK_NUMBER: &[u8] = b"execution_receipt_block_number";
/// Prune the execution receipts when they reach this number.
const PRUNING_DEPTH: u64 = 1000;

fn execution_receipt_key(block_hash: impl Encode) -> Vec<u8> {
	(EXECUTION_RECEIPT_KEY, block_hash).encode()
}

fn load_decode<Backend: AuxStore, T: Decode>(
	backend: &Backend,
	key: &[u8],
) -> ClientResult<Option<T>> {
	match backend.get_aux(key)? {
		None => Ok(None),
		Some(t) => T::decode(&mut &t[..])
			.map_err(|e| {
				ClientError::Backend(format!("Executor DB is corrupted. Decode error: {}", e))
			})
			.map(Some),
	}
}

/// Write the execution receipt of a block to aux storage, optionally prune the receipts that are
/// too old.
pub(super) fn write_execution_receipt<Backend: AuxStore, Block: BlockT>(
	backend: &Backend,
	block_hash: Block::Hash,
	block_number: <<Block as BlockT>::Header as HeaderT>::Number,
	execution_receipt: &ExecutionReceipt<Block::Hash>,
) -> Result<(), sp_blockchain::Error> {
	let block_number_key = (EXECUTION_RECEIPT_BLOCK_NUMBER, block_number).encode();
	let mut hashes_at_block_number =
		load_decode::<_, Vec<Block::Hash>>(backend, block_number_key.as_slice())?
			.unwrap_or_default();
	hashes_at_block_number.push(block_hash);

	let first_saved_receipt = load_decode::<_, <<Block as BlockT>::Header as HeaderT>::Number>(
		backend,
		EXECUTION_RECEIPT_START,
	)?
	.unwrap_or(block_number);

	let mut new_first_saved_receipt = first_saved_receipt;

	if block_number - first_saved_receipt >= PRUNING_DEPTH.saturated_into() {
		new_first_saved_receipt = block_number.saturating_sub((PRUNING_DEPTH - 1).saturated_into());

		let mut keys_to_delete = vec![];
		let mut to_delete_block_number = first_saved_receipt;
		while to_delete_block_number < new_first_saved_receipt {
			let delete_block_number_key =
				(EXECUTION_RECEIPT_BLOCK_NUMBER, to_delete_block_number).encode();
			if let Some(hashes_to_delete) =
				load_decode::<_, Vec<Block::Hash>>(backend, delete_block_number_key.as_slice())?
			{
				keys_to_delete.extend(
					hashes_to_delete.into_iter().map(|h| (EXECUTION_RECEIPT_KEY, h).encode()),
				);
				keys_to_delete.push(delete_block_number_key);
			}
			to_delete_block_number = to_delete_block_number.saturating_add(One::one());
		}

		backend.insert_aux(
			&[
				(
					execution_receipt_key(block_hash).as_slice(),
					execution_receipt.encode().as_slice(),
				),
				(block_number_key.as_slice(), hashes_at_block_number.encode().as_slice()),
				((EXECUTION_RECEIPT_START, new_first_saved_receipt.encode().as_slice())),
			],
			&keys_to_delete.iter().map(|k| &k[..]).collect::<Vec<&[u8]>>()[..],
		)
	} else {
		backend.insert_aux(
			&[
				(
					execution_receipt_key(block_hash).as_slice(),
					execution_receipt.encode().as_slice(),
				),
				(block_number_key.as_slice(), hashes_at_block_number.encode().as_slice()),
				((EXECUTION_RECEIPT_START, new_first_saved_receipt.encode().as_slice())),
			],
			[],
		)
	}
}

/// Load the execution receipt associated with a block.
pub(super) fn load_execution_receipt<Backend: AuxStore, Block: BlockT>(
	backend: &Backend,
	block_hash: Block::Hash,
) -> ClientResult<Option<ExecutionReceipt<Block::Hash>>> {
	load_decode(backend, execution_receipt_key(block_hash).as_slice())
}

pub(super) fn target_receipt_is_pruned<Block: BlockT>(
	current_block: <<Block as BlockT>::Header as HeaderT>::Number,
	target_block: <<Block as BlockT>::Header as HeaderT>::Number,
) -> bool {
	current_block - target_block >= PRUNING_DEPTH.saturated_into()
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_core::hash::H256;
	use substrate_test_runtime::{Block, BlockNumber, Hash};

	type ExecutionReceipt = sp_executor::ExecutionReceipt<Hash>;

	fn create_execution_receipt() -> ExecutionReceipt {
		ExecutionReceipt {
			primary_hash: H256::random(),
			secondary_hash: H256::random(),
			trace: Default::default(),
			trace_root: Default::default(),
		}
	}

	#[test]
	fn prune_execution_receipt_works() {
		let client = substrate_test_runtime_client::new();

		let receipt_start = || {
			load_decode::<_, BlockNumber>(&client, EXECUTION_RECEIPT_START.to_vec().as_slice())
				.unwrap()
		};

		let hashes_at = |number: BlockNumber| {
			load_decode::<_, Vec<Hash>>(
				&client,
				(EXECUTION_RECEIPT_BLOCK_NUMBER, number).encode().as_slice(),
			)
			.unwrap()
		};

		let receipt_at =
			|block_hash: Hash| load_execution_receipt::<_, Block>(&client, block_hash).unwrap();

		let write_receipt_at = |hash: Hash, number: BlockNumber, receipt: &ExecutionReceipt| {
			write_execution_receipt::<_, Block>(&client, hash, number, receipt).unwrap()
		};

		assert_eq!(receipt_start(), None);

		// Create PRUNING_DEPTH receipts.
		let block_hash_list = (1..=PRUNING_DEPTH)
			.map(|block_number| {
				let receipt = create_execution_receipt();
				let block_hash = Hash::random();
				write_receipt_at(block_hash, block_number, &receipt);
				assert_eq!(receipt_at(block_hash), Some(receipt));
				assert_eq!(hashes_at(block_number), Some(vec![block_hash]));
				assert_eq!(receipt_start(), Some(1));
				block_hash
			})
			.collect::<Vec<_>>();

		assert!(!target_receipt_is_pruned::<Block>(PRUNING_DEPTH, 1));

		// Create PRUNING_DEPTH + 1 receipt.
		let block_hash = Hash::random();
		assert!(receipt_at(block_hash).is_none());
		write_receipt_at(block_hash, PRUNING_DEPTH + 1, &create_execution_receipt());
		assert!(receipt_at(block_hash).is_some());
		// ER of block #1 should be pruned.
		assert!(receipt_at(block_hash_list[0]).is_none());
		// block number mapping should be pruned as well.
		assert!(hashes_at(1).is_none());
		assert!(target_receipt_is_pruned::<Block>(PRUNING_DEPTH + 1, 1));
		assert_eq!(receipt_start(), Some(2));

		// Create PRUNING_DEPTH + 2 receipt.
		let block_hash = Hash::random();
		write_receipt_at(block_hash, PRUNING_DEPTH + 2, &create_execution_receipt());
		assert!(receipt_at(block_hash).is_some());
		// ER of block #2 should be pruned.
		assert!(receipt_at(block_hash_list[1]).is_none());
		assert!(target_receipt_is_pruned::<Block>(PRUNING_DEPTH + 2, 2));
		assert!(!target_receipt_is_pruned::<Block>(PRUNING_DEPTH + 2, 3));
		assert_eq!(receipt_start(), Some(3));

		// Multiple hashes attached to the block #(PRUNING_DEPTH + 2)
		let block_hash2 = Hash::random();
		write_receipt_at(block_hash2, PRUNING_DEPTH + 2, &create_execution_receipt());
		assert!(receipt_at(block_hash2).is_some());
		assert_eq!(hashes_at(PRUNING_DEPTH + 2), Some(vec![block_hash, block_hash2]));
	}
}

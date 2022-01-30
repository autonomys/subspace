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
/// Prune the execution receipts when they reach this number.
const PRUNING_DEPTH: u64 = 1000;

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
	block_number: <<Block as BlockT>::Header as HeaderT>::Number,
	execution_receipt: &ExecutionReceipt<Block::Hash>,
) -> Result<(), sp_blockchain::Error> {
	let first_saved_receipt = load_decode::<_, <<Block as BlockT>::Header as HeaderT>::Number>(
		backend,
		EXECUTION_RECEIPT_START,
	)?
	.unwrap_or(block_number);

	let mut new_first_saved_receipt = first_saved_receipt;

	if block_number - first_saved_receipt >= PRUNING_DEPTH.saturated_into() {
		new_first_saved_receipt = block_number.saturating_sub((PRUNING_DEPTH - 1).saturated_into());

		let mut keys_to_delete = vec![];
		let mut to_delete_start = first_saved_receipt;
		while to_delete_start < new_first_saved_receipt {
			keys_to_delete.push((EXECUTION_RECEIPT_KEY, to_delete_start).encode());
			to_delete_start = to_delete_start.saturating_add(One::one());
		}

		backend.insert_aux(
			&[
				(
					(EXECUTION_RECEIPT_KEY, block_number).encode().as_slice(),
					execution_receipt.encode().as_slice(),
				),
				((EXECUTION_RECEIPT_START, new_first_saved_receipt.encode().as_slice())),
			],
			&keys_to_delete.iter().map(|k| &k[..]).collect::<Vec<&[u8]>>()[..],
		)
	} else {
		backend.insert_aux(
			&[
				(
					(EXECUTION_RECEIPT_KEY, block_number).encode().as_slice(),
					execution_receipt.encode().as_slice(),
				),
				((EXECUTION_RECEIPT_START, new_first_saved_receipt.encode().as_slice())),
			],
			[],
		)
	}
}

/// Load the execution receipt associated with a block.
pub(super) fn load_execution_receipt<Backend: AuxStore, Block: BlockT>(
	backend: &Backend,
	block_number: <<Block as BlockT>::Header as HeaderT>::Number,
) -> ClientResult<Option<ExecutionReceipt<Block::Hash>>> {
	let key = (EXECUTION_RECEIPT_KEY, block_number).encode();
	load_decode(backend, key.as_slice())
}

/// Remove the validated execution receipt.
pub(super) fn delete_execution_receipt<Backend: AuxStore, Block: BlockT>(
	backend: &Backend,
	block_number: <<Block as BlockT>::Header as HeaderT>::Number,
) -> Result<(), sp_blockchain::Error> {
	let key = (EXECUTION_RECEIPT_KEY, block_number).encode();
	backend.insert_aux([], &[(key.as_slice())])
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

		let receipt_at =
			|number: BlockNumber| load_execution_receipt::<_, Block>(&client, number).unwrap();

		let write_receipt_at = |number: BlockNumber| {
			write_execution_receipt::<_, Block>(&client, number, &create_execution_receipt())
				.unwrap()
		};

		assert_eq!(receipt_start(), None);

		// Create PRUNING_DEPTH receipts.
		(1..=PRUNING_DEPTH).for_each(|number| {
			write_receipt_at(number);
			assert!(receipt_at(number).is_some());
			assert_eq!(receipt_start(), Some(1));
		});

		assert!(!target_receipt_is_pruned::<Block>(PRUNING_DEPTH, 1));

		// Create PRUNING_DEPTH + 1 receipt.
		write_receipt_at(PRUNING_DEPTH + 1);
		assert!(receipt_at(PRUNING_DEPTH + 1).is_some());
		// ER of block #1 should be pruned.
		assert!(receipt_at(1).is_none());
		assert!(target_receipt_is_pruned::<Block>(PRUNING_DEPTH + 1, 1));
		assert_eq!(receipt_start(), Some(2));

		// Create PRUNING_DEPTH + 2 receipt.
		write_receipt_at(PRUNING_DEPTH + 2);
		assert!(receipt_at(PRUNING_DEPTH + 2).is_some());
		// ER of block #2 should be pruned.
		assert!(receipt_at(2).is_none());
		assert!(target_receipt_is_pruned::<Block>(PRUNING_DEPTH + 2, 2));
		assert!(!target_receipt_is_pruned::<Block>(PRUNING_DEPTH + 2, 3));
		assert_eq!(receipt_start(), Some(3));
	}
}

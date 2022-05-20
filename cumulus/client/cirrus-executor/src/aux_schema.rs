//! Schema for executor in the aux-db.

use codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, Result as ClientResult};
use sp_executor::ExecutionReceipt;
use sp_runtime::traits::{Block as BlockT, NumberFor, One, SaturatedConversion, Saturating};
use subspace_core_primitives::BlockNumber;

const EXECUTION_RECEIPT_KEY: &[u8] = b"execution_receipt";
const EXECUTION_RECEIPT_START: &[u8] = b"execution_receipt_start";
const EXECUTION_RECEIPT_BLOCK_NUMBER: &[u8] = b"execution_receipt_block_number";
/// Prune the execution receipts when they reach this number.
const PRUNING_DEPTH: BlockNumber = 1000;

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
pub(super) fn write_execution_receipt<Backend: AuxStore, Block: BlockT, PBlock: BlockT>(
	backend: &Backend,
	(block_hash, block_number): (Block::Hash, NumberFor<Block>),
	best_execution_chain_number: NumberFor<Block>,
	execution_receipt: &ExecutionReceipt<NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
) -> Result<(), sp_blockchain::Error> {
	let block_number_key = (EXECUTION_RECEIPT_BLOCK_NUMBER, block_number).encode();
	let mut hashes_at_block_number =
		load_decode::<_, Vec<Block::Hash>>(backend, block_number_key.as_slice())?
			.unwrap_or_default();
	hashes_at_block_number.push(block_hash);

	let first_saved_receipt = load_decode::<_, NumberFor<Block>>(backend, EXECUTION_RECEIPT_START)?
		.unwrap_or(block_number);

	let mut new_first_saved_receipt = first_saved_receipt;

	let keys_to_delete =
		if best_execution_chain_number >= first_saved_receipt + PRUNING_DEPTH.saturated_into() {
			new_first_saved_receipt =
				best_execution_chain_number.saturating_sub((PRUNING_DEPTH - 1).saturated_into());

			let mut keys_to_delete = vec![];
			let mut to_delete_start = first_saved_receipt;
			while to_delete_start < new_first_saved_receipt {
				let delete_block_number_key =
					(EXECUTION_RECEIPT_BLOCK_NUMBER, to_delete_start).encode();
				if let Some(hashes_to_delete) =
					load_decode::<_, Vec<Block::Hash>>(backend, delete_block_number_key.as_slice())?
				{
					keys_to_delete.extend(
						hashes_to_delete.into_iter().map(|h| (EXECUTION_RECEIPT_KEY, h).encode()),
					);
					keys_to_delete.push(delete_block_number_key);
				}
				to_delete_start = to_delete_start.saturating_add(One::one());
			}

			keys_to_delete
		} else {
			vec![]
		};

	backend.insert_aux(
		&[
			(execution_receipt_key(block_hash).as_slice(), execution_receipt.encode().as_slice()),
			(block_number_key.as_slice(), hashes_at_block_number.encode().as_slice()),
			(EXECUTION_RECEIPT_START, new_first_saved_receipt.encode().as_slice()),
		],
		&keys_to_delete.iter().map(|k| &k[..]).collect::<Vec<&[u8]>>()[..],
	)
}

/// Load the execution receipt associated with a block.
pub(super) fn load_execution_receipt<Backend, Hash, Number, PHash>(
	backend: &Backend,
	block_hash: Hash,
) -> ClientResult<Option<ExecutionReceipt<Number, PHash, Hash>>>
where
	Backend: AuxStore,
	Hash: Encode + Decode,
	Number: Decode,
	PHash: Decode,
{
	load_decode(backend, execution_receipt_key(block_hash).as_slice())
}

pub(super) fn target_receipt_is_pruned(
	best_execution_chain_number: BlockNumber,
	target_block: BlockNumber,
) -> bool {
	best_execution_chain_number.checked_sub(target_block + PRUNING_DEPTH).is_some()
}

#[cfg(test)]
mod tests {
	use super::*;
	use cirrus_test_service::runtime::Block;
	use sp_core::hash::H256;
	use subspace_runtime_primitives::{BlockNumber, Hash};
	use subspace_test_runtime::Block as PBlock;

	type ExecutionReceipt = sp_executor::ExecutionReceipt<BlockNumber, Hash, Hash>;

	fn create_execution_receipt(primary_number: BlockNumber) -> ExecutionReceipt {
		ExecutionReceipt {
			primary_number,
			primary_hash: H256::random(),
			secondary_hash: H256::random(),
			trace: Default::default(),
			trace_root: Default::default(),
		}
	}

	#[test]
	fn normal_prune_execution_receipt_works() {
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

		let receipt_at = |block_hash: Hash| load_execution_receipt(&client, block_hash).unwrap();

		let write_receipt_at = |hash: Hash, number: BlockNumber, receipt: &ExecutionReceipt| {
			write_execution_receipt::<_, Block, PBlock>(
				&client,
				(hash, number),
				number - 1, // Ideally, the receipt of previous block has been included when writing the receipt of current block.
				receipt,
			)
			.unwrap()
		};

		assert_eq!(receipt_start(), None);

		// Create PRUNING_DEPTH receipts.
		let block_hash_list = (1..=PRUNING_DEPTH)
			.map(|block_number| {
				let receipt = create_execution_receipt(block_number);
				let block_hash = Hash::random();
				write_receipt_at(block_hash, block_number, &receipt);
				assert_eq!(receipt_at(block_hash), Some(receipt));
				assert_eq!(hashes_at(block_number), Some(vec![block_hash]));
				assert_eq!(receipt_start(), Some(1));
				block_hash
			})
			.collect::<Vec<_>>();

		assert!(!target_receipt_is_pruned(PRUNING_DEPTH, 1));

		// Create PRUNING_DEPTH + 1 receipt, best_execution_chain_number is PRUNING_DEPTH.
		let block_hash = Hash::random();
		assert!(receipt_at(block_hash).is_none());
		write_receipt_at(
			block_hash,
			PRUNING_DEPTH + 1,
			&create_execution_receipt(PRUNING_DEPTH + 1),
		);
		assert!(receipt_at(block_hash).is_some());

		// Create PRUNING_DEPTH + 2 receipt, best_execution_chain_number is PRUNING_DEPTH + 1.
		let block_hash = Hash::random();
		write_receipt_at(
			block_hash,
			PRUNING_DEPTH + 2,
			&create_execution_receipt(PRUNING_DEPTH + 2),
		);
		assert!(receipt_at(block_hash).is_some());

		// ER of block #1 should be pruned.
		assert!(receipt_at(block_hash_list[0]).is_none());
		// block number mapping should be pruned as well.
		assert!(hashes_at(1).is_none());
		assert!(target_receipt_is_pruned(PRUNING_DEPTH + 1, 1));
		assert_eq!(receipt_start(), Some(2));

		// Create PRUNING_DEPTH + 3 receipt, best_execution_chain_number is PRUNING_DEPTH + 2.
		let block_hash = Hash::random();
		write_receipt_at(
			block_hash,
			PRUNING_DEPTH + 3,
			&create_execution_receipt(PRUNING_DEPTH + 3),
		);
		assert!(receipt_at(block_hash).is_some());
		// ER of block #2 should be pruned.
		assert!(receipt_at(block_hash_list[1]).is_none());
		assert!(target_receipt_is_pruned(PRUNING_DEPTH + 2, 2));
		assert!(!target_receipt_is_pruned(PRUNING_DEPTH + 2, 3));
		assert_eq!(receipt_start(), Some(3));

		// Multiple hashes attached to the block #(PRUNING_DEPTH + 3)
		let block_hash2 = Hash::random();
		write_receipt_at(
			block_hash2,
			PRUNING_DEPTH + 3,
			&create_execution_receipt(PRUNING_DEPTH + 3),
		);
		assert!(receipt_at(block_hash2).is_some());
		assert_eq!(hashes_at(PRUNING_DEPTH + 3), Some(vec![block_hash, block_hash2]));
	}

	#[test]
	fn execution_receipts_should_be_kept_against_best_execution_chain_number() {
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

		let receipt_at = |block_hash: Hash| load_execution_receipt(&client, block_hash).unwrap();

		let write_receipt_at = |(hash, number): (Hash, BlockNumber),
		                        best_execution_chain_number: BlockNumber,
		                        receipt: &ExecutionReceipt| {
			write_execution_receipt::<_, Block, PBlock>(
				&client,
				(hash, number),
				best_execution_chain_number,
				receipt,
			)
			.unwrap()
		};

		assert_eq!(receipt_start(), None);

		// Create PRUNING_DEPTH receipts, best_execution_chain_number is 0, i.e., no receipt
		// has ever been included on primary chain.
		let block_hash_list = (1..=PRUNING_DEPTH)
			.map(|block_number| {
				let receipt = create_execution_receipt(block_number);
				let block_hash = Hash::random();
				write_receipt_at((block_hash, block_number), 0, &receipt);
				assert_eq!(receipt_at(block_hash), Some(receipt));
				assert_eq!(hashes_at(block_number), Some(vec![block_hash]));
				assert_eq!(receipt_start(), Some(1));
				block_hash
			})
			.collect::<Vec<_>>();

		assert!(!target_receipt_is_pruned(PRUNING_DEPTH, 1));

		// Create PRUNING_DEPTH + 1 receipt, best_execution_chain_number is 0.
		let block_hash = Hash::random();
		assert!(receipt_at(block_hash).is_none());
		write_receipt_at(
			(block_hash, PRUNING_DEPTH + 1),
			0,
			&create_execution_receipt(PRUNING_DEPTH + 1),
		);

		// Create PRUNING_DEPTH + 2 receipt, best_execution_chain_number is 0.
		let block_hash = Hash::random();
		write_receipt_at(
			(block_hash, PRUNING_DEPTH + 2),
			0,
			&create_execution_receipt(PRUNING_DEPTH + 2),
		);

		// ER of block #1 should not be pruned even the size of stored receipts exceeds the pruning depth.
		assert!(receipt_at(block_hash_list[0]).is_some());
		// block number mapping for #1 should not be pruned neither.
		assert!(hashes_at(1).is_some());
		assert!(!target_receipt_is_pruned(0, 1));
		assert_eq!(receipt_start(), Some(1));

		// Create PRUNING_DEPTH + 3 receipt, best_execution_chain_number is 0.
		let block_hash = Hash::random();
		write_receipt_at(
			(block_hash, PRUNING_DEPTH + 3),
			0,
			&create_execution_receipt(PRUNING_DEPTH + 3),
		);

		// Create PRUNING_DEPTH + 3 receipt, best_execution_chain_number is PRUNING_DEPTH + 3.
		let block_hash = Hash::random();
		write_receipt_at(
			(block_hash, PRUNING_DEPTH + 4),
			PRUNING_DEPTH + 3, // Now assuming all the missing receipts are included.
			&create_execution_receipt(PRUNING_DEPTH + 4),
		);
		assert!(receipt_at(block_hash_list[0]).is_none());
		// receipt and block number mapping for [1, 2, 3] should be pruned.
		(1..=3).for_each(|pruned| {
			assert!(hashes_at(pruned).is_none());
			assert!(target_receipt_is_pruned(PRUNING_DEPTH + 3, pruned));
		});
		assert_eq!(receipt_start(), Some(4));
	}
}

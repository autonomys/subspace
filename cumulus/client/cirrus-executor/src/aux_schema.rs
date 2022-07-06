//! Schema for executor in the aux-db.

use codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, Result as ClientResult};
use sp_core::H256;
use sp_executor::ExecutionReceipt;
use sp_runtime::traits::{Block as BlockT, NumberFor, One, SaturatedConversion};
use subspace_core_primitives::BlockNumber;

const EXECUTION_RECEIPT: &[u8] = b"execution_receipt";
const EXECUTION_RECEIPT_START: &[u8] = b"execution_receipt_start";
const EXECUTION_RECEIPT_BLOCK_NUMBER: &[u8] = b"execution_receipt_block_number";

/// bad_receipt_block_number => all_bad_signed_receipt_hashes_at_this_block
const BAD_SIGNED_RECEIPT_HASHES: &[u8] = b"bad_signed_receipt_hashes";

/// bad_signed_receipt_hash => trace_mismatch_index
const BAD_RECEIPT_MISMATCH_INDEX: &[u8] = b"bad_receipt_mismatch_index";

/// Set of block numbers at which there is at least one bad receipt detected.
///
/// NOTE: Unbounded but the size is not expected to be large.
const BAD_RECEIPT_NUMBERS: &[u8] = b"bad_receipt_numbers";

/// Prune the execution receipts when they reach this number.
const PRUNING_DEPTH: BlockNumber = 1000;

fn execution_receipt_key(block_hash: impl Encode) -> Vec<u8> {
	(EXECUTION_RECEIPT, block_hash).encode()
}

fn bad_receipt_mismatch_index_key(signed_receipt_hash: impl Encode) -> Vec<u8> {
	(BAD_RECEIPT_MISMATCH_INDEX, signed_receipt_hash).encode()
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

	let mut keys_to_delete = vec![];

	if let Some(delete_receipts_to) = best_execution_chain_number
		.saturated_into::<BlockNumber>()
		.checked_sub(PRUNING_DEPTH)
	{
		new_first_saved_receipt = Into::<NumberFor<Block>>::into(delete_receipts_to) + One::one();
		for receipt_to_delete in first_saved_receipt.saturated_into()..=delete_receipts_to {
			let delete_block_number_key =
				(EXECUTION_RECEIPT_BLOCK_NUMBER, receipt_to_delete).encode();

			if let Some(hashes_to_delete) =
				load_decode::<_, Vec<Block::Hash>>(backend, delete_block_number_key.as_slice())?
			{
				keys_to_delete
					.extend(hashes_to_delete.into_iter().map(|h| (EXECUTION_RECEIPT, h).encode()));
				keys_to_delete.push(delete_block_number_key);
			}
		}
	}

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
	best_execution_chain_number.saturating_sub(target_block) >= PRUNING_DEPTH
}

/// Writes a bad execution receipt to aux storage.
///
/// Use `bad_signed_receipt_hash` instead of the hash of execution receipt as key to
/// avoid the potential collision that two dishonest executors produced an identical
/// invalid receipt even it's less likely.
pub(super) fn write_bad_receipt<Backend, PBlock>(
	backend: &Backend,
	bad_receipt_number: NumberFor<PBlock>,
	bad_signed_receipt_hash: H256,
	trace_mismatch_index: u32,
) -> Result<(), ClientError>
where
	Backend: AuxStore,
	PBlock: BlockT,
{
	let bad_signed_receipt_hashes_key = (BAD_SIGNED_RECEIPT_HASHES, bad_receipt_number).encode();
	let mut bad_signed_receipt_hashes: Vec<H256> =
		load_decode(backend, bad_signed_receipt_hashes_key.as_slice())?.unwrap_or_default();
	bad_signed_receipt_hashes.push(bad_signed_receipt_hash);

	let mut to_insert = vec![
		(bad_signed_receipt_hashes_key, bad_signed_receipt_hashes.encode()),
		(bad_receipt_mismatch_index_key(bad_signed_receipt_hash), trace_mismatch_index.encode()),
	];

	let mut bad_receipt_numbers: Vec<NumberFor<PBlock>> =
		load_decode(backend, BAD_RECEIPT_NUMBERS.encode().as_slice())?.unwrap_or_default();

	// The first bad receipt detected at this block number.
	if !bad_receipt_numbers.contains(&bad_receipt_number) {
		bad_receipt_numbers.push(bad_receipt_number);

		assert!(bad_receipt_numbers.is_sorted(), "Bad receipt numbers must be sorted");

		to_insert.push((BAD_RECEIPT_NUMBERS.encode(), bad_receipt_numbers.encode()));
	}

	backend.insert_aux(
		&to_insert.iter().map(|(k, v)| (&k[..], &v[..])).collect::<Vec<_>>()[..],
		vec![],
	)
}

pub(super) fn delete_bad_receipt<Backend: AuxStore>(
	backend: &Backend,
	block_number: BlockNumber,
	signed_receipt_hash: H256,
) -> Result<(), ClientError> {
	let bad_signed_receipt_hashes_key = (BAD_SIGNED_RECEIPT_HASHES, block_number).encode();
	let mut hashes_at_block_number: Vec<H256> =
		load_decode(backend, bad_signed_receipt_hashes_key.as_slice())?.unwrap_or_default();

	if let Some(index) = hashes_at_block_number.iter().position(|&x| x == signed_receipt_hash) {
		hashes_at_block_number.swap_remove(index);
	} else {
		return Err(ClientError::Backend(format!(
			"Deleting an inexistent bad receipt {signed_receipt_hash:?}, available: {hashes_at_block_number:?}"
		)))
	}

	let mut keys_to_delete = vec![bad_receipt_mismatch_index_key(signed_receipt_hash)];

	let to_insert = if hashes_at_block_number.is_empty() {
		keys_to_delete.push(bad_signed_receipt_hashes_key);

		let mut bad_receipt_numbers: Vec<BlockNumber> =
			load_decode(backend, BAD_RECEIPT_NUMBERS.encode().as_slice())?.ok_or_else(|| {
				ClientError::Backend("Stored bad receipt numbers must exist".into())
			})?;
		bad_receipt_numbers.retain(|x| *x != block_number);

		if bad_receipt_numbers.is_empty() {
			keys_to_delete.push(BAD_RECEIPT_NUMBERS.encode());

			vec![]
		} else {
			vec![(BAD_RECEIPT_NUMBERS.encode(), bad_receipt_numbers.encode())]
		}
	} else {
		vec![(bad_signed_receipt_hashes_key, hashes_at_block_number.encode())]
	};

	backend.insert_aux(
		&to_insert.iter().map(|(k, v)| (&k[..], &v[..])).collect::<Vec<_>>()[..],
		&keys_to_delete.iter().map(|k| &k[..]).collect::<Vec<_>>()[..],
	)
}

fn delete_expired_bad_receipt_info_at<Backend: AuxStore, Number: Encode>(
	backend: &Backend,
	block_number: Number,
) -> Result<(), sp_blockchain::Error> {
	let bad_signed_receipt_hashes_key = (BAD_SIGNED_RECEIPT_HASHES, block_number).encode();

	let bad_receipt_hashes: Vec<H256> =
		load_decode(backend, bad_signed_receipt_hashes_key.as_slice())?.unwrap_or_default();

	let keys_to_delete = bad_receipt_hashes
		.into_iter()
		.map(bad_receipt_mismatch_index_key)
		.chain(std::iter::once(bad_signed_receipt_hashes_key))
		.collect::<Vec<_>>();

	backend.insert_aux([], &keys_to_delete.iter().map(|k| &k[..]).collect::<Vec<_>>()[..])
}

/// Bad receipts which are older than `oldest_receipt_number` are expired and will be pruned.
pub(super) fn prune_expired_bad_receipts<Backend, Number>(
	backend: &Backend,
	oldest_receipt_number: Number,
) -> Result<(), ClientError>
where
	Backend: AuxStore,
	Number: Encode + Decode + Copy + std::fmt::Debug + Copy + PartialOrd,
{
	let mut bad_receipt_numbers: Vec<Number> =
		load_decode(backend, BAD_RECEIPT_NUMBERS.encode().as_slice())?.unwrap_or_default();

	let expired_receipt_numbers = bad_receipt_numbers
		.drain_filter(|number| *number < oldest_receipt_number)
		.collect::<Vec<_>>();

	if !expired_receipt_numbers.is_empty() {
		// The bad receipt had been pruned on primary chain, i.e., _finalized_.
		tracing::error!(
			target: crate::LOG_TARGET,
			?oldest_receipt_number,
			?expired_receipt_numbers,
			"Bad receipt(s) had been pruned on primary chain"
		);

		for expired_receipt_number in expired_receipt_numbers {
			if let Err(e) = delete_expired_bad_receipt_info_at(backend, expired_receipt_number) {
				tracing::error!(target: crate::LOG_TARGET, error = ?e, "Failed to remove the expired bad receipt");
			}
		}

		if bad_receipt_numbers.is_empty() {
			backend.insert_aux(&[], &[BAD_RECEIPT_NUMBERS.encode().as_slice()])?;
		} else {
			backend.insert_aux(
				&[(
					BAD_RECEIPT_NUMBERS.encode().as_slice(),
					bad_receipt_numbers.encode().as_slice(),
				)],
				&[],
			)?;
		}
	}

	Ok(())
}

/// Returns the first unconfirmed bad receipt info necessary for building a fraud proof if any.
pub(super) fn load_first_unconfirmed_bad_receipt_info<Backend, Number>(
	backend: &Backend,
) -> Result<Option<(Number, H256, u32)>, ClientError>
where
	Backend: AuxStore,
	Number: Encode + Decode + Copy + std::fmt::Debug,
{
	let bad_receipt_numbers: Vec<Number> =
		load_decode(backend, BAD_RECEIPT_NUMBERS.encode().as_slice())?.unwrap_or_default();

	if let Some(bad_receipt_number) = bad_receipt_numbers.get(0).copied() {
		let bad_signed_receipt_hashes_key =
			(BAD_SIGNED_RECEIPT_HASHES, bad_receipt_number).encode();
		let bad_signed_receipt_hashes: Vec<H256> =
			load_decode(backend, bad_signed_receipt_hashes_key.as_slice())?.unwrap_or_default();

		let first_bad_signed_receipt_hash =
			bad_signed_receipt_hashes.get(0).copied().ok_or_else(|| {
				ClientError::Backend(format!(
					"No bad signed receipt hashes found for block {bad_receipt_number:?}"
				))
			})?;

		let trace_mismatch_index = load_decode(
			backend,
			bad_receipt_mismatch_index_key(first_bad_signed_receipt_hash).as_slice(),
		)?
		.ok_or_else(|| {
			ClientError::Backend(format!(
						"Trace mismatch index not found, `bad_signed_receipt_hash`: {first_bad_signed_receipt_hash:?}"
					))
		})?;

		Ok(Some((bad_receipt_number, first_bad_signed_receipt_hash, trace_mismatch_index)))
	} else {
		Ok(None)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use cirrus_test_service::runtime::Block;
	use sp_core::hash::H256;
	use std::collections::HashSet;
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

		// Create PRUNING_DEPTH + 4 receipt, best_execution_chain_number is PRUNING_DEPTH + 3.
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

	#[test]
	fn write_delete_prune_bad_receipt_works() {
		let client = substrate_test_runtime_client::new();

		let bad_receipts_at = |number: BlockNumber| -> Option<HashSet<Hash>> {
			let bad_signed_receipt_hashes_key = (BAD_SIGNED_RECEIPT_HASHES, number).encode();
			load_decode(&client, bad_signed_receipt_hashes_key.as_slice())
				.unwrap()
				.map(|v: Vec<Hash>| v.into_iter().collect())
		};

		let trace_mismatch_index_for = |receipt_hash| -> Option<u32> {
			load_decode(&client, bad_receipt_mismatch_index_key(receipt_hash).as_slice()).unwrap()
		};

		let bad_receipt_numbers = || -> Option<Vec<BlockNumber>> {
			load_decode(&client, BAD_RECEIPT_NUMBERS.encode().as_slice()).unwrap()
		};

		let first_unconfirmed_bad_receipt_info = |oldest_receipt_number: BlockNumber| {
			// Always check and prune the expired bad receipts before loading the first unconfirmed one.
			prune_expired_bad_receipts(&client, oldest_receipt_number).unwrap();
			load_first_unconfirmed_bad_receipt_info::<_, BlockNumber>(&client)
		};

		let bad_receipt_hash1 = Hash::random();
		let bad_receipt_hash2 = Hash::random();
		let bad_receipt_hash3 = Hash::random();
		write_bad_receipt::<_, PBlock>(&client, 10, bad_receipt_hash1, 1).unwrap();
		assert_eq!(bad_receipt_numbers(), Some(vec![10]));
		write_bad_receipt::<_, PBlock>(&client, 10, bad_receipt_hash2, 2).unwrap();
		assert_eq!(bad_receipt_numbers(), Some(vec![10]));
		write_bad_receipt::<_, PBlock>(&client, 10, bad_receipt_hash3, 3).unwrap();
		assert_eq!(bad_receipt_numbers(), Some(vec![10]));

		let bad_receipt_hash4 = Hash::random();
		write_bad_receipt::<_, PBlock>(&client, 20, bad_receipt_hash4, 1).unwrap();
		assert_eq!(bad_receipt_numbers(), Some(vec![10, 20]));

		assert_eq!(trace_mismatch_index_for(bad_receipt_hash1).unwrap(), 1);
		assert_eq!(trace_mismatch_index_for(bad_receipt_hash2).unwrap(), 2);
		assert_eq!(trace_mismatch_index_for(bad_receipt_hash3).unwrap(), 3);
		assert_eq!(
			first_unconfirmed_bad_receipt_info(1).unwrap(),
			Some((10, bad_receipt_hash1, 1))
		);

		assert_eq!(
			bad_receipts_at(10).unwrap(),
			[bad_receipt_hash1, bad_receipt_hash2, bad_receipt_hash3].into(),
		);
		assert_eq!(bad_receipts_at(20).unwrap(), [bad_receipt_hash4].into());

		assert!(delete_bad_receipt(&client, 10, bad_receipt_hash1).is_ok());
		assert_eq!(bad_receipt_numbers(), Some(vec![10, 20]));
		assert!(trace_mismatch_index_for(bad_receipt_hash1).is_none());
		assert_eq!(bad_receipts_at(10).unwrap(), [bad_receipt_hash2, bad_receipt_hash3].into());

		assert!(delete_bad_receipt(&client, 10, bad_receipt_hash2).is_ok());
		assert_eq!(bad_receipt_numbers(), Some(vec![10, 20]));
		assert!(trace_mismatch_index_for(bad_receipt_hash2).is_none());
		assert_eq!(bad_receipts_at(10).unwrap(), [bad_receipt_hash3].into());

		assert!(delete_bad_receipt(&client, 10, bad_receipt_hash3).is_ok());
		assert_eq!(bad_receipt_numbers(), Some(vec![20]));
		assert!(trace_mismatch_index_for(bad_receipt_hash3).is_none());
		assert!(bad_receipts_at(10).is_none());
		assert_eq!(
			first_unconfirmed_bad_receipt_info(1).unwrap(),
			Some((20, bad_receipt_hash4, 1))
		);

		assert!(delete_bad_receipt(&client, 20, bad_receipt_hash4).is_ok());
		assert_eq!(first_unconfirmed_bad_receipt_info(20).unwrap(), None);

		let bad_receipt_hash5 = Hash::random();
		write_bad_receipt::<_, PBlock>(&client, 30, bad_receipt_hash5, 1).unwrap();
		assert_eq!(bad_receipt_numbers(), Some(vec![30]));
		assert_eq!(bad_receipts_at(30).unwrap(), [bad_receipt_hash5].into());
		// Expired bad receipts will be removed.
		assert_eq!(first_unconfirmed_bad_receipt_info(31).unwrap(), None);
		assert_eq!(bad_receipt_numbers(), None);
		assert!(bad_receipts_at(30).is_none());
	}
}

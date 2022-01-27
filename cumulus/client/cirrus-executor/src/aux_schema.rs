//! Schema for executor in the aux-db.

use codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, Result as ClientResult};
use sp_executor::ExecutionReceipt;
use sp_runtime::traits::Block as BlockT;

const EXECUTION_RECEIPT_KEY: &[u8] = b"execution_receipt";

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

/// Write the execution receipt of a block to aux storage.
pub(super) fn write_execution_receipt<Backend: AuxStore, Block: BlockT>(
	backend: &Backend,
	block_hash: Block::Hash,
	execution_receipt: &ExecutionReceipt<Block::Hash>,
) -> Result<(), sp_blockchain::Error> {
	let key = (EXECUTION_RECEIPT_KEY, block_hash).encode();
	backend.insert_aux(&[(key.as_slice(), execution_receipt.encode().as_slice())], [])
}

/// Load the execution receipt associated with a block.
pub(super) fn load_execution_receipt<Backend: AuxStore, Block: BlockT>(
	backend: &Backend,
	block_hash: Block::Hash,
) -> ClientResult<Option<ExecutionReceipt<Block::Hash>>> {
	load_decode(backend, (EXECUTION_RECEIPT_KEY, block_hash).encode().as_slice())
}

/// Remove the validated execution receipt.
pub(super) fn delete_execution_receipt<Backend: AuxStore, Block: BlockT>(
	backend: &Backend,
	block_hash: Block::Hash,
) -> Result<(), sp_blockchain::Error> {
	let key = (EXECUTION_RECEIPT_KEY, block_hash).encode();
	backend.insert_aux([], &[(key.as_slice())])
}

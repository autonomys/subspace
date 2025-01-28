//! Schema for Subspace block weight in the aux-db.

use codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, Result as ClientResult};
use subspace_core_primitives::BlockWeight;

fn load_decode<B, T>(backend: &B, key: &[u8]) -> ClientResult<Option<T>>
where
    B: AuxStore,
    T: Decode,
{
    match backend.get_aux(key)? {
        Some(t) => T::decode(&mut &t[..]).map(Some).map_err(|e: codec::Error| {
            ClientError::Backend(format!("Subspace DB is corrupted. Decode error: {e}"))
        }),
        None => Ok(None),
    }
}

/// The aux storage key used to store the block weight of the given block hash.
fn block_weight_key<H: Encode>(block_hash: H) -> Vec<u8> {
    (b"block_weight", block_hash).encode()
}

/// Write the cumulative chain-weight of a block to aux storage.
pub(crate) fn write_block_weight<H, F, R>(
    block_hash: H,
    block_weight: BlockWeight,
    write_aux: F,
) -> R
where
    H: Encode,
    F: FnOnce(&[(Vec<u8>, &[u8])]) -> R,
{
    let key = block_weight_key(block_hash);
    block_weight.using_encoded(|s| write_aux(&[(key, s)]))
}

/// Load the cumulative chain-weight associated with a block.
pub(crate) fn load_block_weight<H: Encode, B: AuxStore>(
    backend: &B,
    block_hash: H,
) -> ClientResult<Option<BlockWeight>> {
    load_decode(backend, block_weight_key(block_hash).as_slice())
}

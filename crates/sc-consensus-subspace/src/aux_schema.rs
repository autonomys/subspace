// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Schema for Subspace block weight in the aux-db.

use codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, Result as ClientResult};
use subspace_core_primitives::{BlockWeight, RecordsRoot, SegmentIndex};

fn load_decode<B, T>(backend: &B, key: &[u8]) -> ClientResult<Option<T>>
where
    B: AuxStore,
    T: Decode,
{
    match backend.get_aux(key)? {
        Some(t) => T::decode(&mut &t[..]).map(Some).map_err(|e: codec::Error| {
            ClientError::Backend(format!("Subspace DB is corrupted. Decode error: {}", e))
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

/// The aux storage key used to store the records root of the given segment.
fn records_root_key(segment_index: SegmentIndex) -> Vec<u8> {
    (b"records_root", segment_index).encode()
}

/// Write the cumulative records root of a segment to aux storage.
pub(crate) fn write_records_root<F, R>(
    segment_index: SegmentIndex,
    records_root: &RecordsRoot,
    write_aux: F,
) -> R
where
    F: FnOnce(&[(Vec<u8>, &[u8])]) -> R,
{
    let key = records_root_key(segment_index);
    records_root.using_encoded(|s| write_aux(&[(key, s)]))
}

/// Load the cumulative chain-weight associated with a block.
pub(crate) fn load_records_root<B: AuxStore>(
    backend: &B,
    segment_index: SegmentIndex,
) -> ClientResult<Option<RecordsRoot>> {
    load_decode(backend, records_root_key(segment_index).as_slice())
}

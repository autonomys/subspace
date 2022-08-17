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
use sp_consensus_slots::Slot;
use sp_consensus_subspace::ChainConstants;
use subspace_core_primitives::{
    BlockWeight, EonIndex, Randomness, RecordsRoot, SegmentIndex, SolutionRange,
};

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

/// The aux storage key used to store the chain constants.
fn chain_constants_key() -> Vec<u8> {
    b"chain_constants".encode()
}

/// Write chain constants to aux storage.
pub(crate) fn write_chain_constants<F, R>(chain_constants: &ChainConstants, write_aux: F) -> R
where
    F: FnOnce(&[(Vec<u8>, &[u8])]) -> R,
{
    let key = chain_constants_key();
    chain_constants.using_encoded(|s| write_aux(&[(key, s)]))
}

/// Load chain constants.
pub(crate) fn load_chain_constants<Backend>(
    backend: &Backend,
) -> ClientResult<Option<ChainConstants>>
where
    Backend: AuxStore,
{
    load_decode(backend, chain_constants_key().as_slice())
}

/// The aux storage key used to store genesis slot.
fn genesis_slot_key() -> Vec<u8> {
    b"genesis_slot".encode()
}

/// Write genesis slot to aux storage.
pub(crate) fn write_genesis_slot<F, R>(genesis_slot: Slot, write_aux: F) -> R
where
    F: FnOnce(&[(Vec<u8>, &[u8])]) -> R,
{
    let key = genesis_slot_key();
    genesis_slot.using_encoded(|s| write_aux(&[(key, s)]))
}

/// Load genesis slot.
pub(crate) fn load_genesis_slot<Backend>(backend: &Backend) -> ClientResult<Option<Slot>>
where
    Backend: AuxStore,
{
    load_decode(backend, genesis_slot_key().as_slice())
}

/// The aux storage key used to store era start slots corresponding to specified era index.
fn era_start_slot_key<EraIndex>(era_index: EraIndex) -> Vec<u8>
where
    EraIndex: Encode,
{
    (b"era_start_slot", era_index).encode()
}

/// Write era start slots corresponding to specified era index to aux storage.
///
/// If `era_start_slot` is empty, corresponding data is removed from auxiliary storage.
pub(crate) fn write_era_start_slot<EraIndex, BlockHash, F, R>(
    era_index: EraIndex,
    era_start_slot: &[(BlockHash, Slot)],
    write_aux: F,
) -> R
where
    EraIndex: Encode,
    BlockHash: Encode,
    F: FnOnce(&[(Vec<u8>, Option<&[u8]>)]) -> R,
{
    let key = era_start_slot_key(era_index);
    if era_start_slot.is_empty() {
        write_aux(&[(key, None)])
    } else {
        era_start_slot.using_encoded(|s| write_aux(&[(key, Some(s))]))
    }
}

/// Load era start slots corresponding to specified era index.
pub(crate) fn load_era_start_slot<EraIndex, BlockHash, Backend>(
    backend: &Backend,
    era_index: EraIndex,
) -> ClientResult<Option<Vec<(BlockHash, Slot)>>>
where
    EraIndex: Encode,
    BlockHash: Decode,
    Backend: AuxStore,
{
    load_decode(backend, era_start_slot_key(era_index).as_slice())
}

/// The aux storage key used to store eon indexes.
fn eon_indexes_key() -> Vec<u8> {
    b"eon_indexes".encode()
}

#[derive(Debug, Copy, Clone, Encode, Decode)]
pub(super) struct EonIndexEntry<BlockNumber, BlockHash>
where
    BlockNumber: Copy + Encode + Decode,
    BlockHash: Copy + Encode + Decode,
{
    pub(super) eon_index: EonIndex,
    pub(super) randomness: Randomness,
    pub(super) randomness_block: (BlockNumber, BlockHash),
    pub(super) starts_at: (Slot, BlockNumber),
}

/// Write eon indexes to aux storage.
pub(crate) fn write_eon_indexes<BlockNumber, BlockHash, F, R>(
    eon_indexes: &[EonIndexEntry<BlockNumber, BlockHash>],
    write_aux: F,
) -> R
where
    BlockNumber: Copy + Encode + Decode,
    BlockHash: Copy + Encode + Decode,
    F: FnOnce(&[(Vec<u8>, &[u8])]) -> R,
{
    let key = eon_indexes_key();
    eon_indexes.using_encoded(|s| write_aux(&[(key, s)]))
}

/// Load eon indexes.
pub(crate) fn load_eon_indexes<BlockNumber, BlockHash, Backend>(
    backend: &Backend,
) -> ClientResult<Option<Vec<EonIndexEntry<BlockNumber, BlockHash>>>>
where
    BlockNumber: Copy + Encode + Decode,
    BlockHash: Copy + Encode + Decode,
    Backend: AuxStore,
{
    load_decode(backend, eon_indexes_key().as_slice())
}

/// The aux storage key used to store next eon randomness.
fn next_eon_randomness_key(eon_index: EonIndex) -> Vec<u8> {
    (b"next_eon_randomness", eon_index).encode()
}

/// Write eon indexes to aux storage.
///
/// If `next_eon_randomness` is empty, corresponding data is removed from auxiliary storage.
pub(crate) fn write_next_eon_randomness<BlockNumber, BlockHash, F, R>(
    eon_index: EonIndex,
    next_eon_randomness: &[(BlockNumber, BlockHash, Randomness)],
    write_aux: F,
) -> R
where
    BlockNumber: Encode,
    BlockHash: Encode,
    F: FnOnce(&[(Vec<u8>, Option<&[u8]>)]) -> R,
{
    let key = next_eon_randomness_key(eon_index);
    if next_eon_randomness.is_empty() {
        write_aux(&[(key, None)])
    } else {
        next_eon_randomness.using_encoded(|s| write_aux(&[(key, Some(s))]))
    }
}

/// Load next eon randomness.
pub(crate) fn load_next_eon_randomness<BlockNumber, BlockHash, Backend>(
    backend: &Backend,
    eon_index: EonIndex,
) -> ClientResult<Option<Vec<(BlockNumber, BlockHash, Randomness)>>>
where
    BlockNumber: Decode,
    BlockHash: Decode,
    Backend: AuxStore,
{
    load_decode(backend, next_eon_randomness_key(eon_index).as_slice())
}

#[derive(Debug, Copy, Clone, Encode, Decode, Eq, PartialEq)]
pub(super) struct SolutionRangeParameters {
    pub(super) should_adjust: bool,
    pub(super) next_override: Option<SolutionRange>,
}

/// The aux storage key used to store solution range parameters.
fn solution_range_parameters_key() -> Vec<u8> {
    b"solution_range_parameters".encode()
}

/// Write solution range parameters to aux storage.
pub(crate) fn write_solution_range_parameters<F, R>(
    solution_range_parameters: &SolutionRangeParameters,
    write_aux: F,
) -> R
where
    F: FnOnce(&[(Vec<u8>, &[u8])]) -> R,
{
    let key = solution_range_parameters_key();
    solution_range_parameters.using_encoded(|s| write_aux(&[(key, s)]))
}

/// Load solution range parameters.
pub(crate) fn load_solution_range_parameters<Backend>(
    backend: &Backend,
) -> ClientResult<Option<SolutionRangeParameters>>
where
    Backend: AuxStore,
{
    load_decode(backend, solution_range_parameters_key().as_slice())
}

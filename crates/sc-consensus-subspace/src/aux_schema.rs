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

//! Schema for PoC epoch changes in the aux-db.

use codec::{Decode, Encode};
use log::info;

use crate::Epoch;
use sc_client_api::backend::AuxStore;
use sc_consensus_epochs::{EpochChangesFor, SharedEpochChanges};
use sp_blockchain::{Error as ClientError, Result as ClientResult};
use sp_consensus_subspace::{PoCBlockWeight, PoCGenesisConfiguration};
use sp_runtime::traits::Block as BlockT;

const POC_EPOCH_CHANGES_VERSION: &[u8] = b"poc_epoch_changes_version";
const POC_EPOCH_CHANGES_KEY: &[u8] = b"poc_epoch_changes";
const POC_EPOCH_CHANGES_CURRENT_VERSION: u32 = 1;

/// The aux storage key used to store the block weight of the given block hash.
fn block_weight_key<H: Encode>(block_hash: H) -> Vec<u8> {
    (b"block_weight", block_hash).encode()
}

fn load_decode<B, T>(backend: &B, key: &[u8]) -> ClientResult<Option<T>>
where
    B: AuxStore,
    T: Decode,
{
    let corrupt =
        |e: codec::Error| ClientError::Backend(format!("PoC DB is corrupted. Decode error: {}", e));
    match backend.get_aux(key)? {
        None => Ok(None),
        Some(t) => T::decode(&mut &t[..]).map(Some).map_err(corrupt),
    }
}

/// Load or initialize persistent epoch change data from backend.
pub fn load_epoch_changes<Block: BlockT, B: AuxStore>(
    backend: &B,
    _config: &PoCGenesisConfiguration,
) -> ClientResult<SharedEpochChanges<Block, Epoch>> {
    let version = load_decode::<_, u32>(backend, POC_EPOCH_CHANGES_VERSION)?;

    let maybe_epoch_changes = match version {
        Some(POC_EPOCH_CHANGES_CURRENT_VERSION) => {
            load_decode::<_, EpochChangesFor<Block, Epoch>>(backend, POC_EPOCH_CHANGES_KEY)?
        }
        Some(other) => {
            return Err(ClientError::Backend(format!(
                "Unsupported PoC DB version: {:?}",
                other
            )))
        }
        None => None,
    };

    let epoch_changes =
        SharedEpochChanges::<Block, Epoch>::new(maybe_epoch_changes.unwrap_or_else(|| {
            info!(
                target: "poc",
                "🧑‍🌾 Creating empty PoC epoch changes on what appears to be first startup.",
            );
            EpochChangesFor::<Block, Epoch>::default()
        }));

    // rebalance the tree after deserialization. this isn't strictly necessary
    // since the tree is now rebalanced on every update operation. but since the
    // tree wasn't rebalanced initially it's useful to temporarily leave it here
    // to avoid having to wait until an import for rebalancing.
    epoch_changes.shared_data().rebalance();

    Ok(epoch_changes)
}

/// Update the epoch changes on disk after a change.
pub(crate) fn write_epoch_changes<Block: BlockT, F, R>(
    epoch_changes: &EpochChangesFor<Block, Epoch>,
    write_aux: F,
) -> R
where
    F: FnOnce(&[(&'static [u8], &[u8])]) -> R,
{
    POC_EPOCH_CHANGES_CURRENT_VERSION.using_encoded(|version| {
        let encoded_epoch_changes = epoch_changes.encode();
        write_aux(&[
            (POC_EPOCH_CHANGES_KEY, encoded_epoch_changes.as_slice()),
            (POC_EPOCH_CHANGES_VERSION, version),
        ])
    })
}

/// Write the cumulative chain-weight of a block ot aux storage.
pub(crate) fn write_block_weight<H: Encode, F, R>(
    block_hash: H,
    block_weight: PoCBlockWeight,
    write_aux: F,
) -> R
where
    F: FnOnce(&[(Vec<u8>, &[u8])]) -> R,
{
    let key = block_weight_key(block_hash);
    block_weight.using_encoded(|s| write_aux(&[(key, s)]))
}

/// Load the cumulative chain-weight associated with a block.
pub fn load_block_weight<H: Encode, B: AuxStore>(
    backend: &B,
    block_hash: H,
) -> ClientResult<Option<PoCBlockWeight>> {
    load_decode(backend, block_weight_key(block_hash).as_slice())
}

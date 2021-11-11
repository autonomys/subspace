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

use super::*;

type EpochData<B> = ViableEpochDescriptor<<B as BlockT>::Hash, NumberFor<B>, Epoch>;

type Claim = (PreDigest, Pair);

/// Extract the next Subspace solution range digest from the given header if it exists.
fn find_next_solution_range_digest<B: BlockT>(
    header: &B::Header,
) -> Result<Option<NextSolutionRangeDescriptor>, Error<B>>
where
    DigestItemFor<B>: CompatibleDigestItem,
{
    let mut next_solution_range_digest: Option<_> = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for next solution range digest.", log);
        let log = log.try_to::<ConsensusLog>(OpaqueDigestItemId::Consensus(&SUBSPACE_ENGINE_ID));
        match (log, next_solution_range_digest.is_some()) {
            (Some(ConsensusLog::NextSolutionRangeData(_)), true) => {
                return Err(subspace_err(Error::MultipleNextSolutionRangeDigests))
            }
            (Some(ConsensusLog::NextSolutionRangeData(solution_range)), false) => {
                next_solution_range_digest = Some(solution_range)
            }
            _ => trace!(target: "subspace", "Ignoring digest not meant for us"),
        }
    }

    Ok(next_solution_range_digest)
}

/// Extract the next Subspace salt digest from the given header if it exists.
fn find_next_salt_digest<B: BlockT>(
    header: &B::Header,
) -> Result<Option<NextSaltDescriptor>, Error<B>>
where
    DigestItemFor<B>: CompatibleDigestItem,
{
    let mut next_salt_digest: Option<_> = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for salt digest.", log);
        let log = log.try_to::<ConsensusLog>(OpaqueDigestItemId::Consensus(&SUBSPACE_ENGINE_ID));
        match (log, next_salt_digest.is_some()) {
            (Some(ConsensusLog::NextSaltData(_)), true) => {
                return Err(subspace_err(Error::MultipleSaltDigests))
            }
            (Some(ConsensusLog::NextSaltData(salt)), false) => next_salt_digest = Some(salt),
            _ => trace!(target: "subspace", "Ignoring digest not meant for us"),
        }
    }

    Ok(next_salt_digest)
}

struct NewSlotPuzzle<B: BlockT> {
    block_id: BlockId<B>,
    salt: Salt,
    solution_range: u64,
    epoch_randomness: Randomness,
}

impl<B, C, E, I, Error, SO, L, BS> SubspaceSlotWorker<B, C, E, I, SO, L, BS>
where
    B: BlockT,
    C: ProvideRuntimeApi<B>
        + ProvideCache<B>
        + HeaderBackend<B>
        + HeaderMetadata<B, Error = ClientError>
        + 'static,
    C::Api: SubspaceApi<B>,
    E: Environment<B, Error = Error> + Send + Sync,
    E::Proposer: Proposer<B, Error = Error, Transaction = sp_api::TransactionFor<C, B>>,
    I: BlockImport<B, Transaction = sp_api::TransactionFor<C, B>> + Send + Sync + 'static,
    SO: SyncOracle + Send + Sync + Clone,
    L: sc_consensus::JustificationSyncLink<B>,
    BS: BackoffAuthoringBlocksStrategy<NumberFor<B>> + Send + Sync,
    Error: Send + From<ConsensusError> + From<I::Error> + 'static,
{
    /// Actually implements [`SimpleSlotWorker::claim_slot`] for [`SubspaceSlotWorker`].
    pub(crate) async fn claim_slot_impl(
        &self,
        parent_header: &B::Header,
        slot: Slot,
        epoch_descriptor: &EpochData<B>,
    ) -> Option<Claim> {
        debug!(target: "subspace", "Attempting to claim slot {}", slot);

        let (new_slot_puzzle, new_slot_info) =
            self.prepare_new_slot(parent_header, slot, epoch_descriptor)?;

        // Notify the outside farmers about the new slot.
        let (solution_sender, mut solution_receiver) =
            tracing_unbounded("subspace_slot_solution_stream");

        self.subspace_link
            .new_slot_notification_sender
            .notify(|| NewSlotNotification {
                new_slot_info,
                solution_sender,
            });

        // Wait until a valid solution from some farmer arrives.
        while let Some((solution, secret_key)) = solution_receiver.next().await {
            let NewSlotPuzzle {
                block_id,
                solution_range,
                epoch_randomness,
                salt,
            } = new_slot_puzzle;

            let parent_block_id = BlockId::Hash(parent_header.hash());

            // TODO: We need also need to check for equivocation of farmers connected to *this node*
            //  during block import, currently farmers connected to this node are considered trusted
            if self
                .client
                .runtime_api()
                .is_in_block_list(&block_id, &solution.public_key)
                .ok()?
            {
                warn!(
                    target: "subspace",
                    "Ignoring solution for slot {} provided by farmer in block list: {}",
                    slot,
                    solution.public_key,
                );

                continue;
            }

            let record_size = self
                .client
                .runtime_api()
                .record_size(&parent_block_id)
                .ok()?;
            let recorded_history_segment_size = self
                .client
                .runtime_api()
                .recorded_history_segment_size(&parent_block_id)
                .ok()?;
            let merkle_num_leaves = u64::from(recorded_history_segment_size / record_size * 2);
            let segment_index = solution.piece_index / merkle_num_leaves;
            let position = solution.piece_index % merkle_num_leaves;

            let maybe_records_root = self.records_root_for(parent_header, segment_index);
            let records_root = match maybe_records_root {
                Some(records_root) => records_root,
                None => {
                    warn!(
                        target: "subspace",
                        "Records root for segment index {} not found (slot {})",
                        segment_index,
                        slot,
                    );
                    continue;
                }
            };

            match verification::verify_solution::<B>(
                &solution,
                verification::VerifySolutionParams {
                    epoch_randomness: &epoch_randomness,
                    solution_range,
                    slot,
                    salt,
                    records_root: &records_root,
                    position,
                    record_size,
                    signing_context: &self.signing_context,
                },
            ) {
                Ok(_) => {
                    debug!(target: "subspace", "Claimed slot {}", slot);
                    let secret_key = SecretKey::from_bytes(&secret_key).ok()?;
                    return Some((PreDigest { solution, slot }, secret_key.into()));
                }
                Err(error) => {
                    warn!(target: "subspace", "Invalid solution received for slot {}: {:?}", slot, error);
                }
            }
        }

        None
    }

    /// Returns all the data required for the farmers to claim next slot.
    fn prepare_new_slot(
        &self,
        parent_header: &B::Header,
        slot: Slot,
        epoch_descriptor: &EpochData<B>,
    ) -> Option<(NewSlotPuzzle<B>, NewSlotInfo)> {
        let epoch_randomness = self.next_epoch_randomness(epoch_descriptor)?;
        let solution_range = self.next_solution_range(parent_header)?;
        let salt = self.next_salt(parent_header)?;

        let new_slot_puzzle = NewSlotPuzzle {
            block_id: BlockId::Hash(parent_header.hash()),
            salt: salt.to_le_bytes(),
            solution_range,
            epoch_randomness,
        };

        let new_slot_info = NewSlotInfo {
            slot,
            global_challenge: subspace_solving::derive_global_challenge(&epoch_randomness, slot),
            salt: salt.to_le_bytes(),
            // TODO: This will not be the correct way in the future once salt is no longer
            //  just an incremented number
            next_salt: Some((salt + 1).to_le_bytes()),
            solution_range,
        };

        Some((new_slot_puzzle, new_slot_info))
    }

    /// Epoch randomness for the new slot.
    fn next_epoch_randomness(&self, epoch_descriptor: &EpochData<B>) -> Option<Randomness> {
        let epoch_changes = self.subspace_link.epoch_changes.shared_data();
        let epoch = epoch_changes.viable_epoch(epoch_descriptor, |slot| {
            Epoch::genesis(&self.subspace_link.config, slot)
        })?;
        Some(epoch.as_ref().randomness)
    }

    /// Solution range for the new slot.
    fn next_solution_range(&self, parent_header: &B::Header) -> Option<u64> {
        // Here we always use parent block as the source of information, thus on the edge of the
        // era the very first block of the era still uses solution range from the previous one,
        // but the block after it uses "next" solution range deposited in the first block.
        find_next_solution_range_digest::<B>(parent_header)
            .ok()?
            .map(|d| d.solution_range)
            .or_else(|| {
                // We use runtime API as it will fallback to default value for genesis when
                // there is no solution range stored yet
                self.client
                    .runtime_api()
                    .solution_range(&BlockId::Hash(parent_header.hash()))
                    .ok()
            })
    }

    /// Salt for the new slot.
    fn next_salt(&self, parent_header: &B::Header) -> Option<u64> {
        // Here we always use parent block as the source of information, thus on the edge of the
        // eon the very first block of the eon still uses salt from the previous one, but the
        // block after it uses "next" salt deposited in the first block.
        find_next_salt_digest::<B>(parent_header)
            .ok()?
            .map(|d| d.salt)
            .or_else(|| {
                // We use runtime API as it will fallback to default value for genesis when
                // there is no salt stored yet
                self.client
                    .runtime_api()
                    .salt(&BlockId::Hash(parent_header.hash()))
                    .ok()
            })
    }

    /// Returns the merkle root of records given the segment index.
    fn records_root_for(
        &self,
        parent_header: &B::Header,
        segment_index: u64,
    ) -> Option<subspace_core_primitives::Sha256Hash> {
        let mut maybe_records_root = self
            .client
            .runtime_api()
            .records_root(&BlockId::Hash(parent_header.hash()), segment_index)
            .ok()?;

        // TODO: This is not a very nice hack due to the fact that at the time first block is
        //  produced extrinsics with root blocks are not yet in runtime
        if maybe_records_root.is_none() && parent_header.number().is_zero() {
            maybe_records_root = self.subspace_link.root_blocks.lock().iter().find_map(
                |(_block_number, root_blocks)| {
                    root_blocks.iter().find_map(|root_block| {
                        if root_block.segment_index() == segment_index {
                            Some(root_block.records_root())
                        } else {
                            None
                        }
                    })
                },
            );
        }

        maybe_records_root
    }
}

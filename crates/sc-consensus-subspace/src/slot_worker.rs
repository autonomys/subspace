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

use crate::{
    find_pre_digest, subspace_err, verification, Epoch, Error, NewSlotInfo, NewSlotNotification,
    SubspaceIntermediate, SubspaceLink, INTERMEDIATE_KEY,
};
use futures::StreamExt;
use futures::TryFutureExt;
use log::{debug, trace, warn};
use sc_consensus::block_import::{BlockImport, BlockImportParams, StateAction};
use sc_consensus_epochs::{descendent_query, ViableEpochDescriptor};
use sc_consensus_slots::{
    BackoffAuthoringBlocksStrategy, SimpleSlotWorker, SlotInfo, SlotProportion, StorageChanges,
};
use sc_telemetry::TelemetryHandle;
use sc_utils::mpsc::tracing_unbounded;
use schnorrkel::context::SigningContext;
use schnorrkel::SecretKey;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::{Error as ClientError, HeaderBackend, HeaderMetadata, ProvideCache};
use sp_consensus::{BlockOrigin, Environment, Error as ConsensusError, Proposer, SyncOracle};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{
    CompatibleDigestItem, NextSaltDescriptor, NextSolutionRangeDescriptor, PreDigest,
};
use sp_consensus_subspace::{ConsensusLog, SubspaceApi, SUBSPACE_ENGINE_ID};
use sp_core::sr25519::Pair;
use sp_core::Pair as _;
use sp_runtime::generic::{BlockId, OpaqueDigestItemId};
use sp_runtime::traits::{Block as BlockT, DigestItemFor, Header, Zero};
use std::future::Future;
use std::{borrow::Cow, pin::Pin, sync::Arc};
pub use subspace_archiving::archiver::ArchivedSegment;

pub(super) struct SubspaceSlotWorker<B: BlockT, C, E, I, SO, L, BS> {
    pub(super) client: Arc<C>,
    pub(super) block_import: I,
    pub(super) env: E,
    pub(super) sync_oracle: SO,
    pub(super) justification_sync_link: L,
    pub(super) force_authoring: bool,
    pub(super) backoff_authoring_blocks: Option<BS>,
    pub(super) subspace_link: SubspaceLink<B>,
    pub(super) signing_context: SigningContext,
    pub(super) block_proposal_slot_portion: SlotProportion,
    pub(super) max_block_proposal_slot_portion: Option<SlotProportion>,
    pub(super) telemetry: Option<TelemetryHandle>,
}

#[async_trait::async_trait]
impl<B, C, E, I, Error, SO, L, BS> SimpleSlotWorker<B> for SubspaceSlotWorker<B, C, E, I, SO, L, BS>
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
    Error: std::error::Error + Send + From<ConsensusError> + From<I::Error> + 'static,
{
    type EpochData = ViableEpochDescriptor<B::Hash, NumberFor<B>, Epoch>;
    type Claim = (PreDigest, Pair);
    type SyncOracle = SO;
    type JustificationSyncLink = L;
    type CreateProposer =
        Pin<Box<dyn Future<Output = Result<E::Proposer, sp_consensus::Error>> + Send + 'static>>;
    type Proposer = E::Proposer;
    type BlockImport = I;

    fn logging_target(&self) -> &'static str {
        "subspace"
    }

    fn block_import(&mut self) -> &mut Self::BlockImport {
        &mut self.block_import
    }

    fn epoch_data(
        &self,
        parent: &B::Header,
        slot: Slot,
    ) -> Result<Self::EpochData, ConsensusError> {
        self.subspace_link
            .epoch_changes
            .shared_data()
            .epoch_descriptor_for_child_of(
                descendent_query(&*self.client),
                &parent.hash(),
                *parent.number(),
                slot,
            )
            .map_err(|e| ConsensusError::ChainLookup(format!("{:?}", e)))?
            .ok_or(sp_consensus::Error::InvalidAuthoritiesSet)
    }

    async fn claim_slot(
        &self,
        parent_header: &B::Header,
        slot: Slot,
        epoch_descriptor: &Self::EpochData,
    ) -> Option<Self::Claim> {
        debug!(target: "subspace", "Attempting to claim slot {}", slot);

        let parent_block_id = BlockId::Hash(parent_header.hash());
        let runtime_api = self.client.runtime_api();

        let epoch_randomness = self
            .subspace_link
            .epoch_changes
            .shared_data()
            .viable_epoch(epoch_descriptor, |slot| {
                Epoch::genesis(&self.subspace_link.config, slot)
            })?
            .as_ref()
            .randomness;

        // Here we always use parent block as the source of information, thus on the edge of the
        // era the very first block of the era still uses solution range from the previous one,
        // but the block after it uses "next" solution range deposited in the first block.
        let solution_range = find_next_solution_range_digest::<B>(parent_header)
            .ok()?
            .map(|d| d.solution_range)
            .or_else(|| {
                // We use runtime API as it will fallback to default value for genesis when
                // there is no solution range stored yet
                runtime_api.solution_range(&parent_block_id).ok()
            })?;
        // Here we always use parent block as the source of information, thus on the edge of the
        // eon the very first block of the eon still uses salt from the previous one, but the
        // block after it uses "next" salt deposited in the first block.
        let salt = find_next_salt_digest::<B>(parent_header)
            .ok()?
            .map(|d| d.salt)
            .or_else(|| {
                // We use runtime API as it will fallback to default value for genesis when
                // there is no salt stored yet
                runtime_api.salt(&parent_block_id).ok()
            })?;

        let new_slot_info = NewSlotInfo {
            slot,
            global_challenge: subspace_solving::derive_global_challenge(&epoch_randomness, slot),
            salt: salt.to_le_bytes(),
            // TODO: This will not be the correct way in the future once salt is no longer
            //  just an incremented number
            next_salt: Some((salt + 1).to_le_bytes()),
            solution_range,
        };
        let (solution_sender, mut solution_receiver) =
            tracing_unbounded("subspace_slot_solution_stream");

        self.subspace_link
            .new_slot_notification_sender
            .notify(|| NewSlotNotification {
                new_slot_info,
                solution_sender,
            });

        while let Some((solution, secret_key)) = solution_receiver.next().await {
            // TODO: We need also need to check for equivocation of farmers connected to *this node*
            //  during block import, currently farmers connected to this node are considered trusted
            if runtime_api
                .is_in_block_list(&parent_block_id, &solution.public_key)
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

            let record_size = runtime_api.record_size(&parent_block_id).ok()?;
            let recorded_history_segment_size = runtime_api
                .recorded_history_segment_size(&parent_block_id)
                .ok()?;
            let merkle_num_leaves = u64::from(recorded_history_segment_size / record_size * 2);
            let segment_index = solution.piece_index / merkle_num_leaves;
            let position = solution.piece_index % merkle_num_leaves;
            let mut maybe_records_root = runtime_api
                .records_root(&parent_block_id, segment_index)
                .ok()?;

            // This is not a very nice hack due to the fact that at the time first block is produced
            // extrinsics with root blocks are not yet in runtime.
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

            let secret_key = SecretKey::from_bytes(&secret_key).ok()?;

            match verification::verify_solution::<B>(
                &solution,
                verification::VerifySolutionParams {
                    epoch_randomness: &epoch_randomness,
                    solution_range,
                    slot,
                    salt: salt.to_le_bytes(),
                    records_root: &records_root,
                    position,
                    record_size,
                    signing_context: &self.signing_context,
                },
            ) {
                Ok(_) => {
                    debug!(target: "subspace", "Claimed slot {}", slot);

                    return Some((PreDigest { solution, slot }, secret_key.into()));
                }
                Err(error) => {
                    warn!(target: "subspace", "Invalid solution received for slot {}: {:?}", slot, error);
                }
            }
        }

        None
    }

    fn pre_digest_data(
        &self,
        _slot: Slot,
        claim: &Self::Claim,
    ) -> Vec<sp_runtime::DigestItem<B::Hash>> {
        vec![<DigestItemFor<B> as CompatibleDigestItem>::subspace_pre_digest(claim.0.clone())]
    }

    #[allow(clippy::type_complexity)]
    fn block_import_params(
        &self,
    ) -> Box<
        dyn Fn(
                B::Header,
                &B::Hash,
                Vec<B::Extrinsic>,
                StorageChanges<I::Transaction, B>,
                Self::Claim,
                Self::EpochData,
            )
                -> Result<sc_consensus::BlockImportParams<B, I::Transaction>, sp_consensus::Error>
            + Send
            + 'static,
    > {
        Box::new(
            move |header,
                  header_hash,
                  body,
                  storage_changes,
                  (_pre_digest, keypair),
                  epoch_descriptor| {
                // sign the pre-sealed hash of the block and then
                // add it to a digest item.
                let signature = keypair.sign(header_hash.as_ref());
                let digest_item =
                    <DigestItemFor<B> as CompatibleDigestItem>::subspace_seal(signature.into());

                let mut import_block = BlockImportParams::new(BlockOrigin::Own, header);
                import_block.post_digests.push(digest_item);
                import_block.body = Some(body);
                import_block.state_action = StateAction::ApplyChanges(
                    sc_consensus::StorageChanges::Changes(storage_changes),
                );
                import_block.intermediates.insert(
                    Cow::from(INTERMEDIATE_KEY),
                    Box::new(SubspaceIntermediate::<B> { epoch_descriptor }) as Box<_>,
                );

                Ok(import_block)
            },
        )
    }

    fn force_authoring(&self) -> bool {
        self.force_authoring
    }

    fn should_backoff(&self, slot: Slot, chain_head: &B::Header) -> bool {
        if let Some(ref strategy) = self.backoff_authoring_blocks {
            if let Ok(chain_head_slot) = find_pre_digest::<B>(chain_head).map(|digest| digest.slot)
            {
                return strategy.should_backoff(
                    *chain_head.number(),
                    chain_head_slot,
                    self.client.info().finalized_number,
                    slot,
                    self.logging_target(),
                );
            }
        }
        false
    }

    fn sync_oracle(&mut self) -> &mut Self::SyncOracle {
        &mut self.sync_oracle
    }

    fn justification_sync_link(&mut self) -> &mut Self::JustificationSyncLink {
        &mut self.justification_sync_link
    }

    fn proposer(&mut self, block: &B::Header) -> Self::CreateProposer {
        Box::pin(
            self.env
                .init(block)
                .map_err(|e| sp_consensus::Error::ClientImport(format!("{:?}", e))),
        )
    }

    fn telemetry(&self) -> Option<TelemetryHandle> {
        self.telemetry.clone()
    }

    fn proposing_remaining_duration(&self, slot_info: &SlotInfo<B>) -> std::time::Duration {
        let parent_slot = find_pre_digest::<B>(&slot_info.chain_head)
            .ok()
            .map(|d| d.slot);

        sc_consensus_slots::proposing_remaining_duration(
            parent_slot,
            slot_info,
            &self.block_proposal_slot_portion,
            self.max_block_proposal_slot_portion.as_ref(),
            sc_consensus_slots::SlotLenienceType::Exponential,
            self.logging_target(),
        )
    }

    fn authorities_len(&self, _epoch_data: &Self::EpochData) -> Option<usize> {
        // This function is used in `sc-consensus-slots` in order to determine whether it is
        // possible to skip block production under certain circumstances, returning `None` or any
        // number smaller than `1` disables that functionality and we don't want it
        Some(2)
    }
}

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

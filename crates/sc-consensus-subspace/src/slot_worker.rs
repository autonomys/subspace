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

use crate::verification::PieceCheckParams;
use crate::{
    find_pre_digest, subspace_err, verification, BlockSigningNotification, NewSlotInfo,
    NewSlotNotification, SubspaceLink,
};
use futures::StreamExt;
use futures::TryFutureExt;
use log::{debug, error, info, warn};
use sc_consensus::block_import::{BlockImport, BlockImportParams, StateAction};
use sc_consensus::{JustificationSyncLink, StorageChanges};
use sc_consensus_slots::{
    BackoffAuthoringBlocksStrategy, SimpleSlotWorker, SlotInfo, SlotLenienceType, SlotProportion,
};
use sc_telemetry::TelemetryHandle;
use sc_utils::mpsc::tracing_unbounded;
use schnorrkel::context::SigningContext;
use sp_api::{ApiError, NumberFor, ProvideRuntimeApi, TransactionFor};
use sp_blockchain::{Error as ClientError, HeaderBackend, HeaderMetadata};
use sp_consensus::{BlockOrigin, Environment, Error as ConsensusError, Proposer, SyncOracle};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{CompatibleDigestItem, PreDigest};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature, SubspaceApi};
use sp_core::crypto::ByteArray;
use sp_core::H256;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{AppVerify, Block as BlockT, Header, One, Saturating, Zero};
use sp_runtime::{Digest, DigestItem};
use std::future::Future;
use std::{pin::Pin, sync::Arc};
use subspace_core_primitives::{Randomness, Salt};

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
    C: ProvideRuntimeApi<B> + HeaderBackend<B> + HeaderMetadata<B, Error = ClientError> + 'static,
    C::Api: SubspaceApi<B>,
    E: Environment<B, Error = Error> + Send + Sync,
    E::Proposer: Proposer<B, Error = Error, Transaction = TransactionFor<C, B>>,
    I: BlockImport<B, Transaction = TransactionFor<C, B>> + Send + Sync + 'static,
    SO: SyncOracle + Send + Sync + Clone,
    L: JustificationSyncLink<B>,
    BS: BackoffAuthoringBlocksStrategy<NumberFor<B>> + Send + Sync,
    Error: std::error::Error + Send + From<ConsensusError> + From<I::Error> + 'static,
{
    type BlockImport = I;
    type SyncOracle = SO;
    type JustificationSyncLink = L;
    type CreateProposer =
        Pin<Box<dyn Future<Output = Result<E::Proposer, ConsensusError>> + Send + 'static>>;
    type Proposer = E::Proposer;
    type Claim = PreDigest<FarmerPublicKey>;
    type EpochData = ();

    fn logging_target(&self) -> &'static str {
        "subspace"
    }

    fn block_import(&mut self) -> &mut Self::BlockImport {
        &mut self.block_import
    }

    fn epoch_data(
        &self,
        _parent: &B::Header,
        _slot: Slot,
    ) -> Result<Self::EpochData, ConsensusError> {
        Ok(())
    }

    fn authorities_len(&self, _epoch_data: &Self::EpochData) -> Option<usize> {
        // This function is used in `sc-consensus-slots` in order to determine whether it is
        // possible to skip block production under certain circumstances, returning `None` or any
        // number smaller or equal to `1` disables that functionality and we don't want that.
        Some(2)
    }

    async fn claim_slot(
        &self,
        parent_header: &B::Header,
        slot: Slot,
        _epoch_data: &Self::EpochData,
    ) -> Option<Self::Claim> {
        debug!(target: "subspace", "Attempting to claim slot {}", slot);

        let parent_block_id = BlockId::Hash(parent_header.hash());
        let runtime_api = self.client.runtime_api();

        let global_randomness =
            extract_global_randomness_for_block(self.client.as_ref(), &parent_block_id).ok()?;
        let (solution_range, voting_solution_range) =
            extract_solution_ranges_for_block(self.client.as_ref(), &parent_block_id).ok()?;
        let (salt, next_salt) =
            extract_salt_for_block(self.client.as_ref(), &parent_block_id).ok()?;

        let new_slot_info = NewSlotInfo {
            slot,
            global_challenge: subspace_solving::derive_global_challenge(&global_randomness, slot),
            salt,
            next_salt,
            solution_range: voting_solution_range,
        };
        let (solution_sender, mut solution_receiver) =
            tracing_unbounded("subspace_slot_solution_stream");

        self.subspace_link
            .new_slot_notification_sender
            .notify(|| NewSlotNotification {
                new_slot_info,
                solution_sender,
            });

        while let Some(solution) = solution_receiver.next().await {
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
            let max_plot_size = runtime_api.max_plot_size(&parent_block_id).ok()?;
            let merkle_num_leaves = u64::from(recorded_history_segment_size / record_size * 2);
            let segment_index = solution.piece_index / merkle_num_leaves;
            let position = solution.piece_index % merkle_num_leaves;
            let mut maybe_records_root = runtime_api
                .records_root(&parent_block_id, segment_index)
                .ok()?;
            let total_pieces = runtime_api.total_pieces(&parent_block_id).ok()?;

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

            let solution_verification_result = verification::verify_solution::<B::Header>(
                &solution,
                slot,
                verification::VerifySolutionParams {
                    global_randomness: &global_randomness,
                    solution_range: voting_solution_range,
                    salt,
                    piece_check_params: Some(PieceCheckParams {
                        records_root,
                        position,
                        record_size,
                        max_plot_size,
                        total_pieces,
                    }),
                    signing_context: &self.signing_context,
                },
            );

            if let Err(error) = solution_verification_result {
                warn!(target: "subspace", "Invalid solution received for slot {slot}: {error:?}");
            } else {
                let pre_digest = PreDigest { solution, slot };

                // If solution is of high enough quality, block reward is claimed
                if verification::is_within_solution_range(&pre_digest.solution, solution_range) {
                    info!(target: "subspace", "Claimed block at slot {slot}");

                    return Some(pre_digest);
                } else {
                    info!(target: "subspace", "Claimed vote at slot {slot}");

                    self.create_vote(pre_digest, parent_header, &parent_block_id)
                        .await;
                }
            }
        }

        None
    }

    fn pre_digest_data(&self, _slot: Slot, claim: &Self::Claim) -> Vec<DigestItem> {
        vec![DigestItem::subspace_pre_digest(claim)]
    }

    async fn block_import_params(
        &self,
        header: B::Header,
        header_hash: &B::Hash,
        body: Vec<B::Extrinsic>,
        storage_changes: sc_consensus_slots::StorageChanges<I::Transaction, B>,
        pre_digest: Self::Claim,
        _epoch_data: Self::EpochData,
    ) -> Result<BlockImportParams<B, I::Transaction>, ConsensusError> {
        let signature = self
            .sign_pre_header(
                H256::from_slice(header_hash.as_ref()),
                &pre_digest.solution.public_key,
            )
            .await?;

        let digest_item = DigestItem::subspace_seal(signature);

        let mut import_block = BlockImportParams::new(BlockOrigin::Own, header);
        import_block.post_digests.push(digest_item);
        import_block.body = Some(body);
        import_block.state_action =
            StateAction::ApplyChanges(StorageChanges::Changes(storage_changes));

        Ok(import_block)
    }

    fn force_authoring(&self) -> bool {
        self.force_authoring
    }

    fn should_backoff(&self, slot: Slot, chain_head: &B::Header) -> bool {
        if let Some(ref strategy) = self.backoff_authoring_blocks {
            if let Ok(chain_head_slot) = find_pre_digest(chain_head)
                .map(|digest| digest.slot)
                .map_err(subspace_err)
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
                .map_err(|e| ConsensusError::ClientImport(e.to_string())),
        )
    }

    fn telemetry(&self) -> Option<TelemetryHandle> {
        self.telemetry.clone()
    }

    fn proposing_remaining_duration(&self, slot_info: &SlotInfo<B>) -> std::time::Duration {
        let parent_slot = find_pre_digest(&slot_info.chain_head)
            .map_err(subspace_err)
            .ok()
            .map(|d| d.slot);

        sc_consensus_slots::proposing_remaining_duration(
            parent_slot,
            slot_info,
            &self.block_proposal_slot_portion,
            self.max_block_proposal_slot_portion.as_ref(),
            SlotLenienceType::Exponential,
            self.logging_target(),
        )
    }
}

impl<B, C, E, I, Error, SO, L, BS> SubspaceSlotWorker<B, C, E, I, SO, L, BS>
where
    B: BlockT,
    C: ProvideRuntimeApi<B> + HeaderBackend<B> + HeaderMetadata<B, Error = ClientError> + 'static,
    C::Api: SubspaceApi<B>,
    E: Environment<B, Error = Error> + Send + Sync,
    E::Proposer: Proposer<B, Error = Error, Transaction = TransactionFor<C, B>>,
    I: BlockImport<B, Transaction = TransactionFor<C, B>> + Send + Sync + 'static,
    SO: SyncOracle + Send + Sync + Clone,
    L: JustificationSyncLink<B>,
    BS: BackoffAuthoringBlocksStrategy<NumberFor<B>> + Send + Sync,
    Error: std::error::Error + Send + From<ConsensusError> + From<I::Error> + 'static,
{
    async fn create_vote(
        &self,
        pre_digest: PreDigest<FarmerPublicKey>,
        parent_header: &B::Header,
        parent_block_id: &BlockId<B>,
    ) {
        let slot = pre_digest.slot;
        let runtime_api = self.client.runtime_api();

        if self.should_backoff(slot, parent_header) {
            return;
        }

        // Vote doesn't have extrinsics or state, hence dummy values
        let mut vote = B::Header::new(
            parent_header.number().saturating_add(One::one()),
            <B::Header as Header>::Hash::default(),
            <B::Header as Header>::Hash::default(),
            parent_header.hash(),
            Digest {
                logs: vec![DigestItem::subspace_pre_digest(&pre_digest)],
            },
        );

        let signature = match self
            .sign_pre_header(
                H256::from_slice(vote.hash().as_ref()),
                &pre_digest.solution.public_key,
            )
            .await
        {
            Ok(signature) => signature,
            Err(error) => {
                error!(
                    target: "subspace",
                    "Failed to submit vote at slot {slot}: {error:?}",
                );
                return;
            }
        };

        vote.digest_mut()
            .logs
            .push(DigestItem::subspace_seal(signature));

        if let Err(error) = runtime_api.submit_vote_extrinsic(parent_block_id, vote) {
            error!(
                target: "subspace",
                "Failed to submit vote at slot {slot}: {error:?}",
            );
        }
    }

    async fn sign_pre_header(
        &self,
        header_hash: H256,
        public_key: &FarmerPublicKey,
    ) -> Result<FarmerSignature, ConsensusError> {
        let (signature_sender, mut signature_receiver) =
            tracing_unbounded("subspace_signature_signing_stream");

        // Sign the pre-sealed header of the block and then add it to a digest item.
        self.subspace_link
            .block_signing_notification_sender
            .notify(|| BlockSigningNotification {
                header_hash,
                public_key: public_key.clone(),
                signature_sender,
            });

        while let Some(signature) = signature_receiver.next().await {
            if !signature.verify(header_hash.as_ref(), public_key) {
                warn!(
                    target: "subspace",
                    "Received invalid signature for pre-header {header_hash:?}"
                );
                continue;
            }

            return Ok(signature);
        }

        Err(ConsensusError::CannotSign(
            public_key.to_raw_vec(),
            "Farmer didn't sign header".to_string(),
        ))
    }
}

/// Extract global randomness for block, given ID of the parent block.
pub(crate) fn extract_global_randomness_for_block<Block, Client>(
    client: &Client,
    parent_block_id: &BlockId<Block>,
) -> Result<Randomness, ApiError>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: SubspaceApi<Block>,
{
    client
        .runtime_api()
        .global_randomnesses(parent_block_id)
        .map(|randomnesses| randomnesses.next.unwrap_or(randomnesses.current))
}

/// Extract solution ranges for block and votes, given ID of the parent block.
pub(crate) fn extract_solution_ranges_for_block<Block, Client>(
    client: &Client,
    parent_block_id: &BlockId<Block>,
) -> Result<(u64, u64), ApiError>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: SubspaceApi<Block>,
{
    client
        .runtime_api()
        .solution_ranges(parent_block_id)
        .map(|solution_ranges| {
            (
                solution_ranges.next.unwrap_or(solution_ranges.current),
                solution_ranges
                    .voting_next
                    .unwrap_or(solution_ranges.voting_current),
            )
        })
}

/// Extract salt and next salt for block, given ID of the parent block.
pub(crate) fn extract_salt_for_block<Block, Client>(
    client: &Client,
    parent_block_id: &BlockId<Block>,
) -> Result<(Salt, Option<Salt>), ApiError>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: SubspaceApi<Block>,
{
    client.runtime_api().salts(parent_block_id).map(|salts| {
        if salts.switch_next_block {
            (
                salts.next.expect(
                    "Next salt must always be present if `switch_next_block` is `true`; qed",
                ),
                None,
            )
        } else {
            (salts.current, salts.next)
        }
    })
}

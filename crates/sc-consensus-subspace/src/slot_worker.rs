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

use crate::{NewSlotInfo, NewSlotNotification, RewardSigningNotification, SubspaceLink};
use futures::{StreamExt, TryFutureExt};
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
use sp_consensus_subspace::digests::{extract_pre_digest, CompatibleDigestItem, PreDigest};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature, SignedVote, SubspaceApi, Vote};
use sp_core::crypto::ByteArray;
use sp_core::H256;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header, One, Saturating, Zero};
use sp_runtime::DigestItem;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use subspace_core_primitives::{
    Randomness, RewardSignature, SectorId, SegmentIndex, Solution, PIECES_IN_SEGMENT,
};
use subspace_solving::derive_global_challenge;
use subspace_verification::{
    check_reward_signature, is_within_solution_range, verify_solution, PieceCheckParams,
    VerifySolutionParams,
};

#[derive(Clone)]
pub(super) struct SlotWorkerSyncOracle<SO>
where
    SO: SyncOracle + Send + Sync + Clone,
{
    pub(super) force_authoring: bool,
    pub(super) inner: SO,
}

impl<SO> SyncOracle for SlotWorkerSyncOracle<SO>
where
    SO: SyncOracle + Send + Sync + Clone,
{
    fn is_major_syncing(&self) -> bool {
        // This allows slot worker to produce blocks even when it is offline, which according to
        // modified Substrate fork will happen when node is offline or connected to non-synced peers
        // (default state)
        !self.force_authoring && self.inner.is_major_syncing()
    }

    fn is_offline(&self) -> bool {
        self.inner.is_offline()
    }
}

pub(super) struct SubspaceSlotWorker<Block: BlockT, Client, E, I, SO, L, BS> {
    pub(super) client: Arc<Client>,
    pub(super) block_import: I,
    pub(super) env: E,
    pub(super) sync_oracle: SO,
    pub(super) justification_sync_link: L,
    pub(super) force_authoring: bool,
    pub(super) backoff_authoring_blocks: Option<BS>,
    pub(super) subspace_link: SubspaceLink<Block>,
    pub(super) reward_signing_context: SigningContext,
    pub(super) block_proposal_slot_portion: SlotProportion,
    pub(super) max_block_proposal_slot_portion: Option<SlotProportion>,
    pub(super) telemetry: Option<TelemetryHandle>,
}

#[async_trait::async_trait]
impl<Block, Client, E, I, Error, SO, L, BS> SimpleSlotWorker<Block>
    for SubspaceSlotWorker<Block, Client, E, I, SO, L, BS>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = ClientError>
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    E: Environment<Block, Error = Error> + Send + Sync,
    E::Proposer: Proposer<Block, Error = Error, Transaction = TransactionFor<Client, Block>>,
    I: BlockImport<Block, Transaction = TransactionFor<Client, Block>> + Send + Sync + 'static,
    SO: SyncOracle + Send + Sync + Clone,
    L: JustificationSyncLink<Block>,
    BS: BackoffAuthoringBlocksStrategy<NumberFor<Block>> + Send + Sync,
    Error: std::error::Error + Send + From<ConsensusError> + From<I::Error> + 'static,
{
    type BlockImport = I;
    type SyncOracle = SO;
    type JustificationSyncLink = L;
    type CreateProposer =
        Pin<Box<dyn Future<Output = Result<E::Proposer, ConsensusError>> + Send + 'static>>;
    type Proposer = E::Proposer;
    type Claim = PreDigest<FarmerPublicKey, FarmerPublicKey>;
    type EpochData = ();

    fn logging_target(&self) -> &'static str {
        "subspace"
    }

    fn block_import(&mut self) -> &mut Self::BlockImport {
        &mut self.block_import
    }

    fn epoch_data(
        &self,
        _parent: &Block::Header,
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
        parent_header: &Block::Header,
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
        let global_challenge = derive_global_challenge(&global_randomness, slot.into());

        let maybe_root_plot_public_key = self
            .client
            .runtime_api()
            .root_plot_public_key(&parent_block_id)
            .ok()?;

        let new_slot_info = NewSlotInfo {
            slot,
            global_challenge,
            solution_range,
            voting_solution_range,
        };
        let (solution_sender, mut solution_receiver) =
            tracing_unbounded("subspace_slot_solution_stream");

        self.subspace_link
            .new_slot_notification_sender
            .notify(|| NewSlotNotification {
                new_slot_info,
                solution_sender,
            });

        let mut maybe_pre_digest = None;

        while let Some(solution) = solution_receiver.next().await {
            if let Some(root_plot_public_key) = &maybe_root_plot_public_key {
                if &solution.public_key != root_plot_public_key {
                    // Only root plot public key is allowed, no need to even try to claim block or
                    // vote.
                    continue;
                }
            }

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

            let sector_id = SectorId::new(&(&solution.public_key).into(), solution.sector_index);

            let piece_index =
                sector_id.derive_piece_index(solution.piece_offset, solution.total_pieces);
            let segment_index: SegmentIndex = piece_index / SegmentIndex::from(PIECES_IN_SEGMENT);
            let position = u32::try_from(piece_index % u64::from(PIECES_IN_SEGMENT))
                .expect("Position within segment always fits into u32; qed");
            let mut maybe_records_root = runtime_api
                .records_root(&parent_block_id, segment_index)
                .ok()?;
            // TODO: This will be necessary for verifying sector expiration in the future
            let _total_pieces = runtime_api.total_pieces(&parent_block_id).ok()?;

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

            let solution_verification_result = verify_solution(
                &solution,
                slot.into(),
                VerifySolutionParams {
                    global_randomness: &global_randomness,
                    solution_range: voting_solution_range,
                    piece_check_params: Some(PieceCheckParams {
                        records_root: &records_root,
                        position,
                        kzg: &self.subspace_link.kzg,
                        pieces_in_segment: PIECES_IN_SEGMENT,
                    }),
                },
            );

            if let Err(error) = solution_verification_result {
                warn!(target: "subspace", "Invalid solution received for slot {slot}: {error:?}");
            } else {
                let local_challenge = sector_id.derive_local_challenge(&global_challenge);

                let expanded_chunk = solution.chunk.expand(local_challenge);

                // If solution is of high enough quality and block pre-digest wasn't produced yet,
                // block reward is claimed
                if maybe_pre_digest.is_none()
                    && is_within_solution_range(local_challenge, expanded_chunk, solution_range)
                {
                    info!(target: "subspace", "🚜 Claimed block at slot {slot}");

                    maybe_pre_digest.replace(PreDigest { solution, slot });
                } else if !parent_header.number().is_zero() {
                    // Not sending vote on top of genesis block since root blocks since piece
                    // verification wouldn't be possible due to empty records root
                    info!(target: "subspace", "🗳️ Claimed vote at slot {slot}");

                    self.create_vote(solution, slot, parent_header, &parent_block_id)
                        .await;
                }
            }
        }

        maybe_pre_digest
    }

    fn pre_digest_data(&self, _slot: Slot, claim: &Self::Claim) -> Vec<DigestItem> {
        vec![DigestItem::subspace_pre_digest(claim)]
    }

    async fn block_import_params(
        &self,
        header: Block::Header,
        header_hash: &Block::Hash,
        body: Vec<Block::Extrinsic>,
        storage_changes: sc_consensus_slots::StorageChanges<I::Transaction, Block>,
        pre_digest: Self::Claim,
        _epoch_data: Self::EpochData,
    ) -> Result<BlockImportParams<Block, I::Transaction>, ConsensusError> {
        let signature = self
            .sign_reward(
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

    fn should_backoff(&self, slot: Slot, chain_head: &Block::Header) -> bool {
        if let Some(ref strategy) = self.backoff_authoring_blocks {
            if let Ok(chain_head_slot) = extract_pre_digest(chain_head).map(|digest| digest.slot) {
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

    fn proposer(&mut self, block: &Block::Header) -> Self::CreateProposer {
        Box::pin(
            self.env
                .init(block)
                .map_err(|e| ConsensusError::ClientImport(e.to_string())),
        )
    }

    fn telemetry(&self) -> Option<TelemetryHandle> {
        self.telemetry.clone()
    }

    fn proposing_remaining_duration(&self, slot_info: &SlotInfo<Block>) -> std::time::Duration {
        let parent_slot = extract_pre_digest(&slot_info.chain_head)
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

impl<Block, Client, E, I, Error, SO, L, BS> SubspaceSlotWorker<Block, Client, E, I, SO, L, BS>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = ClientError>
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    E: Environment<Block, Error = Error> + Send + Sync,
    E::Proposer: Proposer<Block, Error = Error, Transaction = TransactionFor<Client, Block>>,
    I: BlockImport<Block, Transaction = TransactionFor<Client, Block>> + Send + Sync + 'static,
    SO: SyncOracle + Send + Sync + Clone,
    L: JustificationSyncLink<Block>,
    BS: BackoffAuthoringBlocksStrategy<NumberFor<Block>> + Send + Sync,
    Error: std::error::Error + Send + From<ConsensusError> + From<I::Error> + 'static,
{
    async fn create_vote(
        &self,
        solution: Solution<FarmerPublicKey, FarmerPublicKey>,
        slot: Slot,
        parent_header: &Block::Header,
        parent_block_id: &BlockId<Block>,
    ) {
        let runtime_api = self.client.runtime_api();

        if self.should_backoff(slot, parent_header) {
            return;
        }

        // Vote doesn't have extrinsics or state, hence dummy values
        let vote = Vote::V0 {
            height: parent_header.number().saturating_add(One::one()),
            parent_hash: parent_header.hash(),
            slot,
            solution: solution.clone(),
        };

        let signature = match self.sign_reward(vote.hash(), &solution.public_key).await {
            Ok(signature) => signature,
            Err(error) => {
                error!(
                    target: "subspace",
                    "Failed to submit vote at slot {slot}: {error:?}",
                );
                return;
            }
        };

        let signed_vote = SignedVote { vote, signature };

        if let Err(error) = runtime_api.submit_vote_extrinsic(parent_block_id, signed_vote) {
            error!(
                target: "subspace",
                "Failed to submit vote at slot {slot}: {error:?}",
            );
        }
    }

    async fn sign_reward(
        &self,
        hash: H256,
        public_key: &FarmerPublicKey,
    ) -> Result<FarmerSignature, ConsensusError> {
        let (signature_sender, mut signature_receiver) =
            tracing_unbounded("subspace_signature_signing_stream");

        self.subspace_link
            .reward_signing_notification_sender
            .notify(|| RewardSigningNotification {
                hash,
                public_key: public_key.clone(),
                signature_sender,
            });

        while let Some(signature) = signature_receiver.next().await {
            if check_reward_signature(
                hash.as_ref(),
                &RewardSignature::from(&signature),
                &subspace_core_primitives::PublicKey::from(public_key),
                &self.reward_signing_context,
            )
            .is_err()
            {
                warn!(
                    target: "subspace",
                    "Received invalid signature for reward hash {hash:?}"
                );
                continue;
            }

            return Ok(signature);
        }

        Err(ConsensusError::CannotSign(
            public_key.to_raw_vec(),
            "Farmer didn't sign reward".to_string(),
        ))
    }
}

// TODO: Replace with querying parent block header when breaking protocol
/// Extract global randomness for block, given ID of the parent block.
pub(crate) fn extract_global_randomness_for_block<Block, Client>(
    client: &Client,
    parent_block_id: &BlockId<Block>,
) -> Result<Randomness, ApiError>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
{
    client
        .runtime_api()
        .global_randomnesses(parent_block_id)
        .map(|randomnesses| randomnesses.next.unwrap_or(randomnesses.current))
}

// TODO: Replace with querying parent block header when breaking protocol
/// Extract solution ranges for block and votes, given ID of the parent block.
pub(crate) fn extract_solution_ranges_for_block<Block, Client>(
    client: &Client,
    parent_block_id: &BlockId<Block>,
) -> Result<(u64, u64), ApiError>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
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

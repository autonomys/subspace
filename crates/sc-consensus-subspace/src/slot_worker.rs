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

use crate::archiver::SegmentHeadersStore;
use crate::{
    get_chain_constants, BlockImportingNotification, NewSlotInfo, NewSlotNotification,
    RewardSigningNotification, SubspaceLink,
};
use futures::channel::mpsc;
use futures::{StreamExt, TryFutureExt};
use log::{debug, error, info, warn};
use sc_client_api::AuxStore;
use sc_consensus::block_import::{BlockImport, BlockImportParams, StateAction};
use sc_consensus::{JustificationSyncLink, StorageChanges};
use sc_consensus_slots::{
    BackoffAuthoringBlocksStrategy, SimpleSlotWorker, SlotInfo, SlotLenienceType, SlotProportion,
};
use sc_proof_of_time::PotConsensusState;
#[cfg(feature = "pot")]
use sc_proof_of_time::PotGetBlockProofsError;
use sc_telemetry::TelemetryHandle;
use sc_utils::mpsc::tracing_unbounded;
use schnorrkel::context::SigningContext;
use sp_api::{ApiError, NumberFor, ProvideRuntimeApi, TransactionFor};
use sp_blockchain::{Error as ClientError, HeaderBackend, HeaderMetadata};
use sp_consensus::{BlockOrigin, Environment, Error as ConsensusError, Proposer, SyncOracle};
use sp_consensus_slots::Slot;
#[cfg(feature = "pot")]
use sp_consensus_subspace::digests::PotPreDigest;
use sp_consensus_subspace::digests::{extract_pre_digest, CompatibleDigestItem, PreDigest};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature, SignedVote, SubspaceApi, Vote};
use sp_core::crypto::ByteArray;
use sp_core::H256;
use sp_runtime::traits::{Block as BlockT, Header, One, Saturating, Zero};
use sp_runtime::DigestItem;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(feature = "pot")]
use subspace_core_primitives::SlotNumber;
use subspace_core_primitives::{
    BlockNumber, PublicKey, Randomness, RewardSignature, SectorId, Solution,
};
use subspace_proof_of_space::Table;
use subspace_verification::{
    check_reward_signature, verify_solution, PieceCheckParams, VerifySolutionParams,
};

/// Errors while building the block proof of time.
#[cfg(feature = "pot")]
#[derive(Debug, thiserror::Error)]
pub enum PotCreateError {
    /// Proof creation failed.
    #[error("{0}")]
    PotGetBlockProofsError(#[from] PotGetBlockProofsError),
}

/// Subspace sync oracle that takes into account force authoring flag, allowing to bootstrap
/// Subspace network from scratch due to our fork of Substrate where sync state of nodes depends on
/// connected nodes (none of which will be synced initially).
#[derive(Debug, Clone)]
pub struct SubspaceSyncOracle<SO>
where
    SO: SyncOracle + Send + Sync,
{
    force_authoring: bool,
    inner: SO,
}

impl<SO> SyncOracle for SubspaceSyncOracle<SO>
where
    SO: SyncOracle + Send + Sync,
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

impl<SO> SubspaceSyncOracle<SO>
where
    SO: SyncOracle + Send + Sync,
{
    /// Create new instance
    pub fn new(force_authoring: bool, substrate_sync_oracle: SO) -> Self {
        Self {
            force_authoring,
            inner: substrate_sync_oracle,
        }
    }
}

pub(super) struct SubspaceSlotWorker<PosTable, Block, Client, E, I, SO, L, BS, AS>
where
    Block: BlockT,
{
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
    pub(super) segment_headers_store: SegmentHeadersStore<AS>,
    // TODO: Un-suppress once we enable PoT unconditionally
    #[allow(dead_code)]
    pub(super) proof_of_time: Option<Arc<dyn PotConsensusState>>,
    pub(super) _pos_table: PhantomData<PosTable>,
}

#[async_trait::async_trait]
impl<PosTable, Block, Client, E, I, Error, SO, L, BS, AS> SimpleSlotWorker<Block>
    for SubspaceSlotWorker<PosTable, Block, Client, E, I, SO, L, BS, AS>
where
    PosTable: Table,
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = ClientError>
        + AuxStore
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    E: Environment<Block, Error = Error> + Send + Sync,
    E::Proposer: Proposer<Block, Error = Error, Transaction = TransactionFor<Client, Block>>,
    I: BlockImport<Block, Transaction = TransactionFor<Client, Block>> + Send + Sync + 'static,
    SO: SyncOracle + Send + Sync,
    L: JustificationSyncLink<Block>,
    BS: BackoffAuthoringBlocksStrategy<NumberFor<Block>> + Send + Sync,
    Error: std::error::Error + Send + From<ConsensusError> + From<I::Error> + 'static,
    AS: AuxStore + Send + Sync + 'static,
    BlockNumber: From<<<Block as BlockT>::Header as Header>::Number>,
{
    type BlockImport = I;
    type SyncOracle = SO;
    type JustificationSyncLink = L;
    type CreateProposer =
        Pin<Box<dyn Future<Output = Result<E::Proposer, ConsensusError>> + Send + 'static>>;
    type Proposer = E::Proposer;
    type Claim = PreDigest<FarmerPublicKey, FarmerPublicKey>;
    type AuxData = ();

    fn logging_target(&self) -> &'static str {
        "subspace"
    }

    fn block_import(&mut self) -> &mut Self::BlockImport {
        &mut self.block_import
    }

    fn aux_data(
        &self,
        _parent: &Block::Header,
        _slot: Slot,
    ) -> Result<Self::AuxData, ConsensusError> {
        Ok(())
    }

    fn authorities_len(&self, _epoch_data: &Self::AuxData) -> Option<usize> {
        // This function is used in `sc-consensus-slots` in order to determine whether it is
        // possible to skip block production under certain circumstances, returning `None` or any
        // number smaller or equal to `1` disables that functionality and we don't want that.
        Some(2)
    }

    async fn claim_slot(
        &self,
        parent_header: &Block::Header,
        slot: Slot,
        _epoch_data: &Self::AuxData,
    ) -> Option<Self::Claim> {
        let parent_pre_digest = match extract_pre_digest(parent_header) {
            Ok(pre_digest) => pre_digest,
            Err(error) => {
                error!(
                    target: "subspace",
                    "Failed to parse pre-digest out of parent header: {error}"
                );

                return None;
            }
        };
        let parent_slot = parent_pre_digest.slot;

        if slot <= parent_slot {
            debug!(
                target: "subspace",
                "Skipping claiming slot {slot} it must be higher than parent slot {parent_slot}",
            );

            return None;
        } else {
            debug!(target: "subspace", "Attempting to claim slot {}", slot);
        }

        let parent_hash = parent_header.hash();
        let runtime_api = self.client.runtime_api();

        #[cfg(not(feature = "pot"))]
        let global_randomness =
            extract_global_randomness_for_block(self.client.as_ref(), parent_hash).ok()?;

        // If proof of time is enabled, collect the proofs that go into this
        // block and derive randomness from the last proof.
        #[cfg(feature = "pot")]
        let (pot_pre_digest, global_randomness) =
            if let Some(proof_of_time) = self.proof_of_time.as_ref() {
                let pot_pre_digest = self
                    .build_block_pot(
                        proof_of_time.as_ref(),
                        parent_header,
                        &parent_pre_digest,
                        slot.into(),
                    )
                    .await
                    .ok()?;
                let randomness = pot_pre_digest.derive_global_randomness();
                (Some(pot_pre_digest), randomness)
            } else {
                (
                    None,
                    extract_global_randomness_for_block(self.client.as_ref(), parent_hash).ok()?,
                )
            };

        let (solution_range, voting_solution_range) =
            extract_solution_ranges_for_block(self.client.as_ref(), parent_hash).ok()?;

        let maybe_root_plot_public_key = self
            .client
            .runtime_api()
            .root_plot_public_key(parent_hash)
            .ok()?;

        let new_slot_info = NewSlotInfo {
            slot,
            global_randomness,
            solution_range,
            voting_solution_range,
        };
        let (solution_sender, mut solution_receiver) =
            tracing_unbounded("subspace_slot_solution_stream", 100);

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
                .is_in_block_list(parent_hash, &solution.public_key)
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

            let sector_id = SectorId::new(
                PublicKey::from(&solution.public_key).hash(),
                solution.sector_index,
            );

            let history_size = runtime_api.history_size(parent_hash).ok()?;
            let max_pieces_in_sector = runtime_api.max_pieces_in_sector(parent_hash).ok()?;
            let chain_constants = get_chain_constants(self.client.as_ref()).ok()?;

            let segment_index = sector_id
                .derive_piece_index(
                    solution.piece_offset,
                    solution.history_size,
                    max_pieces_in_sector,
                    chain_constants.recent_segments(),
                    chain_constants.recent_history_fraction(),
                )
                .segment_index();
            let maybe_segment_commitment = self
                .segment_headers_store
                .get_segment_header(segment_index)
                .map(|segment_header| segment_header.segment_commitment());

            let segment_commitment = match maybe_segment_commitment {
                Some(segment_commitment) => segment_commitment,
                None => {
                    warn!(
                        target: "subspace",
                        "Segment commitment for segment index {} not found (slot {})",
                        segment_index,
                        slot,
                    );
                    continue;
                }
            };
            let sector_expiration_check_segment_index = match solution
                .history_size
                .sector_expiration_check(chain_constants.min_sector_lifetime())
            {
                Some(sector_expiration_check) => sector_expiration_check.segment_index(),
                None => {
                    continue;
                }
            };
            let sector_expiration_check_segment_commitment = runtime_api
                .segment_commitment(parent_hash, sector_expiration_check_segment_index)
                .ok()?;

            let solution_verification_result = verify_solution::<PosTable, _, _>(
                &solution,
                slot.into(),
                &VerifySolutionParams {
                    global_randomness,
                    solution_range: voting_solution_range,
                    piece_check_params: Some(PieceCheckParams {
                        max_pieces_in_sector,
                        segment_commitment,
                        recent_segments: chain_constants.recent_segments(),
                        recent_history_fraction: chain_constants.recent_history_fraction(),
                        min_sector_lifetime: chain_constants.min_sector_lifetime(),
                        current_history_size: history_size,
                        sector_expiration_check_segment_commitment,
                    }),
                },
                &self.subspace_link.kzg,
            );

            match solution_verification_result {
                Ok(solution_distance) => {
                    // If solution is of high enough quality and block pre-digest wasn't produced yet,
                    // block reward is claimed
                    if maybe_pre_digest.is_none() && solution_distance <= solution_range / 2 {
                        info!(target: "subspace", "🚜 Claimed block at slot {slot}");
                        maybe_pre_digest.replace(PreDigest {
                            solution,
                            slot,
                            #[cfg(feature = "pot")]
                            proof_of_time: pot_pre_digest.clone(),
                        });
                    } else if !parent_header.number().is_zero() {
                        // Not sending vote on top of genesis block since segment headers since piece
                        // verification wouldn't be possible due to missing (for now) segment commitment
                        info!(target: "subspace", "🗳️ Claimed vote at slot {slot}");

                        self.create_vote(solution, slot, parent_header, parent_hash)
                            .await;
                    }
                }
                Err(error) => {
                    warn!(target: "subspace", "Invalid solution received for slot {slot}: {error:?}");
                }
            }
        }

        // TODO: This is a workaround for potential root cause of
        //  https://github.com/subspace/subspace/issues/871, also being discussed in
        //  https://substrate.stackexchange.com/questions/7886/is-block-creation-guaranteed-to-be-running-after-parent-block-is-fully-imported
        if maybe_pre_digest.is_some() {
            let block_number = *parent_header.number() + One::one();
            let (acknowledgement_sender, mut acknowledgement_receiver) = mpsc::channel(0);

            self.subspace_link
                .block_importing_notification_sender
                .notify(move || BlockImportingNotification {
                    block_number,
                    acknowledgement_sender,
                });

            while (acknowledgement_receiver.next().await).is_some() {
                // Wait for all the acknowledgements to finish.
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
        _epoch_data: Self::AuxData,
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

impl<PosTable, Block, Client, E, I, Error, SO, L, BS, AS>
    SubspaceSlotWorker<PosTable, Block, Client, E, I, SO, L, BS, AS>
where
    PosTable: Table,
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = ClientError>
        + AuxStore
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    E: Environment<Block, Error = Error> + Send + Sync,
    E::Proposer: Proposer<Block, Error = Error, Transaction = TransactionFor<Client, Block>>,
    I: BlockImport<Block, Transaction = TransactionFor<Client, Block>> + Send + Sync + 'static,
    SO: SyncOracle + Send + Sync,
    L: JustificationSyncLink<Block>,
    BS: BackoffAuthoringBlocksStrategy<NumberFor<Block>> + Send + Sync,
    Error: std::error::Error + Send + From<ConsensusError> + From<I::Error> + 'static,
    AS: AuxStore + Send + Sync + 'static,
    BlockNumber: From<<<Block as BlockT>::Header as Header>::Number>,
{
    async fn create_vote(
        &self,
        solution: Solution<FarmerPublicKey, FarmerPublicKey>,
        slot: Slot,
        parent_header: &Block::Header,
        parent_hash: Block::Hash,
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

        if let Err(error) = runtime_api.submit_vote_extrinsic(parent_hash, signed_vote) {
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
            tracing_unbounded("subspace_signature_signing_stream", 100);

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

        Err(ConsensusError::CannotSign(format!(
            "Farmer didn't sign reward. Key: {:?}",
            public_key.to_raw_vec()
        )))
    }

    /// Builds the proof of time for the block being proposed.
    #[cfg(feature = "pot")]
    async fn build_block_pot(
        &self,
        proof_of_time: &dyn PotConsensusState,
        parent_header: &Block::Header,
        parent_pre_digest: &PreDigest<FarmerPublicKey, FarmerPublicKey>,
        slot_number: SlotNumber,
    ) -> Result<PotPreDigest, PotCreateError> {
        let block_number = *parent_header.number() + One::one();

        proof_of_time
            .get_block_proofs(
                block_number.into(),
                slot_number,
                parent_pre_digest.proof_of_time.as_ref(),
                Some(self.subspace_link.slot_duration().as_duration()),
            )
            .await
            .map(|proofs| {
                let pot_pre_digest = PotPreDigest::new(proofs);
                debug!(
                    target: "subspace",
                    "build_block_pot: block_number={block_number}, parent_slot={}, \
                     slot={slot_number}, PoT=[{pot_pre_digest:?}],  randomness = {:?}",
                    parent_pre_digest.slot, pot_pre_digest.derive_global_randomness()
                );
                pot_pre_digest
            })
            .map_err(|err| {
                debug!(
                    target: "subspace",
                    "build_block_pot: block_number={block_number}, parent_slot={}, \
                     slot={slot_number}, err = {err:?}",
                    parent_pre_digest.slot
                );
                PotCreateError::PotGetBlockProofsError(err)
            })
    }
}

// TODO: Replace with querying parent block header when breaking protocol
/// Extract global randomness for block, given ID of the parent block.
pub(crate) fn extract_global_randomness_for_block<Block, Client>(
    client: &Client,
    parent_hash: Block::Hash,
) -> Result<Randomness, ApiError>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
{
    client
        .runtime_api()
        .global_randomnesses(parent_hash)
        .map(|randomnesses| randomnesses.next.unwrap_or(randomnesses.current))
}

// TODO: Replace with querying parent block header when breaking protocol
/// Extract solution ranges for block and votes, given ID of the parent block.
pub(crate) fn extract_solution_ranges_for_block<Block, Client>(
    client: &Client,
    parent_hash: Block::Hash,
) -> Result<(u64, u64), ApiError>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
{
    client
        .runtime_api()
        .solution_ranges(parent_hash)
        .map(|solution_ranges| {
            (
                solution_ranges.next.unwrap_or(solution_ranges.current),
                solution_ranges
                    .voting_next
                    .unwrap_or(solution_ranges.voting_current),
            )
        })
}

#[cfg(feature = "pot")]
pub(crate) mod pot_slot_worker {
    use super::{info, warn, BlockT, Slot, SlotInfo, SyncOracle};
    use sc_consensus_slots::{InherentDataProviderExt, SlotWorker};
    use sc_proof_of_time::ProofReceiver;
    use sp_api::HeaderT;
    use sp_consensus::SelectChain;
    use sp_inherents::CreateInherentDataProviders;
    use std::time::Duration;

    // This is mostly a combination of substrate start_lot_worker + Slot::next_slot().
    pub async fn start_slot_worker<B, C, W, SO, CIDP, Proof>(
        slot_duration: Duration,
        select_chain: C,
        mut worker: W,
        sync_oracle: SO,
        create_inherent_data_providers: CIDP,
        mut proof_receiver: ProofReceiver,
    ) where
        B: BlockT,
        C: SelectChain<B>,
        W: SlotWorker<B, Proof>,
        SO: SyncOracle + Send,
        CIDP: CreateInherentDataProviders<B, Slot> + Send + 'static,
        CIDP::InherentDataProviders: InherentDataProviderExt + Send,
    {
        let mut last_slot: Slot = 0.into();
        loop {
            // Wait for the next proof to be produced.
            let proof = match proof_receiver.next_proof().await {
                Ok(proof) => proof,
                Err(err) => {
                    warn!(target: "subspace", "Failed to receive proof: {err}");
                    return;
                }
            };

            if sync_oracle.is_major_syncing() {
                info!(target: "subspace", "Skipping proposal slot due to sync.");
                continue;
            }

            let chain_head = match select_chain.best_chain().await {
                Ok(x) => x,
                Err(err) => {
                    warn!(
                        target: "subspace",
                        "Unable to author block in slot {}. No best block header: {err}",
                        proof.slot_number
                    );
                    // Let's retry at the next slot.
                    continue;
                }
            };

            let inherent_data_providers = match create_inherent_data_providers
                .create_inherent_data_providers(chain_head.hash(), proof.slot_number.into())
                .await
            {
                Ok(x) => x,
                Err(err) => {
                    warn!(
                        target: "subspace",
                        "Unable to author block in slot {}. Failure creating inherent \
                        data provider: {err}",
                        proof.slot_number,
                    );
                    // Let's retry at the next slot.
                    continue;
                }
            };

            let slot = inherent_data_providers.slot();

            // Never yield the same slot twice.
            if slot > last_slot {
                last_slot = slot;

                let slot_info = SlotInfo::new(
                    slot,
                    Box::new(inherent_data_providers),
                    slot_duration,
                    chain_head,
                    None,
                );
                let _ = worker.on_slot(slot_info).await;
            } else {
                // This should never happen with PoT.
                warn!(
                    target: "subspace",
                    "Received stale slot: slot = {slot}, last_slot = {last_slot}"
                );
            }
        }
    }
}

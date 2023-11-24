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

//! Block import module.
//!
//! Contains implementation of block import with corresponding checks and notifications.

use crate::archiver::{SegmentHeadersStore, FINALIZATION_DEPTH_IN_SEGMENTS};
use crate::verifier::VerificationError;
use crate::{
    aux_schema, notification, slot_worker, BlockImportingNotification, Error, SubspaceLink,
};
use futures::channel::mpsc;
use futures::StreamExt;
use log::warn;
use lru::LruCache;
use parking_lot::Mutex;
use sc_client_api::backend::AuxStore;
use sc_client_api::BlockBackend;
use sc_consensus::block_import::{
    BlockCheckParams, BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult,
};
use sc_proof_of_time::verifier::PotVerifier;
use sp_api::{ApiExt, BlockT, HeaderT, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::HeaderBackend;
use sp_consensus::Error as ConsensusError;
use sp_consensus_subspace::digests::{
    extract_pre_digest, extract_subspace_digest_items, SubspaceDigestItems,
};
use sp_consensus_subspace::{
    ChainConstants, FarmerPublicKey, FarmerSignature, PotNextSlotInput, SubspaceApi,
    SubspaceJustification,
};
use sp_inherents::{CreateInherentDataProviders, InherentDataProvider};
use sp_runtime::traits::One;
use sp_runtime::Justifications;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{BlockNumber, PublicKey, SectorId};
use subspace_proof_of_space::Table;
use subspace_verification::{calculate_block_weight, PieceCheckParams, VerifySolutionParams};

/// A block-import handler for Subspace.
pub struct SubspaceBlockImport<PosTable, Block, Client, I, CIDP, AS>
where
    Block: BlockT,
{
    inner: I,
    client: Arc<Client>,
    subspace_link: SubspaceLink<Block>,
    create_inherent_data_providers: CIDP,
    chain_constants: ChainConstants,
    segment_headers_store: SegmentHeadersStore<AS>,
    pot_verifier: PotVerifier,
    _pos_table: PhantomData<PosTable>,
}

impl<PosTable, Block, I, Client, CIDP, AS> Clone
    for SubspaceBlockImport<PosTable, Block, Client, I, CIDP, AS>
where
    Block: BlockT,
    I: Clone,
    CIDP: Clone,
{
    fn clone(&self) -> Self {
        SubspaceBlockImport {
            inner: self.inner.clone(),
            client: self.client.clone(),
            subspace_link: self.subspace_link.clone(),
            create_inherent_data_providers: self.create_inherent_data_providers.clone(),
            chain_constants: self.chain_constants,
            segment_headers_store: self.segment_headers_store.clone(),
            pot_verifier: self.pot_verifier.clone(),
            _pos_table: PhantomData,
        }
    }
}

impl<PosTable, Block, Client, I, CIDP, AS> SubspaceBlockImport<PosTable, Block, Client, I, CIDP, AS>
where
    PosTable: Table,
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block> + HeaderBackend<Block> + AuxStore,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey> + ApiExt<Block>,
    CIDP: CreateInherentDataProviders<Block, SubspaceLink<Block>> + Send + Sync + 'static,
    AS: AuxStore + Send + Sync + 'static,
    BlockNumber: From<<<Block as BlockT>::Header as HeaderT>::Number>,
{
    fn new(
        client: Arc<Client>,
        block_import: I,
        subspace_link: SubspaceLink<Block>,
        create_inherent_data_providers: CIDP,
        chain_constants: ChainConstants,
        segment_headers_store: SegmentHeadersStore<AS>,
        pot_verifier: PotVerifier,
    ) -> Self {
        Self {
            client,
            inner: block_import,
            subspace_link,
            create_inherent_data_providers,
            chain_constants,
            segment_headers_store,
            pot_verifier,
            _pos_table: PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn block_import_verification(
        &self,
        block_hash: Block::Hash,
        header: Block::Header,
        extrinsics: Option<Vec<Block::Extrinsic>>,
        root_plot_public_key: &Option<FarmerPublicKey>,
        subspace_digest_items: &SubspaceDigestItems<
            FarmerPublicKey,
            FarmerPublicKey,
            FarmerSignature,
        >,
        justifications: &Option<Justifications>,
        skip_runtime_access: bool,
    ) -> Result<(), Error<Block::Header>> {
        let block_number = *header.number();
        let parent_hash = *header.parent_hash();

        let pre_digest = &subspace_digest_items.pre_digest;
        if let Some(root_plot_public_key) = root_plot_public_key {
            if &pre_digest.solution().public_key != root_plot_public_key {
                // Only root plot public key is allowed.
                return Err(Error::OnlyRootPlotPublicKeyAllowed);
            }
        }

        // Check if farmer's plot is burned.
        if self
            .client
            .runtime_api()
            .is_in_block_list(parent_hash, &pre_digest.solution().public_key)
            .or_else(|error| {
                if skip_runtime_access {
                    Ok(false)
                } else {
                    Err(Error::<Block::Header>::RuntimeApi(error))
                }
            })?
        {
            warn!(
                target: "subspace",
                "Ignoring block with solution provided by farmer in block list: {}",
                pre_digest.solution().public_key
            );

            return Err(Error::FarmerInBlockList(
                pre_digest.solution().public_key.clone(),
            ));
        }

        let parent_header = self
            .client
            .header(parent_hash)?
            .ok_or(Error::ParentUnavailable(parent_hash, block_hash))?;

        let parent_slot = extract_pre_digest(&parent_header).map(|d| d.slot())?;

        // Make sure that slot number is strictly increasing
        if pre_digest.slot() <= parent_slot {
            return Err(Error::SlotMustIncrease(parent_slot, pre_digest.slot()));
        }

        let parent_subspace_digest_items = if block_number.is_one() {
            None
        } else {
            Some(extract_subspace_digest_items::<
                _,
                FarmerPublicKey,
                FarmerPublicKey,
                FarmerSignature,
            >(&parent_header)?)
        };

        let correct_solution_range = if block_number.is_one() {
            slot_worker::extract_solution_ranges_for_block(self.client.as_ref(), parent_hash)?.0
        } else {
            let parent_subspace_digest_items = parent_subspace_digest_items
                .as_ref()
                .expect("Always Some for non-first block; qed");

            match parent_subspace_digest_items.next_solution_range {
                Some(solution_range) => solution_range,
                None => parent_subspace_digest_items.solution_range,
            }
        };

        if subspace_digest_items.solution_range != correct_solution_range {
            return Err(Error::InvalidSolutionRange(block_hash));
        }

        // For PoT justifications we only need to check the seed and number of checkpoints, the rest
        // was already checked during stateless block verification.
        {
            let Some(subspace_justification) = justifications
                .as_ref()
                .and_then(|justifications| {
                    justifications
                        .iter()
                        .find_map(SubspaceJustification::try_from_justification)
                })
                .transpose()
                .map_err(Error::InvalidSubspaceJustification)?
            else {
                return Err(Error::MissingSubspaceJustification);
            };

            let SubspaceJustification::PotCheckpoints { seed, checkpoints } =
                subspace_justification;

            let future_slot = pre_digest.slot() + self.chain_constants.block_authoring_delay();

            if block_number.is_one() {
                // In case of first block seed must match genesis seed
                if seed != self.pot_verifier.genesis_seed() {
                    return Err(Error::InvalidSubspaceJustificationContents);
                }

                // Number of checkpoints must match future slot number
                if checkpoints.len() as u64 != *future_slot {
                    return Err(Error::InvalidSubspaceJustificationContents);
                }
            } else {
                let parent_subspace_digest_items = parent_subspace_digest_items
                    .as_ref()
                    .expect("Always Some for non-first block; qed");

                let parent_future_slot = parent_slot + self.chain_constants.block_authoring_delay();

                let correct_input_parameters = PotNextSlotInput::derive(
                    subspace_digest_items.pot_slot_iterations,
                    parent_future_slot,
                    parent_subspace_digest_items
                        .pre_digest
                        .pot_info()
                        .future_proof_of_time(),
                    &subspace_digest_items.pot_parameters_change,
                );

                if seed != correct_input_parameters.seed {
                    return Err(Error::InvalidSubspaceJustificationContents);
                }

                // Number of checkpoints must match number of proofs that were not yet seen on chain
                if checkpoints.len() as u64 != (*future_slot - *parent_future_slot) {
                    return Err(Error::InvalidSubspaceJustificationContents);
                }
            }
        }

        let sector_id = SectorId::new(
            PublicKey::from(&pre_digest.solution().public_key).hash(),
            pre_digest.solution().sector_index,
        );

        // TODO: Below `skip_runtime_access` has no impact on this, but ideally it
        //  should (though we don't support fast sync yet, so doesn't matter in
        //  practice)
        let max_pieces_in_sector = self
            .client
            .runtime_api()
            .max_pieces_in_sector(parent_hash)?;
        let piece_index = sector_id.derive_piece_index(
            pre_digest.solution().piece_offset,
            pre_digest.solution().history_size,
            max_pieces_in_sector,
            self.chain_constants.recent_segments(),
            self.chain_constants.recent_history_fraction(),
        );
        let segment_index = piece_index.segment_index();

        let segment_commitment = self
            .segment_headers_store
            .get_segment_header(segment_index)
            .map(|segment_header| segment_header.segment_commitment())
            .ok_or(Error::SegmentCommitmentNotFound(segment_index))?;

        let sector_expiration_check_segment_commitment = self
            .segment_headers_store
            .get_segment_header(
                subspace_digest_items
                    .pre_digest
                    .solution()
                    .history_size
                    .sector_expiration_check(self.chain_constants.min_sector_lifetime())
                    .ok_or(Error::InvalidHistorySize)?
                    .segment_index(),
            )
            .map(|segment_header| segment_header.segment_commitment());

        // Piece is not checked during initial block verification because it requires access to
        // segment header and runtime, check it now.
        subspace_verification::verify_solution::<PosTable, _, _>(
            pre_digest.solution(),
            // Slot was already checked during initial block verification
            pre_digest.slot().into(),
            &VerifySolutionParams {
                proof_of_time: subspace_digest_items.pre_digest.pot_info().proof_of_time(),
                solution_range: subspace_digest_items.solution_range,
                piece_check_params: Some(PieceCheckParams {
                    max_pieces_in_sector,
                    segment_commitment,
                    recent_segments: self.chain_constants.recent_segments(),
                    recent_history_fraction: self.chain_constants.recent_history_fraction(),
                    min_sector_lifetime: self.chain_constants.min_sector_lifetime(),
                    // TODO: Below `skip_runtime_access` has no impact on this, but ideally it
                    //  should (though we don't support fast sync yet, so doesn't matter in
                    //  practice)
                    current_history_size: self.client.runtime_api().history_size(parent_hash)?,
                    sector_expiration_check_segment_commitment,
                }),
            },
            &self.subspace_link.kzg,
        )
        .map_err(|error| VerificationError::VerificationError(pre_digest.slot(), error))?;

        if !skip_runtime_access {
            // If the body is passed through, we need to use the runtime to check that the
            // internally-set timestamp in the inherents actually matches the slot set in the seal
            // and segment headers in the inherents are set correctly.
            if let Some(extrinsics) = extrinsics {
                let create_inherent_data_providers = self
                    .create_inherent_data_providers
                    .create_inherent_data_providers(parent_hash, self.subspace_link.clone())
                    .await
                    .map_err(|error| Error::Client(sp_blockchain::Error::from(error)))?;

                let inherent_data = create_inherent_data_providers
                    .create_inherent_data()
                    .await
                    .map_err(Error::CreateInherents)?;

                let inherent_res = self.client.runtime_api().check_inherents(
                    parent_hash,
                    Block::new(header, extrinsics),
                    inherent_data,
                )?;

                if !inherent_res.ok() {
                    for (i, e) in inherent_res.into_errors() {
                        match create_inherent_data_providers
                            .try_handle_error(&i, &e)
                            .await
                        {
                            Some(res) => res.map_err(Error::CheckInherents)?,
                            None => return Err(Error::CheckInherentsUnhandled(i)),
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl<PosTable, Block, Client, Inner, CIDP, AS> BlockImport<Block>
    for SubspaceBlockImport<PosTable, Block, Client, Inner, CIDP, AS>
where
    PosTable: Table,
    Block: BlockT,
    Inner: BlockImport<Block, Error = ConsensusError> + Send + Sync,
    Inner::Error: Into<ConsensusError>,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + AuxStore
        + Send
        + Sync,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey> + ApiExt<Block>,
    CIDP: CreateInherentDataProviders<Block, SubspaceLink<Block>> + Send + Sync + 'static,
    AS: AuxStore + Send + Sync + 'static,
    BlockNumber: From<<<Block as BlockT>::Header as HeaderT>::Number>,
{
    type Error = ConsensusError;

    async fn import_block(
        &mut self,
        mut block: BlockImportParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        let block_hash = block.post_hash();
        let block_number = *block.header.number();

        // Early exit if block already in chain
        match self.client.status(block_hash) {
            Ok(sp_blockchain::BlockStatus::InChain) => {
                block.fork_choice = Some(ForkChoiceStrategy::Custom(false));
                return self.inner.import_block(block).await.map_err(Into::into);
            }
            Ok(sp_blockchain::BlockStatus::Unknown) => {}
            Err(error) => return Err(ConsensusError::ClientImport(error.to_string())),
        }

        let subspace_digest_items = extract_subspace_digest_items(&block.header)
            .map_err(|error| ConsensusError::ClientImport(error.to_string()))?;
        let skip_execution_checks = block.state_action.skip_execution_checks();

        let root_plot_public_key = self
            .client
            .runtime_api()
            .root_plot_public_key(*block.header.parent_hash())
            .map_err(Error::<Block::Header>::RuntimeApi)
            .map_err(|e| ConsensusError::ClientImport(e.to_string()))?;

        self.block_import_verification(
            block_hash,
            block.header.clone(),
            block.body.clone(),
            &root_plot_public_key,
            &subspace_digest_items,
            &block.justifications,
            skip_execution_checks,
        )
        .await
        .map_err(|error| ConsensusError::ClientImport(error.to_string()))?;

        let parent_weight = if block_number.is_one() {
            0
        } else {
            aux_schema::load_block_weight(self.client.as_ref(), block.header.parent_hash())
                .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
                .ok_or_else(|| {
                    ConsensusError::ClientImport(
                        Error::<Block::Header>::ParentBlockNoAssociatedWeight(block_hash)
                            .to_string(),
                    )
                })?
        };

        let added_weight = calculate_block_weight(subspace_digest_items.solution_range);
        let total_weight = parent_weight + added_weight;

        aux_schema::write_block_weight(block_hash, total_weight, |values| {
            block
                .auxiliary
                .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
        });

        for (&segment_index, segment_commitment) in &subspace_digest_items.segment_commitments {
            let found_segment_commitment = self
                .segment_headers_store
                .get_segment_header(segment_index)
                .ok_or_else(|| {
                    ConsensusError::ClientImport(format!(
                        "Segment header for index {segment_index} not found"
                    ))
                })?
                .segment_commitment();

            if &found_segment_commitment != segment_commitment {
                warn!(
                    target: "subspace",
                    "Different segment commitment for segment index {} was found in storage, \
                    likely fork below archiving point. expected {:?}, found {:?}",
                    segment_index,
                    segment_commitment,
                    found_segment_commitment
                );
                return Err(ConsensusError::ClientImport(
                    Error::<Block::Header>::DifferentSegmentCommitment(segment_index).to_string(),
                ));
            }
        }

        // The fork choice rule is that we pick the heaviest chain (i.e. smallest solution range),
        // if there's a tie we go with the longest chain
        let fork_choice = {
            let info = self.client.info();

            let last_best_weight = if &info.best_hash == block.header.parent_hash() {
                // the parent=genesis case is already covered for loading parent weight, so we don't
                // need to cover again here
                parent_weight
            } else {
                aux_schema::load_block_weight(&*self.client, info.best_hash)
                    .map_err(|e| ConsensusError::ChainLookup(e.to_string()))?
                    .ok_or_else(|| {
                        ConsensusError::ChainLookup(
                            "No block weight for parent header.".to_string(),
                        )
                    })?
            };

            ForkChoiceStrategy::Custom(total_weight > last_best_weight)
        };
        block.fork_choice = Some(fork_choice);

        let (acknowledgement_sender, mut acknowledgement_receiver) = mpsc::channel(0);

        self.subspace_link
            .block_importing_notification_sender
            .notify(move || BlockImportingNotification {
                block_number,
                acknowledgement_sender,
            });

        while acknowledgement_receiver.next().await.is_some() {
            // Wait for all the acknowledgements to finish.
        }

        self.inner.import_block(block).await
    }

    async fn check_block(
        &self,
        block: BlockCheckParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        self.inner.check_block(block).await.map_err(Into::into)
    }
}

/// Produce a Subspace block-import object to be used later on in the construction of an
/// import-queue.
///
/// Also returns a link object used to correctly instantiate the import queue and background worker.
#[allow(clippy::type_complexity)]
pub fn block_import<PosTable, Client, Block, I, CIDP, AS>(
    block_import_inner: I,
    client: Arc<Client>,
    kzg: Kzg,
    create_inherent_data_providers: CIDP,
    segment_headers_store: SegmentHeadersStore<AS>,
    pot_verifier: PotVerifier,
) -> Result<
    (
        SubspaceBlockImport<PosTable, Block, Client, I, CIDP, AS>,
        SubspaceLink<Block>,
    ),
    sp_blockchain::Error,
>
where
    PosTable: Table,
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block> + HeaderBackend<Block> + AuxStore,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey>,
    CIDP: CreateInherentDataProviders<Block, SubspaceLink<Block>> + Send + Sync + 'static,
    AS: AuxStore + Send + Sync + 'static,
    BlockNumber: From<<<Block as BlockT>::Header as HeaderT>::Number>,
{
    let (new_slot_notification_sender, new_slot_notification_stream) =
        notification::channel("subspace_new_slot_notification_stream");
    let (reward_signing_notification_sender, reward_signing_notification_stream) =
        notification::channel("subspace_reward_signing_notification_stream");
    let (archived_segment_notification_sender, archived_segment_notification_stream) =
        notification::channel("subspace_archived_segment_notification_stream");
    let (block_importing_notification_sender, block_importing_notification_stream) =
        notification::channel("subspace_block_importing_notification_stream");

    let chain_constants = client
        .runtime_api()
        .chain_constants(client.info().best_hash)?;

    let link = SubspaceLink {
        new_slot_notification_sender,
        new_slot_notification_stream,
        reward_signing_notification_sender,
        reward_signing_notification_stream,
        archived_segment_notification_sender,
        archived_segment_notification_stream,
        block_importing_notification_sender,
        block_importing_notification_stream,
        // TODO: Consider making `confirmation_depth_k` non-zero
        segment_headers: Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(
                (FINALIZATION_DEPTH_IN_SEGMENTS + 1)
                    .max(chain_constants.confirmation_depth_k() as usize),
            )
            .expect("Confirmation depth of zero is not supported"),
        ))),
        kzg,
    };

    let import = SubspaceBlockImport::new(
        client,
        block_import_inner,
        link.clone(),
        create_inherent_data_providers,
        chain_constants,
        segment_headers_store,
        pot_verifier,
    );

    Ok((import, link))
}

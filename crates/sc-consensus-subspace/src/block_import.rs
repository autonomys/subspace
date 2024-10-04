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

//! Block import for Subspace, which includes stateful verification and corresponding notifications.
//!
//! In most cases block import happens after stateless block verification using [`verifier`](crate::verifier),
//! the only exception to that is locally authored blocks.
//!
//! Since [`verifier`](crate::verifier) is stateless, the remaining checks in block import are those
//! that require presence of the parent block or its state in the database. Specifically for Proof
//! of Time individual checkpoints are assumed to be checked already and only PoT inputs need to be
//! checked to correspond to the state of the parent block.
//!
//! After all checks and right before importing the block notification ([`SubspaceLink::block_importing_notification_stream`])
//! will be sent that [`archiver`](crate::archiver) among other things is subscribed to.

use crate::archiver::SegmentHeadersStore;
use crate::verifier::VerificationError;
use crate::{aux_schema, slot_worker, SubspaceLink};
use futures::channel::mpsc;
use futures::StreamExt;
use sc_client_api::backend::AuxStore;
use sc_client_api::BlockBackend;
use sc_consensus::block_import::{
    BlockCheckParams, BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult,
};
use sc_consensus::StateAction;
use sc_proof_of_time::verifier::PotVerifier;
use sp_api::{ApiError, ApiExt, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::HeaderBackend;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{
    extract_pre_digest, extract_subspace_digest_items, SubspaceDigestItems,
};
use sp_consensus_subspace::{PotNextSlotInput, SubspaceApi, SubspaceJustification};
use sp_inherents::{CreateInherentDataProviders, InherentDataProvider};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor, One};
use sp_runtime::Justifications;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::sectors::SectorId;
use subspace_core_primitives::segments::{HistorySize, SegmentHeader, SegmentIndex};
use subspace_core_primitives::solutions::SolutionRange;
use subspace_core_primitives::{BlockNumber, PublicKey};
use subspace_proof_of_space::Table;
use subspace_verification::{calculate_block_weight, PieceCheckParams, VerifySolutionParams};
use tracing::warn;

/// Notification with number of the block that is about to be imported and acknowledgement sender
/// that can be used to pause block production if desired.
#[derive(Debug, Clone)]
pub struct BlockImportingNotification<Block>
where
    Block: BlockT,
{
    /// Block number
    pub block_number: NumberFor<Block>,
    /// Sender for pausing the block import when operator is not fast enough to process
    /// the consensus block.
    pub acknowledgement_sender: mpsc::Sender<()>,
}
use subspace_verification::Error as VerificationPrimitiveError;

/// Errors encountered by the Subspace authorship task.
#[derive(Debug, thiserror::Error)]
pub enum Error<Header: HeaderT> {
    /// Inner block import error
    #[error("Inner block import error: {0}")]
    InnerBlockImportError(#[from] sp_consensus::Error),
    /// Error during digest item extraction
    #[error("Digest item error: {0}")]
    DigestItemError(#[from] sp_consensus_subspace::digests::Error),
    /// Parent unavailable. Cannot import
    #[error("Parent ({0}) of {1} unavailable. Cannot import")]
    ParentUnavailable(Header::Hash, Header::Hash),
    /// Genesis block unavailable. Cannot import
    #[error("Genesis block unavailable. Cannot import")]
    GenesisUnavailable,
    /// Slot number must increase
    #[error("Slot number must increase: parent slot: {0}, this slot: {1}")]
    SlotMustIncrease(Slot, Slot),
    /// Header has a bad seal
    #[error("Header {0:?} has a bad seal")]
    HeaderBadSeal(Header::Hash),
    /// Header is unsealed
    #[error("Header {0:?} is unsealed")]
    HeaderUnsealed(Header::Hash),
    /// Bad reward signature
    #[error("Bad reward signature on {0:?}")]
    BadRewardSignature(Header::Hash),
    /// Missing Subspace justification
    #[error("Missing Subspace justification")]
    MissingSubspaceJustification,
    /// Invalid Subspace justification
    #[error("Invalid Subspace justification: {0}")]
    InvalidSubspaceJustification(codec::Error),
    /// Invalid Subspace justification contents
    #[error("Invalid Subspace justification contents")]
    InvalidSubspaceJustificationContents,
    /// Invalid proof of time
    #[error("Invalid proof of time")]
    InvalidProofOfTime,
    /// Solution is outside of solution range
    #[error(
        "Solution distance {solution_distance} is outside of solution range \
        {half_solution_range} (half of actual solution range) for slot {slot}"
    )]
    OutsideOfSolutionRange {
        /// Time slot
        slot: Slot,
        /// Half of solution range
        half_solution_range: SolutionRange,
        /// Solution distance
        solution_distance: SolutionRange,
    },
    /// Invalid proof of space
    #[error("Invalid proof of space")]
    InvalidProofOfSpace,
    /// Invalid audit chunk offset
    #[error("Invalid audit chunk offset")]
    InvalidAuditChunkOffset,
    /// Invalid chunk
    #[error("Invalid chunk: {0}")]
    InvalidChunk(String),
    /// Invalid chunk witness
    #[error("Invalid chunk witness")]
    InvalidChunkWitness,
    /// Piece verification failed
    #[error("Piece verification failed")]
    InvalidPieceOffset {
        /// Time slot
        slot: Slot,
        /// Index of the piece that failed verification
        piece_offset: u16,
        /// How many pieces one sector is supposed to contain (max)
        max_pieces_in_sector: u16,
    },
    /// Piece verification failed
    #[error("Piece verification failed for slot {0}")]
    InvalidPiece(Slot),
    /// Block has invalid associated solution range
    #[error("Invalid solution range for block {0}")]
    InvalidSolutionRange(Header::Hash),
    /// Invalid set of segment headers
    #[error("Invalid set of segment headers")]
    InvalidSetOfSegmentHeaders,
    /// Stored segment header extrinsic was not found
    #[error("Stored segment header extrinsic was not found: {0:?}")]
    SegmentHeadersExtrinsicNotFound(Vec<SegmentHeader>),
    /// Segment header not found
    #[error("Segment header for index {0} not found")]
    SegmentHeaderNotFound(SegmentIndex),
    /// Different segment commitment found
    #[error(
        "Different segment commitment for segment index {0} was found in storage, likely fork \
        below archiving point"
    )]
    DifferentSegmentCommitment(SegmentIndex),
    /// Segment commitment not found
    #[error("Segment commitment for segment index {0} not found")]
    SegmentCommitmentNotFound(SegmentIndex),
    /// Sector expired
    #[error("Sector expired")]
    SectorExpired {
        /// Expiration history size
        expiration_history_size: HistorySize,
        /// Current history size
        current_history_size: HistorySize,
    },
    /// Invalid history size
    #[error("Invalid history size")]
    InvalidHistorySize,
    /// Only root plot public key is allowed
    #[error("Only root plot public key is allowed")]
    OnlyRootPlotPublicKeyAllowed,
    /// Check inherents error
    #[error("Checking inherents failed: {0}")]
    CheckInherents(sp_inherents::Error),
    /// Unhandled check inherents error
    #[error("Checking inherents unhandled error: {}", String::from_utf8_lossy(.0))]
    CheckInherentsUnhandled(sp_inherents::InherentIdentifier),
    /// Create inherents error.
    #[error("Creating inherents failed: {0}")]
    CreateInherents(sp_inherents::Error),
    /// Client error
    #[error(transparent)]
    Client(#[from] sp_blockchain::Error),
    /// Runtime Api error.
    #[error(transparent)]
    RuntimeApi(#[from] ApiError),
}

impl<Header> From<VerificationError<Header>> for Error<Header>
where
    Header: HeaderT,
{
    #[inline]
    fn from(error: VerificationError<Header>) -> Self {
        match error {
            VerificationError::HeaderBadSeal(block_hash) => Error::HeaderBadSeal(block_hash),
            VerificationError::HeaderUnsealed(block_hash) => Error::HeaderUnsealed(block_hash),
            VerificationError::BadRewardSignature(block_hash) => {
                Error::BadRewardSignature(block_hash)
            }
            VerificationError::MissingSubspaceJustification => Error::MissingSubspaceJustification,
            VerificationError::InvalidSubspaceJustification(error) => {
                Error::InvalidSubspaceJustification(error)
            }
            VerificationError::InvalidSubspaceJustificationContents => {
                Error::InvalidSubspaceJustificationContents
            }
            VerificationError::InvalidProofOfTime => Error::InvalidProofOfTime,
            VerificationError::VerificationError(slot, error) => match error {
                VerificationPrimitiveError::InvalidPieceOffset {
                    piece_offset,
                    max_pieces_in_sector,
                } => Error::InvalidPieceOffset {
                    slot,
                    piece_offset,
                    max_pieces_in_sector,
                },
                VerificationPrimitiveError::InvalidPiece => Error::InvalidPiece(slot),
                VerificationPrimitiveError::OutsideSolutionRange {
                    half_solution_range,
                    solution_distance,
                } => Error::OutsideOfSolutionRange {
                    slot,
                    half_solution_range,
                    solution_distance,
                },
                VerificationPrimitiveError::InvalidProofOfSpace => Error::InvalidProofOfSpace,
                VerificationPrimitiveError::InvalidAuditChunkOffset => {
                    Error::InvalidAuditChunkOffset
                }
                VerificationPrimitiveError::InvalidChunk(error) => Error::InvalidChunk(error),
                VerificationPrimitiveError::InvalidChunkWitness => Error::InvalidChunkWitness,
                VerificationPrimitiveError::SectorExpired {
                    expiration_history_size,
                    current_history_size,
                } => Error::SectorExpired {
                    expiration_history_size,
                    current_history_size,
                },
                VerificationPrimitiveError::InvalidHistorySize => Error::InvalidHistorySize,
            },
        }
    }
}

impl<Header> From<Error<Header>> for String
where
    Header: HeaderT,
{
    #[inline]
    fn from(error: Error<Header>) -> String {
        error.to_string()
    }
}

/// A block-import handler for Subspace.
pub struct SubspaceBlockImport<PosTable, Block, Client, I, CIDP, AS>
where
    Block: BlockT,
{
    inner: I,
    client: Arc<Client>,
    subspace_link: SubspaceLink<Block>,
    create_inherent_data_providers: CIDP,
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
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, PublicKey> + ApiExt<Block>,
    CIDP: CreateInherentDataProviders<Block, ()> + Send + Sync + 'static,
    AS: AuxStore + Send + Sync + 'static,
    BlockNumber: From<<Block::Header as HeaderT>::Number>,
{
    /// Produce a Subspace block-import object to be used later on in the construction of an import-queue.
    pub fn new(
        client: Arc<Client>,
        block_import: I,
        subspace_link: SubspaceLink<Block>,
        create_inherent_data_providers: CIDP,
        segment_headers_store: SegmentHeadersStore<AS>,
        pot_verifier: PotVerifier,
    ) -> Self {
        Self {
            client,
            inner: block_import,
            subspace_link,
            create_inherent_data_providers,
            segment_headers_store,
            pot_verifier,
            _pos_table: PhantomData,
        }
    }

    async fn block_import_verification(
        &self,
        block_hash: Block::Hash,
        header: Block::Header,
        extrinsics: Option<Vec<Block::Extrinsic>>,
        root_plot_public_key: &Option<PublicKey>,
        subspace_digest_items: &SubspaceDigestItems<PublicKey>,
        justifications: &Option<Justifications>,
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
            Some(extract_subspace_digest_items::<_, PublicKey>(
                &parent_header,
            )?)
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

        let chain_constants = self.subspace_link.chain_constants();

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

            let future_slot = pre_digest.slot() + chain_constants.block_authoring_delay();

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

                let parent_future_slot = parent_slot + chain_constants.block_authoring_delay();

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
            pre_digest.solution().public_key.hash(),
            pre_digest.solution().sector_index,
            pre_digest.solution().history_size,
        );

        let max_pieces_in_sector = self
            .client
            .runtime_api()
            .max_pieces_in_sector(parent_hash)?;
        let piece_index = sector_id.derive_piece_index(
            pre_digest.solution().piece_offset,
            pre_digest.solution().history_size,
            max_pieces_in_sector,
            chain_constants.recent_segments(),
            chain_constants.recent_history_fraction(),
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
                    .sector_expiration_check(chain_constants.min_sector_lifetime())
                    .ok_or(Error::InvalidHistorySize)?
                    .segment_index(),
            )
            .map(|segment_header| segment_header.segment_commitment());

        // Piece is not checked during initial block verification because it requires access to
        // segment header and runtime, check it now.
        subspace_verification::verify_solution::<PosTable, _>(
            pre_digest.solution(),
            // Slot was already checked during initial block verification
            pre_digest.slot().into(),
            &VerifySolutionParams {
                proof_of_time: subspace_digest_items.pre_digest.pot_info().proof_of_time(),
                solution_range: subspace_digest_items.solution_range,
                piece_check_params: Some(PieceCheckParams {
                    max_pieces_in_sector,
                    segment_commitment,
                    recent_segments: chain_constants.recent_segments(),
                    recent_history_fraction: chain_constants.recent_history_fraction(),
                    min_sector_lifetime: chain_constants.min_sector_lifetime(),
                    current_history_size: self.client.runtime_api().history_size(parent_hash)?,
                    sector_expiration_check_segment_commitment,
                }),
            },
            &self.subspace_link.kzg,
        )
        .map_err(|error| VerificationError::VerificationError(pre_digest.slot(), error))?;

        // If the body is passed through, we need to use the runtime to check that the
        // internally-set timestamp in the inherents actually matches the slot set in the seal
        // and segment headers in the inherents are set correctly.
        if let Some(extrinsics) = extrinsics {
            let create_inherent_data_providers = self
                .create_inherent_data_providers
                .create_inherent_data_providers(parent_hash, ())
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

        Ok(())
    }
}

#[async_trait::async_trait]
impl<PosTable, Block, Client, Inner, CIDP, AS> BlockImport<Block>
    for SubspaceBlockImport<PosTable, Block, Client, Inner, CIDP, AS>
where
    PosTable: Table,
    Block: BlockT,
    Inner: BlockImport<Block, Error = sp_consensus::Error> + Send + Sync,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + AuxStore
        + Send
        + Sync,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, PublicKey> + ApiExt<Block>,
    CIDP: CreateInherentDataProviders<Block, ()> + Send + Sync + 'static,
    AS: AuxStore + Send + Sync + 'static,
    BlockNumber: From<<Block::Header as HeaderT>::Number>,
{
    type Error = Error<Block::Header>;

    async fn import_block(
        &self,
        mut block: BlockImportParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        let block_hash = block.post_hash();
        let block_number = *block.header.number();

        // Early exit if block already in chain
        match self.client.status(block_hash)? {
            sp_blockchain::BlockStatus::InChain => {
                block.fork_choice = Some(ForkChoiceStrategy::Custom(false));
                return self
                    .inner
                    .import_block(block)
                    .await
                    .map_err(Error::InnerBlockImportError);
            }
            sp_blockchain::BlockStatus::Unknown => {}
        }

        let subspace_digest_items = extract_subspace_digest_items(&block.header)?;

        // Only do import verification if we do not have the state already. If state needs to be
        // applied this means verification and execution already happened before and doesn't need to
        // be done again here (often can't because parent block would be missing in special sync
        // modes).
        if !matches!(block.state_action, StateAction::ApplyChanges(_)) {
            let root_plot_public_key = self
                .client
                .runtime_api()
                .root_plot_public_key(*block.header.parent_hash())?;

            self.block_import_verification(
                block_hash,
                block.header.clone(),
                block.body.clone(),
                &root_plot_public_key,
                &subspace_digest_items,
                &block.justifications,
            )
            .await?;
        }

        let parent_weight = if block_number.is_one() {
            0
        } else {
            // Parent block weight might be missing in special sync modes where block is imported in
            // the middle of the blockchain history directly
            aux_schema::load_block_weight(self.client.as_ref(), block.header.parent_hash())?
                .unwrap_or_default()
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
                .ok_or_else(|| Error::SegmentHeaderNotFound(segment_index))?
                .segment_commitment();

            if &found_segment_commitment != segment_commitment {
                warn!(
                    "Different segment commitment for segment index {} was found in storage, \
                    likely fork below archiving point. expected {:?}, found {:?}",
                    segment_index, segment_commitment, found_segment_commitment
                );
                return Err(Error::DifferentSegmentCommitment(segment_index));
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
                // Best block weight might be missing in special sync modes where block is imported
                // in the middle of the blockchain history right after genesis
                aux_schema::load_block_weight(&*self.client, info.best_hash)?.unwrap_or_default()
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

        self.inner
            .import_block(block)
            .await
            .map_err(Error::InnerBlockImportError)
    }

    async fn check_block(
        &self,
        block: BlockCheckParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        self.inner.check_block(block).await.map_err(Into::into)
    }
}

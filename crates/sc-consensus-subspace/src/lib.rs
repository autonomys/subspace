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

#![doc = include_str!("../README.md")]
#![feature(const_option, let_chains, try_blocks)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod archiver;
pub mod aux_schema;
pub mod block_import;
pub mod notification;
mod slot_worker;
#[cfg(test)]
mod tests;
pub mod verifier;

use crate::archiver::SegmentHeadersStore;
use crate::notification::{SubspaceNotificationSender, SubspaceNotificationStream};
use crate::slot_worker::SubspaceSlotWorker;
pub use crate::slot_worker::SubspaceSyncOracle;
use crate::verifier::VerificationError;
use futures::channel::mpsc;
use log::{info, warn};
use lru::LruCache;
use parking_lot::Mutex;
use sc_client_api::backend::AuxStore;
use sc_client_api::{BlockchainEvents, ProvideUncles};
use sc_consensus::{JustificationSyncLink, SharedBlockImport};
use sc_consensus_slots::{BackoffAuthoringBlocksStrategy, SlotProportion};
use sc_proof_of_time::source::PotSlotInfoStream;
use sc_proof_of_time::verifier::PotVerifier;
use sc_telemetry::TelemetryHandle;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::{ApiError, BlockT, HeaderT, NumberFor, ProvideRuntimeApi};
use sp_blockchain::{Error as ClientError, HeaderBackend, HeaderMetadata};
use sp_consensus::{Environment, Error as ConsensusError, Proposer, SelectChain, SyncOracle};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::Error as DigestError;
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature, SubspaceApi};
use sp_core::H256;
use sp_inherents::CreateInherentDataProviders;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use subspace_archiving::archiver::NewArchivedSegment;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    BlockNumber, HistorySize, Randomness, SegmentHeader, SegmentIndex, Solution, SolutionRange,
    REWARD_SIGNING_CONTEXT,
};
use subspace_proof_of_space::Table;
use subspace_verification::Error as VerificationPrimitiveError;

/// Information about new slot that just arrived
#[derive(Debug, Copy, Clone)]
pub struct NewSlotInfo {
    /// Slot
    pub slot: Slot,
    /// Global randomness
    pub global_randomness: Randomness,
    /// Acceptable solution range for block authoring
    pub solution_range: SolutionRange,
    /// Acceptable solution range for voting
    pub voting_solution_range: SolutionRange,
}

/// New slot notification with slot information and sender for solution for the slot.
#[derive(Debug, Clone)]
pub struct NewSlotNotification {
    /// New slot information.
    pub new_slot_info: NewSlotInfo,
    /// Sender that can be used to send solutions for the slot.
    pub solution_sender: mpsc::Sender<Solution<FarmerPublicKey, FarmerPublicKey>>,
}

/// Notification with a hash that needs to be signed to receive reward and sender for signature.
#[derive(Debug, Clone)]
pub struct RewardSigningNotification {
    /// Hash to be signed.
    pub hash: H256,
    /// Public key of the plot identity that should create signature.
    pub public_key: FarmerPublicKey,
    /// Sender that can be used to send signature for the header.
    pub signature_sender: TracingUnboundedSender<FarmerSignature>,
}

/// Notification with block header hash that needs to be signed and sender for signature.
#[derive(Debug, Clone)]
pub struct ArchivedSegmentNotification {
    /// Archived segment.
    pub archived_segment: Arc<NewArchivedSegment>,
    /// Sender that signified the fact of receiving archived segment by farmer.
    ///
    /// This must be used to send a message or else block import pipeline will get stuck.
    pub acknowledgement_sender: TracingUnboundedSender<()>,
}

/// Notification with number of the block that is about to be imported and acknowledgement sender
/// that can be used to pause block production if desired.
///
/// NOTE: Block is not fully imported yet!
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

/// Errors encountered by the Subspace authorship task.
#[derive(Debug, thiserror::Error)]
pub enum Error<Header: HeaderT> {
    /// Error during digest item extraction
    #[error("Digest item error: {0}")]
    DigestItemError(#[from] DigestError),
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
    /// Parent block has no associated weight
    #[error("Parent block of {0} has no associated weight")]
    ParentBlockNoAssociatedWeight(Header::Hash),
    /// Block has invalid associated solution range
    #[error("Invalid solution range for block {0}")]
    InvalidSolutionRange(Header::Hash),
    /// Invalid set of segment headers
    #[error("Invalid set of segment headers")]
    InvalidSetOfSegmentHeaders,
    /// Stored segment header extrinsic was not found
    #[error("Stored segment header extrinsic was not found: {0:?}")]
    SegmentHeadersExtrinsicNotFound(Vec<SegmentHeader>),
    /// Different segment commitment found
    #[error(
        "Different segment commitment for segment index {0} was found in storage, likely fork \
        below archiving point"
    )]
    DifferentSegmentCommitment(SegmentIndex),
    /// Farmer in block list
    #[error("Farmer {0} is in block list")]
    FarmerInBlockList(FarmerPublicKey),
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

/// Parameters for Subspace.
pub struct SubspaceParams<Block, Client, SC, E, SO, L, CIDP, BS, AS>
where
    Block: BlockT,
    SO: SyncOracle + Send + Sync,
{
    /// The client to use
    pub client: Arc<Client>,

    /// The SelectChain Strategy
    pub select_chain: SC,

    /// The environment we are producing blocks for.
    pub env: E,

    /// The underlying block-import object to supply our produced blocks to.
    /// This must be a `SubspaceBlockImport` or a wrapper of it, otherwise
    /// critical consensus logic will be omitted.
    pub block_import: SharedBlockImport<Block>,

    /// A sync oracle
    pub sync_oracle: SubspaceSyncOracle<SO>,

    /// Hook into the sync module to control the justification sync process.
    pub justification_sync_link: L,

    /// Something that can create the inherent data providers.
    pub create_inherent_data_providers: CIDP,

    /// Force authoring of blocks even if we are offline
    pub force_authoring: bool,

    /// Strategy and parameters for backing off block production.
    pub backoff_authoring_blocks: Option<BS>,

    /// The source of timestamps for relative slots
    pub subspace_link: SubspaceLink<Block>,

    /// Persistent storage of segment headers
    pub segment_headers_store: SegmentHeadersStore<AS>,

    /// The proportion of the slot dedicated to proposing.
    ///
    /// The block proposing will be limited to this proportion of the slot from the starting of the
    /// slot. However, the proposing can still take longer when there is some lenience factor applied,
    /// because there were no blocks produced for some slots.
    pub block_proposal_slot_portion: SlotProportion,

    /// The maximum proportion of the slot dedicated to proposing with any lenience factor applied
    /// due to no blocks being produced.
    pub max_block_proposal_slot_portion: Option<SlotProportion>,

    /// Handle use to report telemetries.
    pub telemetry: Option<TelemetryHandle>,

    /// The offchain transaction pool factory.
    ///
    /// Will be used when sending equivocation reports and votes.
    pub offchain_tx_pool_factory: OffchainTransactionPoolFactory<Block>,

    /// Proof of time verifier
    pub pot_verifier: PotVerifier,

    /// Stream with proof of time slots.
    pub pot_slot_info_stream: PotSlotInfoStream,
}

/// Start the Subspace worker.
pub fn start_subspace<PosTable, Block, Client, SC, E, SO, CIDP, BS, L, AS, Error>(
    SubspaceParams {
        client,
        select_chain,
        env,
        block_import,
        sync_oracle,
        justification_sync_link,
        create_inherent_data_providers,
        force_authoring,
        backoff_authoring_blocks,
        subspace_link,
        segment_headers_store,
        block_proposal_slot_portion,
        max_block_proposal_slot_portion,
        telemetry,
        offchain_tx_pool_factory,
        pot_verifier,
        pot_slot_info_stream,
    }: SubspaceParams<Block, Client, SC, E, SO, L, CIDP, BS, AS>,
) -> Result<SubspaceWorker, sp_consensus::Error>
where
    PosTable: Table,
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + ProvideUncles<Block>
        + BlockchainEvents<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = ClientError>
        + AuxStore
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    SC: SelectChain<Block> + 'static,
    E: Environment<Block, Error = Error> + Send + Sync + 'static,
    E::Proposer: Proposer<Block, Error = Error>,
    SO: SyncOracle + Send + Sync + Clone + 'static,
    L: JustificationSyncLink<Block> + 'static,
    CIDP: CreateInherentDataProviders<Block, ()> + Send + Sync + 'static,
    BS: BackoffAuthoringBlocksStrategy<NumberFor<Block>> + Send + Sync + 'static,
    AS: AuxStore + Send + Sync + 'static,
    Error: std::error::Error + Send + From<ConsensusError> + 'static,
    BlockNumber: From<<<Block as BlockT>::Header as HeaderT>::Number>,
{
    let chain_constants = client
        .runtime_api()
        .chain_constants(client.info().best_hash)
        .map_err(|error| sp_consensus::Error::ChainLookup(error.to_string()))?;

    let worker = SubspaceSlotWorker {
        client: client.clone(),
        block_import,
        env,
        sync_oracle: sync_oracle.clone(),
        justification_sync_link,
        force_authoring,
        backoff_authoring_blocks,
        subspace_link: subspace_link.clone(),
        reward_signing_context: schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT),
        block_proposal_slot_portion,
        max_block_proposal_slot_portion,
        telemetry,
        offchain_tx_pool_factory,
        chain_constants,
        segment_headers_store,
        pending_solutions: Default::default(),
        pot_checkpoints: Default::default(),
        pot_verifier,
        _pos_table: PhantomData::<PosTable>,
    };

    info!(target: "subspace", "🧑‍🌾 Starting Subspace Authorship worker");
    let inner = sc_proof_of_time::start_slot_worker(
        chain_constants.slot_duration(),
        client,
        select_chain,
        worker,
        sync_oracle,
        create_inherent_data_providers,
        pot_slot_info_stream,
    );

    Ok(SubspaceWorker {
        inner: Box::pin(inner),
    })
}

/// Worker for Subspace which implements `Future<Output=()>`. This must be polled.
#[must_use]
pub struct SubspaceWorker {
    inner: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
}

impl Future for SubspaceWorker {
    type Output = ();

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut futures::task::Context,
    ) -> futures::task::Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

/// State that must be shared between the import queue and the authoring logic.
#[derive(Clone)]
pub struct SubspaceLink<Block: BlockT> {
    new_slot_notification_sender: SubspaceNotificationSender<NewSlotNotification>,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    reward_signing_notification_sender: SubspaceNotificationSender<RewardSigningNotification>,
    reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    archived_segment_notification_sender: SubspaceNotificationSender<ArchivedSegmentNotification>,
    archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegmentNotification>,
    block_importing_notification_sender:
        SubspaceNotificationSender<BlockImportingNotification<Block>>,
    block_importing_notification_stream:
        SubspaceNotificationStream<BlockImportingNotification<Block>>,
    /// Segment headers that are expected to appear in the corresponding blocks, used for block
    /// production and validation
    segment_headers: Arc<Mutex<LruCache<NumberFor<Block>, Vec<SegmentHeader>>>>,
    kzg: Kzg,
}

impl<Block: BlockT> SubspaceLink<Block> {
    /// Get stream with notifications about new slot arrival with ability to send solution back.
    pub fn new_slot_notification_stream(&self) -> SubspaceNotificationStream<NewSlotNotification> {
        self.new_slot_notification_stream.clone()
    }

    /// A stream with notifications about headers that need to be signed with ability to send
    /// signature back.
    pub fn reward_signing_notification_stream(
        &self,
    ) -> SubspaceNotificationStream<RewardSigningNotification> {
        self.reward_signing_notification_stream.clone()
    }

    /// Get stream with notifications about archived segment creation
    pub fn archived_segment_notification_stream(
        &self,
    ) -> SubspaceNotificationStream<ArchivedSegmentNotification> {
        self.archived_segment_notification_stream.clone()
    }

    /// Get stream with notifications about each imported block right BEFORE import actually
    /// happens.
    ///
    /// NOTE: all Subspace checks have already happened for this block, but block can still
    /// potentially fail to import in Substrate's internals.
    pub fn block_importing_notification_stream(
        &self,
    ) -> SubspaceNotificationStream<BlockImportingNotification<Block>> {
        self.block_importing_notification_stream.clone()
    }

    /// Get blocks that are expected to be included at specified block number.
    pub fn segment_headers_for_block(&self, block_number: NumberFor<Block>) -> Vec<SegmentHeader> {
        self.segment_headers
            .lock()
            .peek(&block_number)
            .cloned()
            .unwrap_or_default()
    }

    /// Access KZG instance
    pub fn kzg(&self) -> &Kzg {
        &self.kzg
    }
}

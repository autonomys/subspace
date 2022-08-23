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
#![feature(drain_filter, int_log, try_blocks)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod archiver;
pub mod aux_schema;
pub mod notification;
mod slot_worker;
#[cfg(test)]
mod tests;

use crate::aux_schema::{EonIndexEntry, SolutionRangeParameters};
use crate::notification::{SubspaceNotificationSender, SubspaceNotificationStream};
use crate::slot_worker::SubspaceSlotWorker;
pub use archiver::start_subspace_archiver;
use codec::Encode;
use futures::channel::mpsc;
use futures::StreamExt;
use log::{debug, info, trace, warn};
use lru::LruCache;
use parking_lot::Mutex;
use prometheus_endpoint::Registry;
use sc_client_api::backend::AuxStore;
use sc_client_api::{BlockBackend, BlockchainEvents, ProvideUncles, UsageProvider};
use sc_consensus::block_import::{
    BlockCheckParams, BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult,
};
use sc_consensus::import_queue::{
    BasicQueue, BoxJustificationImport, DefaultImportQueue, Verifier,
};
use sc_consensus::{JustificationSyncLink, StateAction};
use sc_consensus_slots::{
    check_equivocation, BackoffAuthoringBlocksStrategy, InherentDataProviderExt, SlotProportion,
};
use sc_telemetry::{telemetry, TelemetryHandle, CONSENSUS_DEBUG, CONSENSUS_TRACE};
use sc_utils::mpsc::TracingUnboundedSender;
use schnorrkel::context::SigningContext;
use schnorrkel::PublicKey;
use sp_api::{ApiError, ApiExt, BlockT, HeaderT, NumberFor, ProvideRuntimeApi, TransactionFor};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::{Error as ClientError, HeaderBackend, HeaderMetadata, Result as ClientResult};
use sp_consensus::{
    BlockOrigin, CacheKeyId, CanAuthorWith, Environment, Error as ConsensusError, Proposer,
    SelectChain, SyncOracle,
};
use sp_consensus_slots::{Slot, SlotDuration};
use sp_consensus_subspace::digests::{
    extract_pre_digest, extract_subspace_digest_items, verify_next_digests, Error as DigestError,
    NextDigestsVerificationParams, PreDigest, SubspaceDigestItems,
};
use sp_consensus_subspace::{
    check_header, ChainConstants, CheckedHeader, FarmerPublicKey, FarmerSignature, SubspaceApi,
    VerificationError, VerificationParams,
};
use sp_core::H256;
use sp_inherents::{CreateInherentDataProviders, InherentDataProvider};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{CheckedSub, One, Saturating, Zero};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use subspace_archiving::archiver::{ArchivedSegment, Archiver};
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{
    BlockWeight, EonIndex, Randomness, RootBlock, Salt, SegmentIndex, Sha256Hash, Solution,
    SolutionRange, MERKLE_NUM_LEAVES, RECORDED_HISTORY_SEGMENT_SIZE, RECORD_SIZE,
};
use subspace_solving::{derive_global_challenge, derive_target, REWARD_SIGNING_CONTEXT};
use subspace_verification::{
    derive_randomness, Error as VerificationPrimitiveError, VerifySolutionParams,
};

/// Information about new slot that just arrived
#[derive(Debug, Copy, Clone)]
pub struct NewSlotInfo {
    /// Slot
    pub slot: Slot,
    /// Global slot challenge
    pub global_challenge: Sha256Hash,
    /// Salt
    pub salt: Salt,
    /// Salt for the next eon
    pub next_salt: Option<Salt>,
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
    pub solution_sender: TracingUnboundedSender<Solution<FarmerPublicKey, FarmerPublicKey>>,
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
    pub archived_segment: Arc<ArchivedSegment>,
    /// Sender that signified the fact of receiving archived segment by farmer.
    ///
    /// This must be used to send a message or else block import pipeline will get stuck.
    pub acknowledgement_sender: TracingUnboundedSender<()>,
}

/// Notification with imported block header hash that needs to be archived and sender for
/// root blocks.
#[derive(Debug, Clone)]
pub struct ImportedBlockNotification<Block>
where
    Block: BlockT,
{
    /// Block number
    pub block_number: NumberFor<Block>,
    /// Sender for archived root blocks
    pub root_block_sender: mpsc::Sender<RootBlock>,
    /// Sender for pausing the block import when executor is not fast enough to process
    /// the primary block.
    pub block_import_acknowledgement_sender: mpsc::Sender<()>,
}

/// Errors encountered by the Subspace authorship task.
#[derive(Debug, thiserror::Error)]
pub enum Error<Header: HeaderT> {
    /// Error during digest item extraction
    #[error("Digest item error: {0}")]
    DigestItemError(#[from] DigestError),
    /// No Subspace pre-runtime digest found
    #[error("No Subspace pre-runtime digest found")]
    NoPreRuntimeDigest,
    /// Header rejected: too far in the future
    #[error("Header {0:?} rejected: too far in the future")]
    TooFarInFuture(Header::Hash),
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
    /// Bad solution signature
    #[error("Bad solution signature on slot {0:?}: {1:?}")]
    BadSolutionSignature(Slot, schnorrkel::SignatureError),
    /// Bad local challenge
    #[error("Local challenge is invalid for slot {0}: {1}")]
    BadLocalChallenge(Slot, schnorrkel::SignatureError),
    /// Solution is outside of solution range
    #[error("Solution is outside of solution range for slot {0}")]
    OutsideOfSolutionRange(Slot),
    /// Solution is outside of max plot size
    #[error("Solution is outside of max plot size {0}")]
    OutsideOfMaxPlot(Slot),
    /// Invalid encoding of a piece
    #[error("Invalid encoding for slot {0}")]
    InvalidEncoding(Slot),
    /// Invalid tag for salt
    #[error("Invalid tag for salt for slot {0}")]
    InvalidTag(Slot),
    /// Parent block has no associated weight
    #[error("Parent block of {0} has no associated weight")]
    ParentBlockNoAssociatedWeight(Header::Hash),
    /// Block has invalid associated global randomness
    #[error("Invalid global randomness for block {0}")]
    InvalidGlobalRandomness(Header::Hash),
    /// Block has invalid associated solution range
    #[error("Invalid solution range for block {0}")]
    InvalidSolutionRange(Header::Hash),
    /// Block has invalid associated salt
    #[error("Invalid salt for block {0}")]
    InvalidSalt(Header::Hash),
    /// Invalid set of root blocks
    #[error("Invalid set of root blocks")]
    InvalidSetOfRootBlocks,
    /// Stored root block extrinsic was not found
    #[error("Stored root block extrinsic was not found: {0:?}")]
    RootBlocksExtrinsicNotFound(Vec<RootBlock>),
    /// Duplicated records root
    #[error("Duplicated records root for segment index {0}, it already exists in aux DB")]
    DuplicatedRecordsRoot(u64),
    /// Farmer in block list
    #[error("Farmer {0} is in block list")]
    FarmerInBlockList(FarmerPublicKey),
    /// Merkle Root not found
    #[error("Records Root for segment index {0} not found")]
    RecordsRootNotFound(u64),
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
    fn from(error: VerificationError<Header>) -> Self {
        match error {
            VerificationError::NoPreRuntimeDigest => Error::NoPreRuntimeDigest,
            VerificationError::HeaderBadSeal(block_hash) => Error::HeaderBadSeal(block_hash),
            VerificationError::HeaderUnsealed(block_hash) => Error::HeaderUnsealed(block_hash),
            VerificationError::BadRewardSignature(block_hash) => {
                Error::BadRewardSignature(block_hash)
            }
            VerificationError::VerificationError(slot, error) => match error {
                VerificationPrimitiveError::InvalidTag => Error::InvalidTag(slot),
                VerificationPrimitiveError::InvalidPieceEncoding => Error::InvalidEncoding(slot),
                VerificationPrimitiveError::InvalidPiece => Error::InvalidEncoding(slot),
                VerificationPrimitiveError::InvalidLocalChallenge(err) => {
                    Error::BadLocalChallenge(slot, err)
                }
                VerificationPrimitiveError::OutsideSolutionRange => {
                    Error::OutsideOfSolutionRange(slot)
                }
                VerificationPrimitiveError::InvalidSolutionSignature(err) => {
                    Error::BadSolutionSignature(slot, err)
                }
                VerificationPrimitiveError::OutsideMaxPlot => Error::OutsideOfMaxPlot(slot),
            },
        }
    }
}

impl<Header> From<Error<Header>> for String
where
    Header: HeaderT,
{
    fn from(error: Error<Header>) -> String {
        error.to_string()
    }
}

/// A slot duration.
///
/// Create with [`Self::get`].
#[derive(Clone)]
pub struct Config(SlotDuration);

impl Config {
    /// Fetch the config from the runtime.
    pub fn get<Block, Client>(client: &Client) -> ClientResult<Self>
    where
        Block: BlockT,
        Client: AuxStore + ProvideRuntimeApi<Block> + UsageProvider<Block>,
        Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    {
        trace!(target: "subspace", "Getting slot duration");

        let mut best_block_id = BlockId::Hash(client.usage_info().chain.best_hash);
        if client.usage_info().chain.finalized_state.is_none() {
            debug!(
                target: "subspace",
                "No finalized state is available. Reading config from genesis"
            );
            best_block_id = BlockId::Hash(client.usage_info().chain.genesis_hash);
        }
        let slot_duration = client.runtime_api().slot_duration(&best_block_id)?;

        Ok(Self(SlotDuration::from_millis(
            slot_duration
                .as_millis()
                .try_into()
                .expect("Slot duration in ms never exceeds u64; qed"),
        )))
    }

    /// Get the inner slot duration
    pub fn slot_duration(&self) -> SlotDuration {
        self.0
    }
}

/// Parameters for Subspace.
pub struct SubspaceParams<B: BlockT, C, SC, E, I, SO, L, CIDP, BS, CAW> {
    /// The client to use
    pub client: Arc<C>,

    /// The SelectChain Strategy
    pub select_chain: SC,

    /// The environment we are producing blocks for.
    pub env: E,

    /// The underlying block-import object to supply our produced blocks to.
    /// This must be a `SubspaceBlockImport` or a wrapper of it, otherwise
    /// critical consensus logic will be omitted.
    pub block_import: I,

    /// A sync oracle
    pub sync_oracle: SO,

    /// Hook into the sync module to control the justification sync process.
    pub justification_sync_link: L,

    /// Something that can create the inherent data providers.
    pub create_inherent_data_providers: CIDP,

    /// Force authoring of blocks even if we are offline
    pub force_authoring: bool,

    /// Strategy and parameters for backing off block production.
    pub backoff_authoring_blocks: Option<BS>,

    /// The source of timestamps for relative slots
    pub subspace_link: SubspaceLink<B>,

    /// Checks if the current native implementation can author with a runtime at a given block.
    pub can_author_with: CAW,

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
}

/// Start the Subspace worker.
pub fn start_subspace<Block, Client, SC, E, I, SO, CIDP, BS, CAW, L, Error>(
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
        can_author_with,
        block_proposal_slot_portion,
        max_block_proposal_slot_portion,
        telemetry,
    }: SubspaceParams<Block, Client, SC, E, I, SO, L, CIDP, BS, CAW>,
) -> Result<SubspaceWorker, sp_consensus::Error>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + ProvideUncles<Block>
        + BlockchainEvents<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = ClientError>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
    SC: SelectChain<Block> + 'static,
    E: Environment<Block, Error = Error> + Send + Sync + 'static,
    E::Proposer: Proposer<Block, Error = Error, Transaction = TransactionFor<Client, Block>>,
    I: BlockImport<Block, Error = ConsensusError, Transaction = TransactionFor<Client, Block>>
        + Send
        + Sync
        + 'static,
    SO: SyncOracle + Send + Sync + Clone + 'static,
    L: JustificationSyncLink<Block> + 'static,
    CIDP: CreateInherentDataProviders<Block, ()> + Send + Sync + 'static,
    CIDP::InherentDataProviders: InherentDataProviderExt + Send,
    BS: BackoffAuthoringBlocksStrategy<NumberFor<Block>> + Send + Sync + 'static,
    CAW: CanAuthorWith<Block> + Send + Sync + 'static,
    Error: std::error::Error + Send + From<ConsensusError> + From<I::Error> + 'static,
{
    let worker = SubspaceSlotWorker {
        client,
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
    };

    info!(target: "subspace", "🧑‍🌾 Starting Subspace Authorship worker");
    let inner = sc_consensus_slots::start_slot_worker(
        subspace_link.config.0,
        select_chain,
        sc_consensus_slots::SimpleSlotWorkerToSlotWorker(worker),
        sync_oracle,
        create_inherent_data_providers,
        can_author_with,
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
    config: Config,
    new_slot_notification_sender: SubspaceNotificationSender<NewSlotNotification>,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    reward_signing_notification_sender: SubspaceNotificationSender<RewardSigningNotification>,
    reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    archived_segment_notification_sender: SubspaceNotificationSender<ArchivedSegmentNotification>,
    archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegmentNotification>,
    imported_block_notification_stream:
        SubspaceNotificationStream<ImportedBlockNotification<Block>>,
    /// Root blocks that are expected to appear in the corresponding blocks, used for block
    /// validation
    root_blocks: Arc<Mutex<LruCache<NumberFor<Block>, Vec<RootBlock>>>>,
}

impl<Block: BlockT> SubspaceLink<Block> {
    /// Get the config of this link.
    pub fn config(&self) -> &Config {
        &self.config
    }

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

    /// Get stream with notifications about each imported block.
    pub fn imported_block_notification_stream(
        &self,
    ) -> SubspaceNotificationStream<ImportedBlockNotification<Block>> {
        self.imported_block_notification_stream.clone()
    }

    /// Get blocks that are expected to be included at specified block number.
    pub fn root_blocks_for_block(&self, block_number: NumberFor<Block>) -> Vec<RootBlock> {
        self.root_blocks
            .lock()
            .peek(&block_number)
            .cloned()
            .unwrap_or_default()
    }
}

/// A verifier for Subspace blocks.
pub struct SubspaceVerifier<Block: BlockT, Client, SelectChain, SN> {
    client: Arc<Client>,
    select_chain: SelectChain,
    slot_now: SN,
    telemetry: Option<TelemetryHandle>,
    reward_signing_context: SigningContext,
    is_authoring_blocks: bool,
    block: PhantomData<Block>,
}

impl<Block, Client, SelectChain, SN> SubspaceVerifier<Block, Client, SelectChain, SN>
where
    Block: BlockT,
    Client: AuxStore + HeaderBackend<Block> + HeaderMetadata<Block> + ProvideRuntimeApi<Block>,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey>,
    SelectChain: sp_consensus::SelectChain<Block>,
{
    async fn check_and_report_equivocation(
        &self,
        slot_now: Slot,
        slot: Slot,
        header: &Block::Header,
        author: &FarmerPublicKey,
        origin: &BlockOrigin,
    ) -> Result<(), Error<Block::Header>> {
        // don't report any equivocations during initial sync
        // as they are most likely stale.
        if *origin == BlockOrigin::NetworkInitialSync {
            return Ok(());
        }

        // check if authorship of this header is an equivocation and return a proof if so.
        let equivocation_proof =
            match check_equivocation(&*self.client, slot_now, slot, header, author)
                .map_err(Error::Client)?
            {
                Some(proof) => proof,
                None => return Ok(()),
            };

        info!(
            "Slot author {:?} is equivocating at slot {} with headers {:?} and {:?}",
            author,
            slot,
            equivocation_proof.first_header.hash(),
            equivocation_proof.second_header.hash(),
        );

        if self.is_authoring_blocks {
            // get the best block on which we will build and send the equivocation report.
            let best_id = self
                .select_chain
                .best_chain()
                .await
                .map(|h| BlockId::Hash(h.hash()))
                .map_err(|e| Error::Client(e.into()))?;

            // submit equivocation report at best block.
            self.client
                .runtime_api()
                .submit_report_equivocation_extrinsic(&best_id, equivocation_proof)
                .map_err(Error::RuntimeApi)?;

            info!(target: "subspace", "Submitted equivocation report for author {:?}", author);
        } else {
            info!(
                target: "subspace",
                "Not submitting equivocation report because node is not authoring blocks"
            );
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl<Block, Client, SelectChain, SN> Verifier<Block>
    for SubspaceVerifier<Block, Client, SelectChain, SN>
where
    Block: BlockT,
    Client: HeaderMetadata<Block, Error = sp_blockchain::Error>
        + HeaderBackend<Block>
        + ProvideRuntimeApi<Block>
        + Send
        + Sync
        + AuxStore,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey>,
    SelectChain: sp_consensus::SelectChain<Block>,
    SN: Fn() -> Slot + Send + Sync + 'static,
{
    async fn verify(
        &mut self,
        mut block: BlockImportParams<Block, ()>,
    ) -> Result<
        (
            BlockImportParams<Block, ()>,
            Option<Vec<(CacheKeyId, Vec<u8>)>>,
        ),
        String,
    > {
        trace!(
            target: "subspace",
            "Verifying origin: {:?} header: {:?} justification(s): {:?} body: {:?}",
            block.origin,
            block.header,
            block.justifications,
            block.body,
        );

        let hash = block.header.hash();

        debug!(target: "subspace", "We have {:?} logs in this header", block.header.digest().logs().len());

        let subspace_digest_items = extract_subspace_digest_items::<
            Block::Header,
            FarmerPublicKey,
            FarmerPublicKey,
            FarmerSignature,
        >(&block.header)
        .map_err(Error::<Block::Header>::from)?;
        let pre_digest = subspace_digest_items.pre_digest;

        // Check if farmer's plot is burned.
        // TODO: Add to header and store in aux storage?
        if self
            .client
            .runtime_api()
            .is_in_block_list(
                &BlockId::Hash(*block.header.parent_hash()),
                &pre_digest.solution.public_key,
            )
            .or_else(|error| {
                if matches!(block.state_action, StateAction::Skip) {
                    Ok(false)
                } else {
                    Err(Error::<Block::Header>::RuntimeApi(error))
                }
            })?
        {
            warn!(
                target: "subspace",
                "Verifying block with solution provided by farmer in block list: {}",
                pre_digest.solution.public_key
            );

            return Err(Error::<Block::Header>::FarmerInBlockList(
                pre_digest.solution.public_key.clone(),
            )
            .into());
        }

        let slot_now = (self.slot_now)();

        // Stateless header verification only. This means only check that header contains required
        // contents, correct signature and valid Proof-of-Space, but because previous block is not
        // guaranteed to be imported at this point, it is not possible to verify
        // Proof-of-Archival-Storage. In order to verify PoAS randomness, solution range and salt
        // from the header are checked against expected correct values during block import as well
        // as whether piece in the header corresponds to the actual archival history of the
        // blockchain.
        let checked_header = {
            // We add one to the current slot to allow for some small drift.
            // FIXME https://github.com/paritytech/substrate/issues/1019 in the future, alter this
            //  queue to allow deferring of headers
            check_header::<_, FarmerPublicKey>(
                VerificationParams {
                    header: block.header.clone(),
                    slot_now: slot_now + 1,
                    verify_solution_params: VerifySolutionParams {
                        global_randomness: &subspace_digest_items.global_randomness,
                        solution_range: subspace_digest_items.solution_range,
                        salt: subspace_digest_items.salt,
                        piece_check_params: None,
                    },
                    reward_signing_context: &self.reward_signing_context,
                },
                Some(pre_digest),
            )
            .map_err(Error::<Block::Header>::from)?
        };

        match checked_header {
            CheckedHeader::Checked(pre_header, verified_info) => {
                let slot = verified_info.pre_digest.slot;

                // the header is valid but let's check if there was something else already
                // proposed at the same slot by the given author. if there was, we will
                // report the equivocation to the runtime.
                if let Err(err) = self
                    .check_and_report_equivocation(
                        slot_now,
                        slot,
                        &block.header,
                        &verified_info.pre_digest.solution.public_key,
                        &block.origin,
                    )
                    .await
                {
                    warn!(
                        target: "subspace",
                        "Error checking/reporting Subspace equivocation: {}",
                        err
                    );
                }

                trace!(target: "subspace", "Checked {:?}; importing.", pre_header);
                telemetry!(
                    self.telemetry;
                    CONSENSUS_TRACE;
                    "subspace.checked_and_importing";
                    "pre_header" => ?pre_header,
                );

                block.header = pre_header;
                block.post_digests.push(verified_info.seal);
                block.post_hash = Some(hash);

                Ok((block, Default::default()))
            }
            CheckedHeader::Deferred(a, b) => {
                debug!(target: "subspace", "Checking {:?} failed; {:?}, {:?}.", hash, a, b);
                telemetry!(
                    self.telemetry;
                    CONSENSUS_DEBUG;
                    "subspace.header_too_far_in_future";
                    "hash" => ?hash, "a" => ?a, "b" => ?b
                );
                Err(Error::<Block::Header>::TooFarInFuture(hash).into())
            }
        }
    }
}

/// A block-import handler for Subspace.
///
/// This scans each imported block for epoch change signals. The signals are
/// tracked in a tree (of all forks), and the import logic validates all epoch
/// change transitions, i.e. whether a given epoch change is expected or whether
/// it is missing.
///
/// The epoch change tree should be pruned as blocks are finalized.
pub struct SubspaceBlockImport<Block: BlockT, Client, I, CAW, CIDP> {
    inner: I,
    client: Arc<Client>,
    imported_block_notification_sender:
        SubspaceNotificationSender<ImportedBlockNotification<Block>>,
    subspace_link: SubspaceLink<Block>,
    can_author_with: CAW,
    create_inherent_data_providers: CIDP,
}

impl<Block, I, Client, CAW, CIDP> Clone for SubspaceBlockImport<Block, Client, I, CAW, CIDP>
where
    Block: BlockT,
    I: Clone,
    CAW: Clone,
    CIDP: Clone,
{
    fn clone(&self) -> Self {
        SubspaceBlockImport {
            inner: self.inner.clone(),
            client: self.client.clone(),
            imported_block_notification_sender: self.imported_block_notification_sender.clone(),
            subspace_link: self.subspace_link.clone(),
            can_author_with: self.can_author_with.clone(),
            create_inherent_data_providers: self.create_inherent_data_providers.clone(),
        }
    }
}

impl<Block, Client, I, CAW, CIDP> SubspaceBlockImport<Block, Client, I, CAW, CIDP>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block>
        + AuxStore,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey> + ApiExt<Block>,
    CAW: CanAuthorWith<Block> + Send + Sync + 'static,
    CIDP: CreateInherentDataProviders<Block, SubspaceLink<Block>> + Send + Sync + 'static,
{
    fn new(
        client: Arc<Client>,
        block_import: I,
        imported_block_notification_sender: SubspaceNotificationSender<
            ImportedBlockNotification<Block>,
        >,
        subspace_link: SubspaceLink<Block>,
        can_author_with: CAW,
        create_inherent_data_providers: CIDP,
    ) -> Self {
        SubspaceBlockImport {
            client,
            inner: block_import,
            imported_block_notification_sender,
            subspace_link,
            can_author_with,
            create_inherent_data_providers,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn block_import_verification(
        &self,
        block_hash: Block::Hash,
        origin: BlockOrigin,
        header: Block::Header,
        extrinsics: Option<Vec<Block::Extrinsic>>,
        chain_constants: &ChainConstants,
        genesis_slot: Slot,
        era_start_slot: Slot,
        current_eon_index: EonIndex,
        next_eon_randomness: Option<Randomness>,
        should_adjust_solution_range: &mut bool,
        maybe_next_solution_range_override: &mut Option<SolutionRange>,
        root_plot_public_key: &mut Option<FarmerPublicKey>,
        subspace_digest_items: &SubspaceDigestItems<
            FarmerPublicKey,
            FarmerPublicKey,
            FarmerSignature,
        >,
        skip_runtime_access: bool,
    ) -> Result<(), Error<Block::Header>> {
        let block_number = *header.number();
        let parent_hash = *header.parent_hash();
        let parent_block_id = BlockId::Hash(parent_hash);

        let pre_digest = &subspace_digest_items.pre_digest;

        if !skip_runtime_access {
            if let Some(root_plot_public_key) = root_plot_public_key {
                if &pre_digest.solution.public_key != root_plot_public_key {
                    // Only root plot public key is allowed.
                    return Err(Error::OnlyRootPlotPublicKeyAllowed);
                }
            }
        }

        // Check if farmer's plot is burned.
        // TODO: Add to header and store in aux storage?
        if self
            .client
            .runtime_api()
            .is_in_block_list(&parent_block_id, &pre_digest.solution.public_key)
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
                pre_digest.solution.public_key
            );

            return Err(Error::FarmerInBlockList(
                pre_digest.solution.public_key.clone(),
            ));
        }

        let parent_header = self
            .client
            .header(parent_block_id)?
            .ok_or(Error::ParentUnavailable(parent_hash, block_hash))?;

        let (correct_global_randomness, correct_solution_range, correct_salt) = if block_number
            .is_one()
        {
            // Genesis block doesn't contain usual digest items, we need to query runtime API
            // instead
            let correct_global_randomness = slot_worker::extract_global_randomness_for_block(
                self.client.as_ref(),
                &parent_block_id,
            )?;
            let (correct_solution_range, _) = slot_worker::extract_solution_ranges_for_block(
                self.client.as_ref(),
                &parent_block_id,
            )?;
            let (correct_salt, _) =
                slot_worker::extract_salt_for_block(self.client.as_ref(), &parent_block_id)?;

            (
                correct_global_randomness,
                correct_solution_range,
                correct_salt,
            )
        } else {
            let parent_subspace_digest_items = extract_subspace_digest_items::<
                _,
                FarmerPublicKey,
                FarmerPublicKey,
                FarmerSignature,
            >(&parent_header)?;

            let correct_global_randomness =
                match parent_subspace_digest_items.next_global_randomness {
                    Some(global_randomness) => global_randomness,
                    None => parent_subspace_digest_items.global_randomness,
                };

            let correct_solution_range = match parent_subspace_digest_items.next_solution_range {
                Some(solution_range) => solution_range,
                None => parent_subspace_digest_items.solution_range,
            };

            let correct_salt = match parent_subspace_digest_items.next_salt {
                Some(salt) => salt,
                None => parent_subspace_digest_items.salt,
            };

            (
                correct_global_randomness,
                correct_solution_range,
                correct_salt,
            )
        };

        if subspace_digest_items.global_randomness != correct_global_randomness {
            return Err(Error::InvalidGlobalRandomness(block_hash));
        }

        if subspace_digest_items.solution_range != correct_solution_range {
            return Err(Error::InvalidSolutionRange(block_hash));
        }

        if subspace_digest_items.salt != correct_salt {
            return Err(Error::InvalidSalt(block_hash));
        }

        let segment_index: SegmentIndex =
            pre_digest.solution.piece_index / SegmentIndex::from(MERKLE_NUM_LEAVES);
        let position = pre_digest.solution.piece_index % u64::from(MERKLE_NUM_LEAVES);

        // This is not a very nice hack due to the fact that at the time first block is produced
        // extrinsics with root blocks are not yet in runtime.
        let maybe_records_root = if block_number.is_one() {
            let archived_segments =
                Archiver::new(RECORD_SIZE as usize, RECORDED_HISTORY_SEGMENT_SIZE as usize)
                    .expect("Incorrect parameters for archiver")
                    .add_block(
                        self.client
                            .block(&BlockId::Number(Zero::zero()))?
                            .ok_or(Error::GenesisUnavailable)?
                            .encode(),
                        BlockObjectMapping::default(),
                    );
            archived_segments.into_iter().find_map(|archived_segment| {
                if archived_segment.root_block.segment_index() == segment_index {
                    Some(archived_segment.root_block.records_root())
                } else {
                    None
                }
            })
        } else {
            aux_schema::load_records_root(self.client.as_ref(), segment_index)?
        };

        let records_root = maybe_records_root.ok_or(Error::RecordsRootNotFound(segment_index))?;

        // Piece is not checked during initial block verification because it requires access to
        // root block, check it now.
        subspace_verification::check_piece(
            records_root,
            position,
            RECORD_SIZE,
            &pre_digest.solution,
        )
        .map_err(|error| VerificationError::VerificationError(pre_digest.slot, error))?;

        let parent_slot = extract_pre_digest(&parent_header).map(|d| d.slot)?;

        // Make sure that slot number is strictly increasing
        if pre_digest.slot <= parent_slot {
            return Err(Error::SlotMustIncrease(parent_slot, pre_digest.slot));
        }

        if !skip_runtime_access {
            // If the body is passed through, we need to use the runtime to check that the
            // internally-set timestamp in the inherents actually matches the slot set in the seal
            // and root blocks in the inherents are set correctly.
            if let Some(extrinsics) = extrinsics {
                if let Err(error) = self.can_author_with.can_author_with(&parent_block_id) {
                    debug!(
                        target: "subspace",
                        "Skipping `check_inherents` as authoring version is not compatible: {}",
                        error,
                    );
                } else {
                    let create_inherent_data_providers = self
                        .create_inherent_data_providers
                        .create_inherent_data_providers(parent_hash, self.subspace_link.clone())
                        .await
                        .map_err(|error| Error::Client(sp_blockchain::Error::from(error)))?;

                    let inherent_data = create_inherent_data_providers
                        .create_inherent_data()
                        .map_err(Error::CreateInherents)?;

                    let inherent_res = self.client.runtime_api().check_inherents_with_context(
                        &parent_block_id,
                        origin.into(),
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
        }

        verify_next_digests::<Block::Header>(NextDigestsVerificationParams {
            number: block_number,
            header_digests: subspace_digest_items,
            global_randomness_interval: chain_constants.global_randomness_interval().into(),
            era_duration: chain_constants.era_duration().into(),
            slot_probability: chain_constants.slot_probability(),
            eon_duration: chain_constants.eon_duration(),
            genesis_slot,
            era_start_slot,
            current_eon_index,
            maybe_randomness: next_eon_randomness,
            should_adjust_solution_range,
            maybe_next_solution_range_override,
            maybe_root_plot_public_key: root_plot_public_key,
        })?;

        Ok(())
    }

    fn find_era_start_slot(
        &self,
        block_number: NumberFor<Block>,
        parent_block_hash: Block::Hash,
        era_index: NumberFor<Block>,
        genesis_slot: Slot,
        chain_constants: &ChainConstants,
    ) -> Result<Slot, ConsensusError> {
        // Extract era start slot, taking into account potential forks at era boundary
        let era_start_slots = match aux_schema::load_era_start_slot(self.client.as_ref(), era_index)
            .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
        {
            Some(era_start_slots) => era_start_slots,
            None => {
                return if block_number.is_one() {
                    Ok(genesis_slot)
                } else {
                    Err(ConsensusError::ClientImport(format!(
                        "Era start slot for era index {era_index} not found"
                    )))
                };
            }
        };

        if era_start_slots.len() == 1 {
            let (_block_hash, slot) = era_start_slots
                .into_iter()
                .next()
                .expect("Length checked above; qed");

            return Ok(slot);
        }

        let first_block_number_in_era = era_index * chain_constants.era_duration().into();
        let mut block_hash = parent_block_hash;
        let first_block_in_era = loop {
            match self.client.header_metadata(block_hash) {
                Ok(header_metadata) => {
                    if header_metadata.number == first_block_number_in_era {
                        break block_hash;
                    }

                    block_hash = header_metadata.parent;
                }
                Err(error) => {
                    return Err(ConsensusError::ClientImport(format!(
                        "Failed to read block {block_hash} during search for start block for era \
                        index {era_index}: {error}"
                    )));
                }
            }
        };

        let maybe_era_start_slot = era_start_slots.into_iter().find_map(|(block_hash, slot)| {
            if first_block_in_era == block_hash {
                Some(slot)
            } else {
                None
            }
        });

        match maybe_era_start_slot {
            Some(era_start_slot) => Ok(era_start_slot),
            None => Err(ConsensusError::ClientImport(format!(
                "Failed to find era start slot for era index {era_index}, must be an \
                    implementation error"
            ))),
        }
    }

    fn find_eon_index(
        &self,
        block_number: NumberFor<Block>,
        parent_block_hash: Block::Hash,
        eon_indexes: &[EonIndexEntry<NumberFor<Block>, Block::Hash>],
    ) -> Result<EonIndexEntry<NumberFor<Block>, Block::Hash>, ConsensusError> {
        let mut ready_eon_indexes = eon_indexes
            .iter()
            .filter(|eon_index_entry| {
                let (_starts_at_slot, starts_at_block) = eon_index_entry.starts_at;
                // Relevant EON must start before current block number
                starts_at_block <= block_number
            })
            .copied()
            .collect::<Vec<_>>();

        if ready_eon_indexes.len() == 1 {
            return Ok(ready_eon_indexes
                .into_iter()
                .next()
                .expect("Length checked above; qed"));
        }

        ready_eon_indexes.sort_unstable_by_key(|eon_index_entry| {
            let (starts_at_slot, _starts_at_block) = eon_index_entry.starts_at;
            starts_at_slot
        });

        // In case of multiple potential eon index entries available, find one that belongs to the
        // correct fork
        for eon_index_entry in ready_eon_indexes.into_iter().rev() {
            let eon_index = eon_index_entry.eon_index;
            let (randomness_block_number, randomness_block_hash) = eon_index_entry.randomness_block;
            // Edge-case when randomness is used immediately after reveal
            if randomness_block_hash == parent_block_hash {
                return Ok(eon_index_entry);
            }

            let mut block_hash = parent_block_hash;
            loop {
                match self.client.header_metadata(block_hash) {
                    Ok(header_metadata) => {
                        let parent_hash = header_metadata.parent;

                        if parent_hash == randomness_block_hash {
                            return Ok(eon_index_entry);
                        }

                        let parent_block_number =
                            match header_metadata.number.checked_sub(&One::one()) {
                                Some(parent_block_number) => parent_block_number,
                                None => {
                                    break;
                                }
                            };

                        // No need to check further, this is an eon entry for a different wrong fork
                        if parent_block_number <= randomness_block_number {
                            break;
                        }

                        block_hash = parent_hash;
                    }
                    Err(error) => {
                        return Err(ConsensusError::ClientImport(format!(
                            "Failed to read block {block_hash} during search for start block for \
                            parent block when checking entry for eon index {eon_index}: {error}"
                        )));
                    }
                }
            }
        }

        Err(ConsensusError::ClientImport(format!(
            "Failed to find eon index entry for block {block_number}, must be an implementation \
            error"
        )))
    }

    // Extract next eon randomness, taking into account potential forks
    #[allow(clippy::type_complexity)]
    fn find_next_eon_randomness(
        &self,
        next_eon_randomnesses: &[(NumberFor<Block>, Block::Hash, Randomness)],
        eon_index: EonIndex,
        block_number: NumberFor<Block>,
        parent_block_hash: Block::Hash,
        chain_constants: &ChainConstants,
    ) -> Result<Option<(NumberFor<Block>, Block::Hash, Randomness)>, ConsensusError> {
        if next_eon_randomnesses.is_empty() {
            return Ok(None);
        }

        if next_eon_randomnesses.len() == 1 {
            let (
                next_eon_randomness_block_number,
                next_eon_randomness_block_hash,
                next_eon_randomness,
            ) = next_eon_randomnesses
                .first()
                .expect("Length checked above; qed");

            // Single entry below archiving point is accepted immediately
            if *next_eon_randomness_block_number
                < block_number.saturating_sub(chain_constants.confirmation_depth_k().into())
            {
                return Ok(Some((
                    *next_eon_randomness_block_number,
                    *next_eon_randomness_block_hash,
                    *next_eon_randomness,
                )));
            }
        }

        for (
            next_eon_randomness_block_number,
            next_eon_randomness_block_hash,
            next_eon_randomness,
        ) in next_eon_randomnesses
        {
            if next_eon_randomness_block_hash == &parent_block_hash {
                return Ok(Some((
                    *next_eon_randomness_block_number,
                    *next_eon_randomness_block_hash,
                    *next_eon_randomness,
                )));
            }
        }

        let mut block_hash = parent_block_hash;
        loop {
            match self.client.header_metadata(block_hash) {
                Ok(header_metadata) => {
                    for (
                        next_eon_randomness_block_number,
                        next_eon_randomness_block_hash,
                        next_eon_randomness,
                    ) in next_eon_randomnesses
                    {
                        if *next_eon_randomness_block_hash == header_metadata.parent {
                            return Ok(Some((
                                *next_eon_randomness_block_number,
                                *next_eon_randomness_block_hash,
                                *next_eon_randomness,
                            )));
                        }
                    }

                    block_hash = header_metadata.parent;
                }
                Err(error) => {
                    return Err(ConsensusError::ClientImport(format!(
                        "Failed to read block {block_hash} during search for next eon randomness \
                        for eon index {eon_index}: {error}"
                    )));
                }
            }
        }
    }

    /// Returns randomness used to derive the next salt if the next salt is revealed after importing header.
    fn derive_next_eon_randomness(
        &self,
        eon_index: EonIndex,
        genesis_slot: Slot,
        pre_digest: &PreDigest<FarmerPublicKey, FarmerPublicKey>,
        chain_constants: &ChainConstants,
    ) -> Result<Option<Randomness>, ConsensusError> {
        let next_salt_reveal_slot = chain_constants
            .eon_next_salt_reveal()
            .checked_add(
                eon_index
                    .checked_mul(chain_constants.eon_duration())
                    .and_then(|res| res.checked_add(u64::from(genesis_slot)))
                    .expect("Eon start slot always fits into u64; qed"),
            )
            .expect("Will never exceed u64; qed");

        // salt will be revealed after importing this header.
        // derive randomness at this header and store it for later verification
        let maybe_randomness = if pre_digest.slot >= next_salt_reveal_slot {
            let randomness = derive_randomness(
                &subspace_core_primitives::PublicKey::from(&pre_digest.solution.public_key),
                pre_digest.solution.tag,
                &pre_digest.solution.tag_signature,
            )
            .map_err(|error| {
                ConsensusError::ClientImport(format!(
                    "Failed to derive next eon randomness: {error}"
                ))
            })?;
            Some(randomness)
        } else {
            None
        };

        Ok(maybe_randomness)
    }
}

#[async_trait::async_trait]
impl<Block, Client, Inner, CAW, CIDP> BlockImport<Block>
    for SubspaceBlockImport<Block, Client, Inner, CAW, CIDP>
where
    Block: BlockT,
    Inner: BlockImport<Block, Transaction = TransactionFor<Client, Block>, Error = ConsensusError>
        + Send
        + Sync,
    Inner::Error: Into<ConsensusError>,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + AuxStore
        + Send
        + Sync,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey> + ApiExt<Block>,
    CAW: CanAuthorWith<Block> + Send + Sync + 'static,
    CIDP: CreateInherentDataProviders<Block, SubspaceLink<Block>> + Send + Sync + 'static,
{
    type Error = ConsensusError;
    type Transaction = TransactionFor<Client, Block>;

    async fn import_block(
        &mut self,
        mut block: BlockImportParams<Block, Self::Transaction>,
        new_cache: HashMap<CacheKeyId, Vec<u8>>,
    ) -> Result<ImportResult, Self::Error> {
        let block_hash = block.post_hash();
        let block_number = *block.header.number();
        let parent_block_hash = *block.header.parent_hash();

        // Early exit if block already in chain
        match self.client.status(BlockId::Hash(block_hash)) {
            Ok(sp_blockchain::BlockStatus::InChain) => {
                block.fork_choice = Some(ForkChoiceStrategy::Custom(false));
                return self
                    .inner
                    .import_block(block, new_cache)
                    .await
                    .map_err(Into::into);
            }
            Ok(sp_blockchain::BlockStatus::Unknown) => {}
            Err(error) => return Err(ConsensusError::ClientImport(error.to_string())),
        }

        let subspace_digest_items = extract_subspace_digest_items(&block.header)
            .map_err(|error| ConsensusError::ClientImport(error.to_string()))?;
        let skip_state_computation = matches!(block.state_action, StateAction::Skip);

        let chain_constants = get_chain_constants(self.client.as_ref())
            .map_err(|e| ConsensusError::ClientImport(e.to_string()))?;

        let (mut solution_range_parameters, old_solution_range_parameters) =
            match aux_schema::load_solution_range_parameters(self.client.as_ref())
                .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
            {
                Some(solution_range_parameters) => {
                    (solution_range_parameters, Some(solution_range_parameters))
                }
                None => {
                    // This is only called on the very first block for which we always have runtime
                    // storage access
                    let should_adjust = self
                        .client
                        .runtime_api()
                        .should_adjust_solution_range(&BlockId::Hash(*block.header.parent_hash()))
                        .map_err(Error::<Block::Header>::RuntimeApi)
                        .map_err(|e| ConsensusError::ClientImport(e.to_string()))?;
                    (
                        SolutionRangeParameters {
                            should_adjust,
                            next_override: None,
                        },
                        None,
                    )
                }
            };

        let (mut root_plot_public_key, old_root_plot_public_key) =
            match aux_schema::load_root_plot_public_key(self.client.as_ref())
                .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
            {
                Some(root_plot_public_key) => (root_plot_public_key.clone(), root_plot_public_key),
                None => {
                    // This is only called on the very first block for which we always have runtime
                    // storage access
                    let root_plot_public_key = self
                        .client
                        .runtime_api()
                        .root_plot_public_key(&BlockId::Hash(*block.header.parent_hash()))
                        .map_err(Error::<Block::Header>::RuntimeApi)
                        .map_err(|e| ConsensusError::ClientImport(e.to_string()))?;
                    (root_plot_public_key, None)
                }
            };

        let mut genesis_slot = aux_schema::load_genesis_slot(self.client.as_ref())
            .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
            .unwrap_or_default();

        // Special case, in block 1 we update genesis slot
        if block_number.is_one() {
            if !genesis_slot.is_zero() {
                warn!(
                    target: "subspace",
                    "Switching fork on block 1, replacing old genesis slot {} with {}, this can \
                    break the chain",
                    genesis_slot,
                    subspace_digest_items.pre_digest.slot
                );
            }
            genesis_slot = subspace_digest_items.pre_digest.slot;
        }

        let era_index = (block_number - One::one()) / chain_constants.era_duration().into();
        let era_start_slot = self.find_era_start_slot(
            block_number,
            parent_block_hash,
            era_index,
            genesis_slot,
            &chain_constants,
        )?;

        let mut eon_indexes = aux_schema::load_eon_indexes(self.client.as_ref())
            .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
            .unwrap_or_default();

        // Special case, filling information about genesis eon
        if block_number.is_one() && eon_indexes.is_empty() {
            eon_indexes.push(EonIndexEntry {
                eon_index: 0,
                randomness: Randomness::default(),
                randomness_block: (0u32.into(), self.client.info().genesis_hash),
                starts_at: (subspace_digest_items.pre_digest.slot, 0u32.into()),
            });
        }

        let eon_index_entry = self.find_eon_index(block_number, parent_block_hash, &eon_indexes)?;
        let mut next_eon_randomnesses = aux_schema::load_next_eon_randomness::<
            NumberFor<Block>,
            Block::Hash,
            _,
        >(self.client.as_ref(), eon_index_entry.eon_index)
        .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
        .unwrap_or_default();

        let next_eon_randomness = match self.find_next_eon_randomness(
            &next_eon_randomnesses,
            eon_index_entry.eon_index,
            block_number,
            parent_block_hash,
            &chain_constants,
        )? {
            Some(next_eon_randomness) => Some(next_eon_randomness),
            None => match self.derive_next_eon_randomness(
                eon_index_entry.eon_index,
                genesis_slot,
                &subspace_digest_items.pre_digest,
                &chain_constants,
            )? {
                Some(next_eon_randomness) => {
                    debug!(
                        target: "subspace",
                        "Derived randomness at block {block_number}: {next_eon_randomness:?}",
                    );
                    next_eon_randomnesses.push((block_number, block_hash, next_eon_randomness));
                    aux_schema::write_next_eon_randomness(
                        eon_index_entry.eon_index,
                        &next_eon_randomnesses,
                        |values| {
                            block.auxiliary.extend(
                                values
                                    .iter()
                                    .map(|(k, v)| (k.to_vec(), v.map(|v| v.to_vec()))),
                            )
                        },
                    );

                    Some((block_number, block_hash, next_eon_randomness))
                }
                None => None,
            },
        };

        self.block_import_verification(
            block_hash,
            block.origin,
            block.header.clone(),
            block.body.clone(),
            &chain_constants,
            genesis_slot,
            era_start_slot,
            eon_index_entry.eon_index,
            next_eon_randomness.map(|(_block_number, _block_hash, randomness)| randomness),
            &mut solution_range_parameters.should_adjust,
            &mut solution_range_parameters.next_override,
            &mut root_plot_public_key,
            &subspace_digest_items,
            skip_state_computation,
        )
        .await
        .map_err(|error| ConsensusError::ClientImport(error.to_string()))?;

        let pre_digest = subspace_digest_items.pre_digest;

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

        let added_weight = {
            let global_challenge = derive_global_challenge(
                &subspace_digest_items.global_randomness,
                pre_digest.slot.into(),
            );

            // Verification of the local challenge was done before this
            let target = SolutionRange::from_be_bytes(
                derive_target(
                    &PublicKey::from_bytes(pre_digest.solution.public_key.as_ref())
                        .expect("Always correct length; qed"),
                    global_challenge,
                    &pre_digest.solution.local_challenge,
                )
                .expect("Verification of the local challenge was done before this; qed"),
            );
            let tag = SolutionRange::from_be_bytes(pre_digest.solution.tag);

            BlockWeight::from(
                SolutionRange::MAX
                    - subspace_core_primitives::bidirectional_distance(&target, &tag),
            )
        };
        let total_weight = parent_weight + added_weight;

        let info = self.client.info();

        aux_schema::write_block_weight(block_hash, total_weight, |values| {
            block
                .auxiliary
                .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
        });

        for (&segment_index, records_root) in &subspace_digest_items.records_roots {
            if aux_schema::load_records_root(self.client.as_ref(), segment_index)
                .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
                .is_some()
            {
                return Err(ConsensusError::ClientImport(
                    Error::<Block::Header>::DuplicatedRecordsRoot(segment_index).to_string(),
                ));
            }

            aux_schema::write_records_root(segment_index, records_root, |values| {
                block
                    .auxiliary
                    .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
            });
        }

        // In the very first block we need to store chain constants and genesis slot for further use
        if block_number.is_one() {
            aux_schema::write_genesis_slot(genesis_slot, |values| {
                block
                    .auxiliary
                    .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
            });

            aux_schema::write_eon_indexes(&eon_indexes, |values| {
                block
                    .auxiliary
                    .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
            });
        }

        // Store updated solution range parameters if we didn't store them before or if they
        // changed.
        if old_solution_range_parameters.is_none()
            || old_solution_range_parameters != Some(solution_range_parameters)
        {
            aux_schema::write_solution_range_parameters(&solution_range_parameters, |values| {
                block
                    .auxiliary
                    .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
            });
        }

        // Store updated root plot public key on the first block or when changed.
        if block_number.is_one() || old_root_plot_public_key != root_plot_public_key {
            aux_schema::write_root_plot_public_key(&root_plot_public_key, |values| {
                block
                    .auxiliary
                    .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
            });
        }

        // Check if era has changed and store corresponding era start slot.
        //
        // Special case when the current block number is one, then first era begins or era
        // duration interval has reached, so era has changed.
        if block_number.is_one()
            || block_number % chain_constants.era_duration().into() == Zero::zero()
        {
            let next_era_index = if block_number.is_one() {
                Zero::zero()
            } else {
                era_index + One::one()
            };
            let mut next_era_start_slot =
                aux_schema::load_era_start_slot(self.client.as_ref(), next_era_index)
                    .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
                    .unwrap_or_default();
            next_era_start_slot.push((block_hash, pre_digest.slot));

            aux_schema::write_era_start_slot(next_era_index, &next_era_start_slot, |values| {
                block.auxiliary.extend(
                    values
                        .iter()
                        .map(|(k, v)| (k.to_vec(), v.map(|v| v.to_vec()))),
                )
            });
        }

        // Check if the eon is about to be changed
        let maybe_next_eon_index = subspace_verification::derive_next_eon_index(
            eon_index_entry.eon_index,
            chain_constants.eon_duration(),
            u64::from(genesis_slot),
            u64::from(pre_digest.slot),
        );

        if let Some(next_eon_index) = maybe_next_eon_index {
            let (
                next_eon_randomness_block_number,
                next_eon_randomness_block_hash,
                next_eon_randomness,
            ) = next_eon_randomness.ok_or_else(|| {
                ConsensusError::ClientImport(
                    "Next eon randomness was expected, but not present".to_string(),
                )
            })?;
            eon_indexes.push(EonIndexEntry {
                eon_index: next_eon_index,
                randomness: next_eon_randomness,
                randomness_block: (
                    next_eon_randomness_block_number,
                    next_eon_randomness_block_hash,
                ),
                starts_at: (pre_digest.slot, block_number),
            });

            aux_schema::write_eon_indexes(&eon_indexes, |values| {
                block
                    .auxiliary
                    .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
            });
        }

        // Prune era start slots that are too old to be useful
        if let Some(previous_block_number) = block_number.checked_sub(&2u32.into()) {
            let previous_block_era_index =
                previous_block_number / chain_constants.era_duration().into();

            if previous_block_era_index != era_index {
                if let Some(prune_era_index) = previous_block_era_index.checked_sub(&One::one()) {
                    aux_schema::write_era_start_slot::<_, Block::Hash, _, ()>(
                        prune_era_index,
                        &[],
                        |values| {
                            block.auxiliary.extend(
                                values
                                    .iter()
                                    .map(|(k, v)| (k.to_vec(), v.map(|v| v.to_vec()))),
                            )
                        },
                    );
                }
            }

            // Delete eon indexes and randomnesses that are too old to be useful anymore
            {
                let mut eon_indexes_updated = false;
                for eon_index_entry in eon_indexes.drain_filter(|eon_index_entry| {
                    let (starts_at_slot, _starts_at_block) = eon_index_entry.starts_at;
                    starts_at_slot
                        < pre_digest
                            .slot
                            .saturating_sub(chain_constants.eon_duration() * 2)
                }) {
                    eon_indexes_updated = true;
                    debug!(
                        target: "subspace",
                        "Pruning auxiliary storage for eon {}", eon_index_entry.eon_index,
                    );
                    aux_schema::write_next_eon_randomness::<NumberFor<Block>, Block::Hash, _, ()>(
                        eon_index_entry.eon_index,
                        &[],
                        |values| {
                            block.auxiliary.extend(
                                values
                                    .iter()
                                    .map(|(k, v)| (k.to_vec(), v.map(|v| v.to_vec()))),
                            )
                        },
                    );
                }

                if eon_indexes_updated {
                    aux_schema::write_eon_indexes(&eon_indexes, |values| {
                        block
                            .auxiliary
                            .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
                    });
                }
            }
        }

        // The fork choice rule is that we pick the heaviest chain (i.e. smallest solution
        // range), if there's a tie we go with the longest chain.
        block.fork_choice = {
            let (last_best, last_best_number) = (info.best_hash, info.best_number);

            let last_best_weight = if &last_best == block.header.parent_hash() {
                // the parent=genesis case is already covered for loading parent weight,
                // so we don't need to cover again here.
                parent_weight
            } else {
                aux_schema::load_block_weight(&*self.client, last_best)
                    .map_err(|e| ConsensusError::ChainLookup(e.to_string()))?
                    .ok_or_else(|| {
                        ConsensusError::ChainLookup(
                            "No block weight for parent header.".to_string(),
                        )
                    })?
            };

            Some(ForkChoiceStrategy::Custom(
                match total_weight.cmp(&last_best_weight) {
                    Ordering::Greater => true,
                    Ordering::Equal => block_number > last_best_number,
                    Ordering::Less => false,
                },
            ))
        };

        let import_result = self.inner.import_block(block, new_cache).await?;
        let (root_block_sender, root_block_receiver) = mpsc::channel(0);
        let (block_import_acknowledgement_sender, mut block_import_acknowledgement_receiver) =
            mpsc::channel(0);

        self.imported_block_notification_sender
            .notify(move || ImportedBlockNotification {
                block_number,
                root_block_sender,
                block_import_acknowledgement_sender,
            });

        while (block_import_acknowledgement_receiver.next().await).is_some() {
            // Wait for all the acknowledgements to progress.
        }

        let root_blocks: Vec<RootBlock> = root_block_receiver.collect().await;

        if !root_blocks.is_empty() {
            self.subspace_link
                .root_blocks
                .lock()
                .put(block_number + One::one(), root_blocks);
        }

        Ok(import_result)
    }

    async fn check_block(
        &mut self,
        block: BlockCheckParams<Block>,
    ) -> Result<ImportResult, Self::Error> {
        self.inner.check_block(block).await.map_err(Into::into)
    }
}

fn get_chain_constants<Block, Client>(
    client: &Client,
) -> Result<ChainConstants, Error<Block::Header>>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + AuxStore,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
{
    match aux_schema::load_chain_constants(client)? {
        Some(chain_constants) => Ok(chain_constants),
        None => {
            // This is only called on the very first block for which we always have runtime
            // storage access
            let chain_constants = client
                .runtime_api()
                .chain_constants(&BlockId::Hash(client.info().best_hash))
                .map_err(Error::<Block::Header>::RuntimeApi)?;

            aux_schema::write_chain_constants(&chain_constants, |values| {
                client.insert_aux(
                    &values
                        .iter()
                        .map(|(key, value)| (key.as_slice(), *value))
                        .collect::<Vec<_>>(),
                    &[],
                )
            })?;

            Ok(chain_constants)
        }
    }
}

/// Produce a Subspace block-import object to be used later on in the construction of an
/// import-queue.
///
/// Also returns a link object used to correctly instantiate the import queue and background worker.
#[allow(clippy::type_complexity)]
pub fn block_import<Client, Block, I, CAW, CIDP>(
    config: Config,
    wrapped_block_import: I,
    client: Arc<Client>,
    can_author_with: CAW,
    create_inherent_data_providers: CIDP,
) -> ClientResult<(
    SubspaceBlockImport<Block, Client, I, CAW, CIDP>,
    SubspaceLink<Block>,
)>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + AuxStore,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey>,
    CAW: CanAuthorWith<Block> + Send + Sync + 'static,
    CIDP: CreateInherentDataProviders<Block, SubspaceLink<Block>> + Send + Sync + 'static,
{
    let (new_slot_notification_sender, new_slot_notification_stream) =
        notification::channel("subspace_new_slot_notification_stream");
    let (reward_signing_notification_sender, reward_signing_notification_stream) =
        notification::channel("subspace_reward_signing_notification_stream");
    let (archived_segment_notification_sender, archived_segment_notification_stream) =
        notification::channel("subspace_archived_segment_notification_stream");
    let (imported_block_notification_sender, imported_block_notification_stream) =
        notification::channel("subspace_imported_block_notification_stream");

    let confirmation_depth_k = get_chain_constants(client.as_ref())
        .expect("Must always be able to get chain constants")
        .confirmation_depth_k();

    let link = SubspaceLink {
        config,
        new_slot_notification_sender,
        new_slot_notification_stream,
        reward_signing_notification_sender,
        reward_signing_notification_stream,
        archived_segment_notification_sender,
        archived_segment_notification_stream,
        imported_block_notification_stream,
        root_blocks: Arc::new(Mutex::new(LruCache::new(confirmation_depth_k as usize))),
    };

    let import = SubspaceBlockImport::new(
        client,
        wrapped_block_import,
        imported_block_notification_sender,
        link.clone(),
        can_author_with,
        create_inherent_data_providers,
    );

    Ok((import, link))
}

/// Start an import queue for the Subspace consensus algorithm.
///
/// This method returns the import queue, some data that needs to be passed to the block authoring
/// logic (`SubspaceLink`), and a future that must be run to
/// completion and is responsible for listening to finality notifications and
/// pruning the epoch changes tree.
///
/// The block import object provided must be the `SubspaceBlockImport` or a wrapper
/// of it, otherwise crucial import logic will be omitted.
// TODO: Create a struct for these parameters
#[allow(clippy::too_many_arguments)]
pub fn import_queue<Block: BlockT, Client, SelectChain, Inner, SN>(
    block_import: Inner,
    justification_import: Option<BoxJustificationImport<Block>>,
    client: Arc<Client>,
    select_chain: SelectChain,
    slot_now: SN,
    spawner: &impl sp_core::traits::SpawnEssentialNamed,
    registry: Option<&Registry>,
    telemetry: Option<TelemetryHandle>,
    is_authoring_blocks: bool,
) -> ClientResult<DefaultImportQueue<Block, Client>>
where
    Inner: BlockImport<Block, Error = ConsensusError, Transaction = TransactionFor<Client, Block>>
        + Send
        + Sync
        + 'static,
    Client: ProvideRuntimeApi<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + AuxStore
        + Send
        + Sync
        + 'static,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey> + ApiExt<Block>,
    SelectChain: sp_consensus::SelectChain<Block> + 'static,
    SN: Fn() -> Slot + Send + Sync + 'static,
{
    let verifier = SubspaceVerifier {
        select_chain,
        slot_now,
        telemetry,
        client,
        reward_signing_context: schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT),
        is_authoring_blocks,
        block: PhantomData::default(),
    };

    Ok(BasicQueue::new(
        verifier,
        Box::new(block_import),
        justification_import,
        spawner,
        registry,
    ))
}

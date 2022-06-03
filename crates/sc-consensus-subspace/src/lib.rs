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
#![feature(try_blocks)]
#![feature(int_log)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod archiver;
pub mod aux_schema;
pub mod notification;
mod slot_worker;
#[cfg(test)]
mod tests;

use crate::notification::{SubspaceNotificationSender, SubspaceNotificationStream};
use crate::slot_worker::SubspaceSlotWorker;
use crate::verification::{VerificationParams, VerifySolutionParams};
pub use archiver::start_subspace_archiver;
use futures::channel::mpsc;
use futures::StreamExt;
use log::{debug, info, trace, warn};
use lru::LruCache;
use parking_lot::Mutex;
use prometheus_endpoint::Registry;
use sc_client_api::backend::AuxStore;
use sc_client_api::{BlockchainEvents, ProvideUncles, UsageProvider};
use sc_consensus::block_import::{
    BlockCheckParams, BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult,
};
use sc_consensus::import_queue::{
    BasicQueue, BoxJustificationImport, DefaultImportQueue, Verifier,
};
use sc_consensus::JustificationSyncLink;
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
    CompatibleDigestItem, GlobalRandomnessDescriptor, PreDigest, SaltDescriptor,
    SolutionRangeDescriptor,
};
use sp_consensus_subspace::verification::{CheckedHeader, VerificationError};
use sp_consensus_subspace::{verification, FarmerPublicKey, FarmerSignature, SubspaceApi};
use sp_core::crypto::UncheckedFrom;
use sp_core::{ByteArray, H256};
use sp_inherents::{CreateInherentDataProviders, InherentDataProvider};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{One, Zero};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{BlockNumber, RootBlock, Salt, Sha256Hash, Solution};
use subspace_solving::{derive_global_challenge, derive_target, REWARD_SIGNING_CONTEXT};

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
    pub solution_range: u64,
    /// Acceptable solution range for voting
    pub voting_solution_range: u64,
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
}

/// Errors encountered by the Subspace authorship task.
#[derive(Debug, thiserror::Error)]
pub enum Error<Header: HeaderT> {
    /// Multiple Subspace pre-runtime digests
    #[error("Multiple Subspace pre-runtime digests, rejecting!")]
    MultiplePreRuntimeDigests,
    /// No Subspace pre-runtime digest found
    #[error("No Subspace pre-runtime digest found")]
    NoPreRuntimeDigest,
    /// Multiple Subspace global randomness digests
    #[error("Multiple Subspace global randomness digests, rejecting!")]
    MultipleGlobalRandomnessDigests,
    /// Multiple Subspace solution range digests
    #[error("Multiple Subspace solution range digests, rejecting!")]
    MultipleSolutionRangeDigests,
    /// Multiple Subspace salt digests
    #[error("Multiple Subspace salt digests, rejecting!")]
    MultipleSaltDigests,
    /// Header rejected: too far in the future
    #[error("Header {0:?} rejected: too far in the future")]
    TooFarInFuture(Header::Hash),
    /// Parent unavailable. Cannot import
    #[error("Parent ({0}) of {1} unavailable. Cannot import")]
    ParentUnavailable(Header::Hash, Header::Hash),
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
    /// Block has no associated global randomness
    #[error("Missing global randomness for block {0}")]
    MissingGlobalRandomness(Header::Hash),
    /// Block has invalid associated global randomness
    #[error("Invalid global randomness for block {0}")]
    InvalidGlobalRandomness(Header::Hash),
    /// Block has no associated solution range
    #[error("Missing solution range for block {0}")]
    MissingSolutionRange(Header::Hash),
    /// Block has invalid associated solution range
    #[error("Invalid solution range for block {0}")]
    InvalidSolutionRange(Header::Hash),
    /// Block has no associated salt
    #[error("Missing salt for block {0}")]
    MissingSalt(Header::Hash),
    /// Block has invalid associated salt
    #[error("Invalid salt for block {0}")]
    InvalidSalt(Header::Hash),
    /// Invalid set of root blocks
    #[error("Invalid set of root blocks")]
    InvalidSetOfRootBlocks,
    /// Stored root block extrinsic was not found
    #[error("Stored root block extrinsic was not found: {0:?}")]
    RootBlocksExtrinsicNotFound(Vec<RootBlock>),
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
            VerificationError::BadSolutionSignature(slot, signature_error) => {
                Error::BadSolutionSignature(slot, signature_error)
            }
            VerificationError::BadLocalChallenge(slot, signature_error) => {
                Error::BadLocalChallenge(slot, signature_error)
            }
            VerificationError::OutsideOfSolutionRange(slot) => Error::OutsideOfSolutionRange(slot),
            VerificationError::OutsideOfMaxPlot(slot) => Error::OutsideOfMaxPlot(slot),
            VerificationError::InvalidEncoding(slot) => Error::InvalidEncoding(slot),
            VerificationError::InvalidTag(slot) => Error::InvalidTag(slot),
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

    /// Chain ID from chain specification, needed to work around Gemini 1b launch issues.
    pub chain_id: String,
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
        chain_id,
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
        chain_id,
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

/// Extract the Subspace pre digest from the given header. Pre-runtime digests are mandatory, the
/// function will return `Err` if none is found.
pub fn find_pre_digest<Header>(
    header: &Header,
) -> Result<PreDigest<FarmerPublicKey, FarmerPublicKey>, Error<Header>>
where
    Header: HeaderT,
{
    // genesis block doesn't contain a pre digest so let's generate a
    // dummy one to not break any invariants in the rest of the code
    if header.number().is_zero() {
        return Ok(PreDigest {
            slot: Slot::from(0),
            solution: Solution::genesis_solution(
                FarmerPublicKey::unchecked_from([0u8; 32]),
                FarmerPublicKey::unchecked_from([0u8; 32]),
            ),
        });
    }

    let mut pre_digest = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for pre runtime digest", log);
        match (log.as_subspace_pre_digest(), pre_digest.is_some()) {
            (Some(_), true) => return Err(Error::MultiplePreRuntimeDigests),
            (None, _) => trace!(target: "subspace", "Ignoring digest not meant for us"),
            (s, false) => pre_digest = s,
        }
    }
    pre_digest.ok_or(Error::NoPreRuntimeDigest)
}

/// Extract the Subspace global randomness descriptor from the given header.
fn find_global_randomness_descriptor<Header>(
    header: &Header,
) -> Result<Option<GlobalRandomnessDescriptor>, Error<Header>>
where
    Header: HeaderT,
{
    let mut global_randomness_descriptor = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for global randomness digest.", log);
        match (
            log.as_global_randomness_descriptor(),
            global_randomness_descriptor.is_some(),
        ) {
            (Some(_), true) => return Err(Error::MultipleGlobalRandomnessDigests),
            (Some(global_randomness), false) => {
                global_randomness_descriptor = Some(global_randomness)
            }
            _ => trace!(target: "subspace", "Ignoring digest not meant for us"),
        }
    }

    Ok(global_randomness_descriptor)
}

/// Extract the Subspace solution range descriptor from the given header.
fn find_solution_range_descriptor<Header>(
    header: &Header,
) -> Result<Option<SolutionRangeDescriptor>, Error<Header>>
where
    Header: HeaderT,
{
    let mut solution_range_descriptor = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for solution range digest.", log);
        match (
            log.as_solution_range_descriptor(),
            solution_range_descriptor.is_some(),
        ) {
            (Some(_), true) => return Err(Error::MultipleSolutionRangeDigests),
            (Some(solution_range), false) => solution_range_descriptor = Some(solution_range),
            _ => trace!(target: "subspace", "Ignoring digest not meant for us"),
        }
    }

    Ok(solution_range_descriptor)
}

/// Extract the Subspace salt descriptor from the given header.
fn find_salt_descriptor<Header>(header: &Header) -> Result<Option<SaltDescriptor>, Error<Header>>
where
    Header: HeaderT,
{
    let mut salt_descriptor = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for salt digest.", log);
        match (log.as_salt_descriptor(), salt_descriptor.is_some()) {
            (Some(_), true) => return Err(Error::MultipleSaltDigests),
            (Some(salt), false) => salt_descriptor = Some(salt),
            _ => trace!(target: "subspace", "Ignoring digest not meant for us"),
        }
    }

    Ok(salt_descriptor)
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
    /// Chain ID from chain specification, needed to work around Gemini 1b launch issues.
    chain_id: String,
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

        let pre_digest = find_pre_digest(&block.header)?;

        // TODO: Hack for Gemini 1b launch. These blocks should have correct block author.
        if *block.header.number() <= 33_671_u32.into()
            && self.chain_id.as_str() == "subspace_gemini_1b"
            && pre_digest.solution.public_key.as_slice()
                != [
                    0x54, 0x26, 0x37, 0xb0, 0xd4, 0x43, 0x08, 0x7a, 0x34, 0x08, 0x08, 0xbb, 0x02,
                    0x1a, 0x05, 0x19, 0x6f, 0x68, 0x1a, 0x1b, 0x3d, 0xae, 0x24, 0x75, 0x93, 0x2b,
                    0x72, 0x03, 0xf7, 0x84, 0x1e, 0x5a,
                ]
        {
            return Err(
                "Unexpected block author during early history of Gemini 1b, please ignore this \
                message"
                    .to_string(),
            );
        }
        // Check if farmer's plot is burned.
        if self
            .client
            .runtime_api()
            .is_in_block_list(
                &BlockId::Hash(*block.header.parent_hash()),
                &pre_digest.solution.public_key,
            )
            .map_err(Error::<Block::Header>::RuntimeApi)?
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
            let global_randomness = find_global_randomness_descriptor(&block.header)?
                .ok_or(Error::<Block::Header>::MissingGlobalRandomness(hash))?
                .global_randomness;

            let solution_range = find_solution_range_descriptor(&block.header)?
                .ok_or(Error::<Block::Header>::MissingSolutionRange(hash))?
                .solution_range;

            let salt = find_salt_descriptor(&block.header)?
                .ok_or(Error::<Block::Header>::MissingSalt(hash))?
                .salt;

            // We add one to the current slot to allow for some small drift.
            // FIXME https://github.com/paritytech/substrate/issues/1019 in the future, alter this
            //  queue to allow deferring of headers
            verification::check_header::<_, FarmerPublicKey>(
                VerificationParams {
                    header: block.header.clone(),
                    slot_now: slot_now + 1,
                    verify_solution_params: VerifySolutionParams {
                        global_randomness: &global_randomness,
                        solution_range,
                        salt,
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
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
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

    async fn block_import_verification(
        &self,
        block_hash: Block::Hash,
        origin: BlockOrigin,
        header: Block::Header,
        extrinsics: Option<Vec<Block::Extrinsic>>,
        pre_digest: &PreDigest<FarmerPublicKey, FarmerPublicKey>,
    ) -> Result<(), Error<Block::Header>> {
        let parent_hash = *header.parent_hash();
        let parent_block_id = BlockId::Hash(parent_hash);

        let maybe_root_plot_public_key = self
            .client
            .runtime_api()
            .root_plot_public_key(&parent_block_id)?;

        if let Some(root_plot_public_key) = maybe_root_plot_public_key {
            if pre_digest.solution.public_key != root_plot_public_key {
                // Only root plot public key is allowed.
                return Err(Error::OnlyRootPlotPublicKeyAllowed);
            }
        }

        // Check if farmer's plot is burned.
        if self
            .client
            .runtime_api()
            .is_in_block_list(&parent_block_id, &pre_digest.solution.public_key)?
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

        let global_randomness = find_global_randomness_descriptor(&header)?
            .ok_or(Error::MissingGlobalRandomness(block_hash))?
            .global_randomness;
        let correct_global_randomness = slot_worker::extract_global_randomness_for_block(
            self.client.as_ref(),
            &parent_block_id,
        )?;
        if global_randomness != correct_global_randomness {
            return Err(Error::InvalidGlobalRandomness(block_hash));
        }

        let solution_range = find_solution_range_descriptor(&header)?
            .ok_or(Error::MissingSolutionRange(block_hash))?
            .solution_range;
        let (correct_solution_range, _) =
            slot_worker::extract_solution_ranges_for_block(self.client.as_ref(), &parent_block_id)?;
        if solution_range != correct_solution_range {
            return Err(Error::InvalidSolutionRange(block_hash));
        }

        let salt = find_salt_descriptor(&header)?
            .ok_or(Error::MissingSalt(block_hash))?
            .salt;
        let correct_salt =
            slot_worker::extract_salt_for_block(self.client.as_ref(), &parent_block_id)?.0;
        if salt != correct_salt {
            return Err(Error::InvalidSalt(block_hash));
        }

        // TODO: This assumes fixed size segments, which might not be the case
        let record_size = self.client.runtime_api().record_size(&parent_block_id)?;
        let recorded_history_segment_size = self
            .client
            .runtime_api()
            .recorded_history_segment_size(&parent_block_id)?;
        let merkle_num_leaves = u64::from(recorded_history_segment_size / record_size * 2);
        let segment_index = pre_digest.solution.piece_index / merkle_num_leaves;
        let position = pre_digest.solution.piece_index % merkle_num_leaves;
        let mut maybe_records_root = self
            .client
            .runtime_api()
            .records_root(&parent_block_id, segment_index)?;

        // This is not a very nice hack due to the fact that at the time first block is produced
        // extrinsics with root blocks are not yet in runtime.
        if maybe_records_root.is_none() && header.number().is_one() {
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
                return Err(Error::RecordsRootNotFound(segment_index));
            }
        };

        // Piece is not checked during initial block verification because it requires access to
        // root block, check it now.
        verification::check_piece(
            pre_digest.slot,
            records_root,
            position,
            record_size,
            &pre_digest.solution,
        )?;

        let parent_slot = find_pre_digest(&parent_header).map(|d| d.slot)?;

        // Make sure that slot number is strictly increasing
        if pre_digest.slot <= parent_slot {
            return Err(Error::SlotMustIncrease(parent_slot, pre_digest.slot));
        }

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

        Ok(())
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
    Client: HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + AuxStore
        + ProvideRuntimeApi<Block>
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

        let pre_digest = find_pre_digest::<Block::Header>(&block.header)
            .map_err(|error| ConsensusError::ClientImport(error.to_string()))?;

        self.block_import_verification(
            block_hash,
            block.origin,
            block.header.clone(),
            block.body.clone(),
            &pre_digest,
        )
        .await
        .map_err(|error| ConsensusError::ClientImport(error.to_string()))?;

        let parent_weight = if block_number.is_one() {
            0
        } else {
            aux_schema::load_block_weight(&*self.client, block.header.parent_hash())
                .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
                .ok_or_else(|| {
                    ConsensusError::ClientImport(
                        Error::<Block::Header>::ParentBlockNoAssociatedWeight(block_hash)
                            .to_string(),
                    )
                })?
        };

        let added_weight = {
            let global_randomness = find_global_randomness_descriptor(&block.header)
                .expect("Verification of the header was done before this; qed")
                .expect("Verification of the header was done before this; qed")
                .global_randomness;
            let global_challenge =
                derive_global_challenge(&global_randomness, pre_digest.slot.into());

            // Verification of the local challenge was done before this
            let target = u64::from_be_bytes(
                derive_target(
                    &PublicKey::from_bytes(pre_digest.solution.public_key.as_ref())
                        .expect("Always correct length; qed"),
                    global_challenge,
                    &pre_digest.solution.local_challenge,
                )
                .expect("Verification of the local challenge was done before this; qed"),
            );
            let tag = u64::from_be_bytes(pre_digest.solution.tag);

            u128::from(u64::MAX - subspace_core_primitives::bidirectional_distance(&target, &tag))
        };
        let total_weight = parent_weight + added_weight;

        let info = self.client.info();

        aux_schema::write_block_weight(block_hash, total_weight, |values| {
            block
                .auxiliary
                .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
        });

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

        self.imported_block_notification_sender
            .notify(move || ImportedBlockNotification {
                block_number,
                root_block_sender,
            });

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
        + AuxStore
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>,
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

    let best_block_id = BlockId::Hash(client.info().best_hash);

    let confirmation_depth_k = TryInto::<BlockNumber>::try_into(
        client
            .runtime_api()
            .confirmation_depth_k(&best_block_id)
            .expect("Failed to get `confirmation_depth_k` from runtime API"),
    )
    .unwrap_or_else(|_| {
        panic!("Confirmation depth K can't be converted into BlockNumber");
    });

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
    chain_id: String,
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
        chain_id,
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

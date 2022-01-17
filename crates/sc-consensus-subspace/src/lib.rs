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

// TODO: Update this description, it is out of date now
//! # Subspace Proof-of-Storage Consensus
//!
//! Subspace is a slot-based block production mechanism which uses a Proof-of-Storage to randomly
//! perform the slot allocation. On every slot, all the farmers evaluate their disk-based plot. If
//! they have a tag (reflecting a commitment to a valid encoding) that it is lower than a given
//! threshold (which is proportional to the total space pledged by the network) they may produce a
//! new block. The proof of the Subspace function execution will be used by other peers to validate
//! the legitimacy of the slot claim.
//!
//! The engine is also responsible for collecting entropy on-chain which will be used to seed the
//! given PoR (Proof-of-Replication) challenge. An epoch is a contiguous number of slots under which
//! we will be using the same base PoR challenge. During an epoch all PoR outputs produced as a
//! result of block production will be collected into an on-chain randomness pool. Epoch changes are
//! announced one epoch in advance, i.e. when ending epoch N, we announce the parameters (i.e, new
//! randomness) for epoch N+2.
//!
//! Since the slot assignment is randomized, it is possible that a slot is claimed by multiple
//! farmers, in which case we will have a temporary fork, or that a slot is not claimed by any
//! farmer, in which case no block is produced. This means that block times are probabilistic.
//!
//! The protocol has a parameter `c` [0, 1] for which `1 - c` is the probability of a slot being
//! empty. The choice of this parameter affects the security of the protocol relating to maximum
//! tolerable network delays.
//!
//! The fork choice rule is weight-based, where weight equals the number of primary blocks in the
//! chain. We will pick the heaviest chain (more blocks) and will go with the longest one in case of
//! a tie.

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
mod verification;

use crate::notification::{SubspaceNotificationSender, SubspaceNotificationStream};
use crate::slot_worker::SubspaceSlotWorker;
pub use archiver::start_subspace_archiver;
use futures::channel::mpsc;
use futures::StreamExt;
use log::{debug, info, trace, warn};
use lru::LruCache;
use parking_lot::Mutex;
use prometheus_endpoint::Registry;
use sc_client_api::{backend::AuxStore, BlockchainEvents, ProvideUncles, UsageProvider};
use sc_consensus::block_import::{
    BlockCheckParams, BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult,
};
use sc_consensus::import_queue::{
    BasicQueue, BoxJustificationImport, DefaultImportQueue, Verifier,
};
use sc_consensus::JustificationSyncLink;
use sc_consensus_slots::{
    check_equivocation, BackoffAuthoringBlocksStrategy, CheckedHeader, InherentDataProviderExt,
    SlotProportion,
};
use sc_telemetry::{telemetry, TelemetryHandle, CONSENSUS_DEBUG, CONSENSUS_TRACE};
use sc_utils::mpsc::TracingUnboundedSender;
use schnorrkel::context::SigningContext;
use sp_api::{ApiExt, NumberFor, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::{Error as ClientError, HeaderBackend, HeaderMetadata, Result as ClientResult};
use sp_consensus::{
    BlockOrigin, CacheKeyId, CanAuthorWith, Environment, Error as ConsensusError, Proposer,
    SelectChain, SlotData, SyncOracle,
};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{
    CompatibleDigestItem, GlobalRandomnessDescriptor, PreDigest, SaltDescriptor, Solution,
    SolutionRangeDescriptor,
};
use sp_consensus_subspace::inherents::{InherentType, SubspaceInherentData};
use sp_consensus_subspace::{
    FarmerPublicKey, FarmerSignature, SubspaceApi, SubspaceGenesisConfiguration,
};
use sp_core::{ExecutionContext, H256};
use sp_inherents::{CreateInherentDataProviders, InherentData, InherentDataProvider};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header, One, Zero};
use std::cmp::Ordering;
use std::future::Future;
use std::{collections::HashMap, pin::Pin, sync::Arc, time::Duration};
pub use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{BlockNumber, RootBlock, Salt, Tag};
use subspace_solving::SOLUTION_SIGNING_CONTEXT;

/// Information about new slot that just arrived
#[derive(Debug, Copy, Clone)]
pub struct NewSlotInfo {
    /// Slot
    pub slot: Slot,
    /// Global slot challenge
    pub global_challenge: Tag,
    /// Salt
    pub salt: Salt,
    /// Salt for the next eon
    pub next_salt: Option<Salt>,
    /// Acceptable solution range
    pub solution_range: u64,
}

/// New slot notification with slot information and sender for solution for the slot.
#[derive(Debug, Clone)]
pub struct NewSlotNotification {
    /// New slot information.
    pub new_slot_info: NewSlotInfo,
    /// Sender that can be used to send solutions for the slot.
    pub solution_sender: TracingUnboundedSender<Solution<FarmerPublicKey>>,
}

/// Notification with block header hash that needs to be signed and sender for signature.
#[derive(Debug, Clone)]
pub struct BlockSigningNotification {
    /// Header hash of the block to be signed.
    pub header_hash: H256,
    /// Sender that can be used to send signature for the header.
    pub signature_sender: TracingUnboundedSender<FarmerSignature>,
}

/// Errors encountered by the Subspace authorship task.
#[derive(derive_more::Display, Debug)]
pub enum Error<B: BlockT> {
    /// Multiple Subspace pre-runtime digests
    #[display(fmt = "Multiple Subspace pre-runtime digests, rejecting!")]
    MultiplePreRuntimeDigests,
    /// No Subspace pre-runtime digest found
    #[display(fmt = "No Subspace pre-runtime digest found")]
    NoPreRuntimeDigest,
    /// Multiple Subspace global randomness digests
    #[display(fmt = "Multiple Subspace global randomness digests, rejecting!")]
    MultipleGlobalRandomnessDigests,
    /// Multiple Subspace solution range digests
    #[display(fmt = "Multiple Subspace solution range digests, rejecting!")]
    MultipleSolutionRangeDigests,
    /// Multiple Subspace salt digests
    #[display(fmt = "Multiple Subspace salt digests, rejecting!")]
    MultipleSaltDigests,
    /// Header rejected: too far in the future
    #[display(fmt = "Header {:?} rejected: too far in the future", _0)]
    TooFarInFuture(B::Hash),
    /// Parent unavailable. Cannot import
    #[display(fmt = "Parent ({}) of {} unavailable. Cannot import", _0, _1)]
    ParentUnavailable(B::Hash, B::Hash),
    /// Slot number must increase
    #[display(
        fmt = "Slot number must increase: parent slot: {}, this slot: {}",
        _0,
        _1
    )]
    SlotMustIncrease(Slot, Slot),
    /// Header has a bad seal
    #[display(fmt = "Header {:?} has a bad seal", _0)]
    HeaderBadSeal(B::Hash),
    /// Header is unsealed
    #[display(fmt = "Header {:?} is unsealed", _0)]
    HeaderUnsealed(B::Hash),
    /// Bad signature
    #[display(fmt = "Bad signature on {:?}", _0)]
    BadSignature(B::Hash),
    /// Bad solution signature
    #[display(fmt = "Bad solution signature on slot {:?}: {:?}", _0, _1)]
    BadSolutionSignature(Slot, schnorrkel::SignatureError),
    /// Bad local challenge
    #[display(fmt = "Local challenge is invalid for slot {}: {}", _0, _1)]
    BadLocalChallenge(Slot, schnorrkel::SignatureError),
    /// Solution is outside of solution range
    #[display(fmt = "Solution is outside of solution range for slot {}", _0)]
    OutsideOfSolutionRange(Slot),
    /// Invalid encoding of a piece
    #[display(fmt = "Invalid encoding for slot {}", _0)]
    InvalidEncoding(Slot),
    /// Invalid tag for salt
    #[display(fmt = "Invalid tag for salt for slot {}", _0)]
    InvalidTag(Slot),
    /// Parent block has no associated weight
    #[display(fmt = "Parent block of {} has no associated weight", _0)]
    ParentBlockNoAssociatedWeight(B::Hash),
    /// Block has no associated global randomness
    #[display(fmt = "Missing global randomness for block {}", _0)]
    MissingGlobalRandomness(B::Hash),
    /// Block has invalid associated global randomness
    #[display(fmt = "Invalid global randomness for block {}", _0)]
    InvalidGlobalRandomness(B::Hash),
    /// Block has no associated solution range
    #[display(fmt = "Missing solution range for block {}", _0)]
    MissingSolutionRange(B::Hash),
    /// Block has invalid associated solution range
    #[display(fmt = "Invalid solution range for block {}", _0)]
    InvalidSolutionRange(B::Hash),
    /// Block has no associated salt
    #[display(fmt = "Missing salt for block {}", _0)]
    MissingSalt(B::Hash),
    /// Block has invalid associated salt
    #[display(fmt = "Invalid salt for block {}", _0)]
    InvalidSalt(B::Hash),
    /// Farmer in block list
    #[display(fmt = "Farmer {} is in block list", _0)]
    FarmerInBlockList(FarmerPublicKey),
    /// Merkle Root not found
    #[display(fmt = "Records Root for segment index {} not found", _0)]
    RecordsRootNotFound(u64),
    /// Check inherents error
    #[display(fmt = "Checking inherents failed: {}", _0)]
    CheckInherents(sp_inherents::Error),
    /// Unhandled check inherents error
    #[display(
        fmt = "Checking inherents unhandled error: {}",
        "String::from_utf8_lossy(_0)"
    )]
    CheckInherentsUnhandled(sp_inherents::InherentIdentifier),
    /// Create inherents error.
    #[display(fmt = "Creating inherents failed: {}", _0)]
    CreateInherents(sp_inherents::Error),
    /// Client error
    Client(sp_blockchain::Error),
    /// Runtime Api error.
    RuntimeApi(sp_api::ApiError),
}

impl<B: BlockT> std::convert::From<Error<B>> for String {
    fn from(error: Error<B>) -> String {
        error.to_string()
    }
}

fn subspace_err<B: BlockT>(error: Error<B>) -> Error<B> {
    debug!(target: "subspace", "{}", error);
    error
}

/// A slot duration.
///
/// Create with [`Self::get`].
// FIXME: Once Rust has higher-kinded types, the duplication between this
// and `super::subspace::Config` can be eliminated.
// https://github.com/paritytech/substrate/issues/2434
#[derive(Clone)]
pub struct Config(sc_consensus_slots::SlotDuration<SubspaceGenesisConfiguration>);

impl Config {
    /// Fetch the config from the runtime.
    pub fn get<B: BlockT, C>(client: &C) -> ClientResult<Self>
    where
        C: AuxStore + ProvideRuntimeApi<B> + UsageProvider<B>,
        C::Api: SubspaceApi<B>,
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
        let runtime_api = client.runtime_api();

        let version = runtime_api.api_version::<dyn SubspaceApi<B>>(&best_block_id)?;

        let slot_duration = if version == Some(1) {
            runtime_api.configuration(&best_block_id)?
        } else {
            return Err(sp_blockchain::Error::VersionInvalid(
                "Unsupported or invalid SubspaceApi version".to_string(),
            ));
        };

        Ok(Self(sc_consensus_slots::SlotDuration::new(slot_duration)))
    }

    /// Get the inner slot duration
    pub fn slot_duration(&self) -> Duration {
        self.0.slot_duration()
    }
}

impl std::ops::Deref for Config {
    type Target = SubspaceGenesisConfiguration;

    fn deref(&self) -> &SubspaceGenesisConfiguration {
        &*self.0
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
    Client::Api: SubspaceApi<Block>,
    SC: SelectChain<Block> + 'static,
    E: Environment<Block, Error = Error> + Send + Sync + 'static,
    E::Proposer:
        Proposer<Block, Error = Error, Transaction = sp_api::TransactionFor<Client, Block>>,
    I: BlockImport<
            Block,
            Error = ConsensusError,
            Transaction = sp_api::TransactionFor<Client, Block>,
        > + Send
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
        // TODO: Figure out how to remove explicit schnorrkel dependency
        signing_context: schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT),
        block_proposal_slot_portion,
        max_block_proposal_slot_portion,
        telemetry,
    };

    info!(target: "subspace", "🧑‍🌾 Starting Subspace Authorship worker");
    let inner = sc_consensus_slots::start_slot_worker(
        subspace_link.config.0,
        select_chain,
        worker,
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
pub fn find_pre_digest<B: BlockT>(
    header: &B::Header,
) -> Result<PreDigest<FarmerPublicKey>, Error<B>> {
    // genesis block doesn't contain a pre digest so let's generate a
    // dummy one to not break any invariants in the rest of the code
    if header.number().is_zero() {
        return Ok(PreDigest {
            slot: Slot::from(0),
            solution: Solution::genesis_solution(),
        });
    }

    let mut pre_digest = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for pre runtime digest", log);
        match (log.as_subspace_pre_digest(), pre_digest.is_some()) {
            (Some(_), true) => return Err(subspace_err(Error::MultiplePreRuntimeDigests)),
            (None, _) => trace!(target: "subspace", "Ignoring digest not meant for us"),
            (s, false) => pre_digest = s,
        }
    }
    pre_digest.ok_or_else(|| subspace_err(Error::NoPreRuntimeDigest))
}

/// Extract the Subspace global randomness descriptor from the given header.
fn find_global_randomness_descriptor<B: BlockT>(
    header: &B::Header,
) -> Result<Option<GlobalRandomnessDescriptor>, Error<B>> {
    let mut global_randomness_descriptor = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for global randomness digest.", log);
        match (
            log.as_global_randomness_descriptor(),
            global_randomness_descriptor.is_some(),
        ) {
            (Some(_), true) => return Err(subspace_err(Error::MultipleGlobalRandomnessDigests)),
            (Some(global_randomness), false) => {
                global_randomness_descriptor = Some(global_randomness)
            }
            _ => trace!(target: "subspace", "Ignoring digest not meant for us"),
        }
    }

    Ok(global_randomness_descriptor)
}

/// Extract the Subspace solution range descriptor from the given header.
fn find_solution_range_descriptor<B: BlockT>(
    header: &B::Header,
) -> Result<Option<SolutionRangeDescriptor>, Error<B>> {
    let mut solution_range_descriptor = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for solution range digest.", log);
        match (
            log.as_solution_range_descriptor(),
            solution_range_descriptor.is_some(),
        ) {
            (Some(_), true) => return Err(subspace_err(Error::MultipleSolutionRangeDigests)),
            (Some(solution_range), false) => solution_range_descriptor = Some(solution_range),
            _ => trace!(target: "subspace", "Ignoring digest not meant for us"),
        }
    }

    Ok(solution_range_descriptor)
}

/// Extract the Subspace salt descriptor from the given header.
fn find_salt_descriptor<B: BlockT>(header: &B::Header) -> Result<Option<SaltDescriptor>, Error<B>> {
    let mut salt_descriptor = None;
    for log in header.digest().logs() {
        trace!(target: "subspace", "Checking log {:?}, looking for salt digest.", log);
        match (log.as_salt_descriptor(), salt_descriptor.is_some()) {
            (Some(_), true) => return Err(subspace_err(Error::MultipleSaltDigests)),
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
    block_signing_notification_sender: SubspaceNotificationSender<BlockSigningNotification>,
    block_signing_notification_stream: SubspaceNotificationStream<BlockSigningNotification>,
    archived_segment_notification_sender: SubspaceNotificationSender<ArchivedSegment>,
    archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegment>,
    imported_block_notification_stream:
        SubspaceNotificationStream<(NumberFor<Block>, mpsc::Sender<RootBlock>)>,
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
    pub fn block_signing_notification_stream(
        &self,
    ) -> SubspaceNotificationStream<BlockSigningNotification> {
        self.block_signing_notification_stream.clone()
    }

    /// Get stream with notifications about archived segment creation
    pub fn archived_segment_notification_stream(
        &self,
    ) -> SubspaceNotificationStream<ArchivedSegment> {
        self.archived_segment_notification_stream.clone()
    }

    /// Get blocks that are expected to be included at specified block number.
    pub fn root_blocks_for_block(&self, block_number: NumberFor<Block>) -> Vec<RootBlock> {
        self.root_blocks
            .lock()
            .get(&block_number)
            .cloned()
            .unwrap_or_default()
    }
}

/// A verifier for Subspace blocks.
pub struct SubspaceVerifier<Block: BlockT, Client, SelectChain, CAW, CIDP> {
    client: Arc<Client>,
    select_chain: SelectChain,
    create_inherent_data_providers: CIDP,
    can_author_with: CAW,
    /// Root blocks that are expected to appear in the corresponding blocks, used for block
    /// validation
    root_blocks: Arc<Mutex<LruCache<NumberFor<Block>, Vec<RootBlock>>>>,
    telemetry: Option<TelemetryHandle>,
    signing_context: SigningContext,
}

impl<Block, Client, SelectChain, CAW, CIDP> SubspaceVerifier<Block, Client, SelectChain, CAW, CIDP>
where
    Block: BlockT,
    Client: AuxStore + HeaderBackend<Block> + HeaderMetadata<Block> + ProvideRuntimeApi<Block>,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block>,
    SelectChain: sp_consensus::SelectChain<Block>,
    CAW: CanAuthorWith<Block>,
    CIDP: CreateInherentDataProviders<Block, ()>,
{
    async fn check_inherents(
        &self,
        block: Block,
        block_id: BlockId<Block>,
        inherent_data: InherentData,
        create_inherent_data_providers: CIDP::InherentDataProviders,
        execution_context: ExecutionContext,
    ) -> Result<(), Error<Block>> {
        if let Err(e) = self.can_author_with.can_author_with(&block_id) {
            debug!(
                target: "subspace",
                "Skipping `check_inherents` as authoring version is not compatible: {}",
                e,
            );

            return Ok(());
        }

        let inherent_res = self
            .client
            .runtime_api()
            .check_inherents_with_context(&block_id, execution_context, block, inherent_data)
            .map_err(Error::RuntimeApi)?;

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

        Ok(())
    }

    async fn check_and_report_equivocation(
        &self,
        slot_now: Slot,
        slot: Slot,
        header: &Block::Header,
        author: &FarmerPublicKey,
        origin: &BlockOrigin,
    ) -> Result<(), Error<Block>> {
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

type BlockVerificationResult<Block> = Result<
    (
        BlockImportParams<Block, ()>,
        Option<Vec<(CacheKeyId, Vec<u8>)>>,
    ),
    String,
>;

#[async_trait::async_trait]
impl<Block, Client, SelectChain, CAW, CIDP> Verifier<Block>
    for SubspaceVerifier<Block, Client, SelectChain, CAW, CIDP>
where
    Block: BlockT,
    Client: HeaderMetadata<Block, Error = sp_blockchain::Error>
        + HeaderBackend<Block>
        + ProvideRuntimeApi<Block>
        + Send
        + Sync
        + AuxStore,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block>,
    SelectChain: sp_consensus::SelectChain<Block>,
    CAW: CanAuthorWith<Block> + Send + Sync,
    CIDP: CreateInherentDataProviders<Block, ()> + Send + Sync,
    CIDP::InherentDataProviders: InherentDataProviderExt + Send + Sync,
{
    async fn verify(
        &mut self,
        mut block: BlockImportParams<Block, ()>,
    ) -> BlockVerificationResult<Block> {
        trace!(
            target: "subspace",
            "Verifying origin: {:?} header: {:?} justification(s): {:?} body: {:?}",
            block.origin,
            block.header,
            block.justifications,
            block.body,
        );

        let hash = block.header.hash();
        let parent_hash = *block.header.parent_hash();
        let parent_block_id = BlockId::Hash(parent_hash);

        debug!(target: "subspace", "We have {:?} logs in this header", block.header.digest().logs().len());

        let create_inherent_data_providers = self
            .create_inherent_data_providers
            .create_inherent_data_providers(parent_hash, ())
            .await
            .map_err(|e| Error::<Block>::Client(sp_consensus::Error::from(e).into()))?;

        let slot_now = create_inherent_data_providers.slot();

        let checked_header = {
            let pre_digest = find_pre_digest::<Block>(&block.header)?;

            let global_randomness = find_global_randomness_descriptor::<Block>(&block.header)?
                .ok_or(Error::<Block>::MissingGlobalRandomness(hash))?
                .global_randomness;
            let correct_global_randomness = slot_worker::extract_global_randomness_for_block(
                self.client.as_ref(),
                &parent_block_id,
            )
            .map_err(Error::<Block>::RuntimeApi)?;
            if global_randomness != correct_global_randomness {
                return Err(Error::<Block>::InvalidGlobalRandomness(hash).into());
            }

            let solution_range = find_solution_range_descriptor::<Block>(&block.header)?
                .ok_or(Error::<Block>::MissingSolutionRange(hash))?
                .solution_range;
            let correct_solution_range = slot_worker::extract_solution_range_for_block(
                self.client.as_ref(),
                &parent_block_id,
            )
            .map_err(Error::<Block>::RuntimeApi)?;
            if solution_range != correct_solution_range {
                return Err(Error::<Block>::InvalidSolutionRange(hash).into());
            }

            let salt = find_salt_descriptor::<Block>(&block.header)?
                .ok_or(Error::<Block>::MissingSalt(hash))?
                .salt;
            let correct_salt =
                slot_worker::extract_salt_for_block(self.client.as_ref(), &parent_block_id)
                    .map_err(Error::<Block>::RuntimeApi)?
                    .0;
            if salt != correct_salt {
                return Err(Error::<Block>::InvalidSalt(hash).into());
            }

            if self
                .client
                .runtime_api()
                .is_in_block_list(&parent_block_id, &pre_digest.solution.public_key)
                .map_err(Error::<Block>::RuntimeApi)?
            {
                warn!(
                    target: "subspace",
                    "Ignoring block with solution provided by farmer in block list: {}",
                    pre_digest.solution.public_key
                );

                return Err(
                    Error::<Block>::FarmerInBlockList(pre_digest.solution.public_key).into(),
                );
            }

            // TODO: This assumes fixed size segments, which might not be the case
            let record_size = self
                .client
                .runtime_api()
                .record_size(&parent_block_id)
                .expect("Failed to get `record_size` from runtime API");
            let recorded_history_segment_size = self
                .client
                .runtime_api()
                .recorded_history_segment_size(&parent_block_id)
                .expect("Failed to get `recorded_history_segment_size` from runtime API");
            let merkle_num_leaves = u64::from(recorded_history_segment_size / record_size * 2);
            let segment_index = pre_digest.solution.piece_index / merkle_num_leaves;
            let position = pre_digest.solution.piece_index % merkle_num_leaves;
            let mut maybe_records_root = self
                .client
                .runtime_api()
                .records_root(&parent_block_id, segment_index)
                .unwrap_or_else(|error| {
                    panic!(
                        "Failed to get Merkle Root for segment {} from runtime API: {}",
                        segment_index, error
                    );
                });

            // This is not a very nice hack due to the fact that at the time first block is produced
            // extrinsics with root blocks are not yet in runtime.
            if maybe_records_root.is_none() && block.header.number().is_one() {
                maybe_records_root =
                    self.root_blocks
                        .lock()
                        .iter()
                        .find_map(|(_block_number, root_blocks)| {
                            root_blocks.iter().find_map(|root_block| {
                                if root_block.segment_index() == segment_index {
                                    Some(root_block.records_root())
                                } else {
                                    None
                                }
                            })
                        });
            }

            let records_root = match maybe_records_root {
                Some(records_root) => records_root,
                None => {
                    return Err(Error::<Block>::RecordsRootNotFound(segment_index).into());
                }
            };

            // We add one to the current slot to allow for some small drift.
            // FIXME #1019 in the future, alter this queue to allow deferring of headers
            let v_params = verification::VerificationParams {
                header: block.header.clone(),
                pre_digest,
                slot_now: slot_now + 1,
                global_randomness: &global_randomness,
                solution_range,
                salt,
                records_root: &records_root,
                position,
                record_size,
                signing_context: &self.signing_context,
            };

            verification::check_header::<Block>(v_params)?
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
                        "Error checking/reporting Subspace equivocation: {:?}",
                        err
                    );
                }

                // if the body is passed through, we need to use the runtime
                // to check that the internally-set timestamp in the inherents
                // actually matches the slot set in the seal.
                if let Some(inner_body) = block.body {
                    let mut inherent_data = create_inherent_data_providers
                        .create_inherent_data()
                        .map_err(Error::<Block>::CreateInherents)?;
                    inherent_data.replace_subspace_inherent_data(InherentType {
                        slot,
                        root_blocks: self
                            .root_blocks
                            .lock()
                            .peek(block.header.number())
                            .cloned()
                            .unwrap_or_default(),
                    });
                    let new_block = Block::new(pre_header.clone(), inner_body);

                    self.check_inherents(
                        new_block.clone(),
                        BlockId::Hash(parent_hash),
                        inherent_data,
                        create_inherent_data_providers,
                        block.origin.into(),
                    )
                    .await?;

                    let (_, inner_body) = new_block.deconstruct();
                    block.body = Some(inner_body);
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
                Err(Error::<Block>::TooFarInFuture(hash).into())
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
pub struct SubspaceBlockImport<Block: BlockT, Client, I> {
    inner: I,
    client: Arc<Client>,
    config: Config,
    imported_block_notification_sender:
        SubspaceNotificationSender<(NumberFor<Block>, mpsc::Sender<RootBlock>)>,
    /// Root blocks that are expected to appear in the corresponding blocks, used for block
    /// validation
    root_blocks: Arc<Mutex<LruCache<NumberFor<Block>, Vec<RootBlock>>>>,
}

impl<Block: BlockT, I: Clone, Client> Clone for SubspaceBlockImport<Block, Client, I> {
    fn clone(&self) -> Self {
        SubspaceBlockImport {
            inner: self.inner.clone(),
            client: self.client.clone(),
            config: self.config.clone(),
            imported_block_notification_sender: self.imported_block_notification_sender.clone(),
            root_blocks: Arc::clone(&self.root_blocks),
        }
    }
}

impl<Block: BlockT, Client, I> SubspaceBlockImport<Block, Client, I> {
    fn new(
        client: Arc<Client>,
        block_import: I,
        config: Config,
        imported_block_notification_sender: SubspaceNotificationSender<(
            NumberFor<Block>,
            mpsc::Sender<RootBlock>,
        )>,
        root_blocks: Arc<Mutex<LruCache<NumberFor<Block>, Vec<RootBlock>>>>,
    ) -> Self {
        SubspaceBlockImport {
            client,
            inner: block_import,
            config,
            imported_block_notification_sender,
            root_blocks,
        }
    }
}

#[async_trait::async_trait]
impl<Block, Client, Inner> BlockImport<Block> for SubspaceBlockImport<Block, Client, Inner>
where
    Block: BlockT,
    Inner: BlockImport<
            Block,
            Transaction = sp_api::TransactionFor<Client, Block>,
            Error = ConsensusError,
        > + Send
        + Sync,
    Inner::Error: Into<ConsensusError>,
    Client: HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + AuxStore
        + ProvideRuntimeApi<Block>
        + Send
        + Sync,
    Client::Api: SubspaceApi<Block> + ApiExt<Block>,
{
    type Error = ConsensusError;
    type Transaction = sp_api::TransactionFor<Client, Block>;

    async fn import_block(
        &mut self,
        mut block: BlockImportParams<Block, Self::Transaction>,
        new_cache: HashMap<CacheKeyId, Vec<u8>>,
    ) -> Result<ImportResult, Self::Error> {
        let block_hash = block.post_hash();
        let block_number = *block.header.number();

        // early exit if block already in chain, otherwise the check for
        // epoch changes will error when trying to re-import an epoch change
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
            Err(e) => return Err(ConsensusError::ClientImport(e.to_string())),
        }

        let pre_digest = find_pre_digest::<Block>(&block.header).expect(
            "valid Subspace headers must contain a predigest; header has been already verified; \
            qed",
        );
        let slot = pre_digest.slot;

        let parent_hash = *block.header.parent_hash();
        let parent_header = self
            .client
            .header(BlockId::Hash(parent_hash))
            .map_err(|e| ConsensusError::ChainLookup(e.to_string()))?
            .ok_or_else(|| {
                ConsensusError::ChainLookup(
                    subspace_err(Error::<Block>::ParentUnavailable(parent_hash, block_hash)).into(),
                )
            })?;

        let parent_slot = find_pre_digest::<Block>(&parent_header)
            .map(|d| d.slot)
            .expect(
                "parent is non-genesis; valid Subspace headers contain a pre-digest; header has \
                already been verified; qed",
            );

        // Make sure that slot number is strictly increasing
        if slot <= parent_slot {
            return Err(ConsensusError::ClientImport(
                subspace_err(Error::<Block>::SlotMustIncrease(parent_slot, slot)).into(),
            ));
        }

        let parent_weight = if *parent_header.number() == Zero::zero() {
            0
        } else {
            aux_schema::load_block_weight(&*self.client, parent_hash)
                .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
                .ok_or_else(|| {
                    ConsensusError::ClientImport(
                        subspace_err(Error::<Block>::ParentBlockNoAssociatedWeight(block_hash))
                            .into(),
                    )
                })?
        };

        let total_weight = parent_weight + pre_digest.added_weight();

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
                    .map_err(|e| ConsensusError::ChainLookup(format!("{:?}", e)))?
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

        // If there are root blocks expected to be included in this block, check them
        if let Some(correct_root_blocks) = self.root_blocks.lock().peek(&block_number) {
            let mut found = false;
            for extrinsic in block
                .body
                .as_ref()
                .expect("Light client or fast sync is unsupported; qed")
            {
                match self
                    .client
                    .runtime_api()
                    .extract_root_blocks(&BlockId::Hash(parent_hash), extrinsic)
                {
                    Ok(Some(found_root_blocks)) => {
                        if correct_root_blocks == &found_root_blocks {
                            found = true;
                            break;
                        } else {
                            warn!(
                                target: "subspace",
                                "Found root blocks: {:?}",
                                found_root_blocks
                            );
                            warn!(
                                target: "subspace",
                                "Correct root blocks: {:?}",
                                correct_root_blocks
                            );
                            return Err(ConsensusError::ClientImport(
                                "Found incorrect set of root blocks".to_string(),
                            ));
                        }
                    }
                    Ok(None) => {
                        // Some other extrinsic, ignore
                    }
                    Err(error) => {
                        return Err(ConsensusError::ClientImport(format!(
                            "Failed to make runtime API call: {:?}",
                            error
                        )));
                    }
                }
            }

            if !found {
                return Err(ConsensusError::ClientImport(format!(
                    "Stored root block extrinsics were not found: {:?}",
                    correct_root_blocks,
                )));
            }
        }

        let import_result = self.inner.import_block(block, new_cache).await?;
        let (root_block_sender, mut root_block_receiver) = mpsc::channel(0);

        self.imported_block_notification_sender
            .notify(move || (block_number, root_block_sender));

        let next_block_number = block_number + One::one();
        while let Some(root_block) = root_block_receiver.next().await {
            {
                let mut root_blocks = self.root_blocks.lock();
                if let Some(list) = root_blocks.get_mut(&next_block_number) {
                    list.push(root_block);
                } else {
                    root_blocks.put(next_block_number, vec![root_block]);
                }
            }
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
pub fn block_import<Client, Block: BlockT, I>(
    config: Config,
    wrapped_block_import: I,
    client: Arc<Client>,
) -> ClientResult<(SubspaceBlockImport<Block, Client, I>, SubspaceLink<Block>)>
where
    Client: ProvideRuntimeApi<Block>
        + AuxStore
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>,
    Client::Api: SubspaceApi<Block>,
{
    let (new_slot_notification_sender, new_slot_notification_stream) =
        notification::channel("subspace_new_slot_notification_stream");
    let (block_signing_notification_sender, block_signing_notification_stream) =
        notification::channel("subspace_block_signing_notification_stream");
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
        config: config.clone(),
        new_slot_notification_sender,
        new_slot_notification_stream,
        block_signing_notification_sender,
        block_signing_notification_stream,
        archived_segment_notification_sender,
        archived_segment_notification_stream,
        imported_block_notification_stream,
        root_blocks: Arc::new(Mutex::new(LruCache::new(confirmation_depth_k as usize))),
    };

    let import = SubspaceBlockImport::new(
        client,
        wrapped_block_import,
        config,
        imported_block_notification_sender,
        Arc::clone(&link.root_blocks),
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
pub fn import_queue<Block: BlockT, Client, SelectChain, Inner, CAW, CIDP>(
    subspace_link: &SubspaceLink<Block>,
    block_import: Inner,
    justification_import: Option<BoxJustificationImport<Block>>,
    client: Arc<Client>,
    select_chain: SelectChain,
    create_inherent_data_providers: CIDP,
    spawner: &impl sp_core::traits::SpawnEssentialNamed,
    registry: Option<&Registry>,
    can_author_with: CAW,
    telemetry: Option<TelemetryHandle>,
) -> ClientResult<DefaultImportQueue<Block, Client>>
where
    Inner: BlockImport<
            Block,
            Error = ConsensusError,
            Transaction = sp_api::TransactionFor<Client, Block>,
        > + Send
        + Sync
        + 'static,
    Client: ProvideRuntimeApi<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + AuxStore
        + Send
        + Sync
        + 'static,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block> + ApiExt<Block>,
    SelectChain: sp_consensus::SelectChain<Block> + 'static,
    CAW: CanAuthorWith<Block> + Send + Sync + 'static,
    CIDP: CreateInherentDataProviders<Block, ()> + Send + Sync + 'static,
    CIDP::InherentDataProviders: InherentDataProviderExt + Send + Sync,
{
    let verifier = SubspaceVerifier {
        select_chain,
        create_inherent_data_providers,
        can_author_with,
        root_blocks: Arc::clone(&subspace_link.root_blocks),
        telemetry,
        client,
        // TODO: Figure out how to remove explicit schnorrkel dependency
        signing_context: schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT),
    };

    Ok(BasicQueue::new(
        verifier,
        Box::new(block_import),
        justification_import,
        spawner,
        registry,
    ))
}

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
#![feature(drain_filter, try_blocks)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod archiver;
pub mod aux_schema;
pub mod notification;
mod slot_worker;
#[cfg(test)]
mod tests;

use crate::notification::{SubspaceNotificationSender, SubspaceNotificationStream};
use crate::slot_worker::{SlotWorkerSyncOracle, SubspaceSlotWorker};
pub use archiver::create_subspace_archiver;
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
use sc_consensus::JustificationSyncLink;
use sc_consensus_slots::{
    check_equivocation, BackoffAuthoringBlocksStrategy, InherentDataProviderExt, SlotProportion,
};
use sc_telemetry::{telemetry, TelemetryHandle, CONSENSUS_DEBUG, CONSENSUS_TRACE};
use sc_utils::mpsc::TracingUnboundedSender;
use schnorrkel::context::SigningContext;
use sp_api::{ApiError, ApiExt, BlockT, HeaderT, NumberFor, ProvideRuntimeApi, TransactionFor};
use sp_block_builder::BlockBuilder as BlockBuilderApi;
use sp_blockchain::{Error as ClientError, HeaderBackend, HeaderMetadata, Result as ClientResult};
use sp_consensus::{
    BlockOrigin, Environment, Error as ConsensusError, Proposer, SelectChain, SyncOracle,
};
use sp_consensus_slots::{Slot, SlotDuration};
use sp_consensus_subspace::digests::{
    extract_pre_digest, extract_subspace_digest_items, Error as DigestError, SubspaceDigestItems,
};
use sp_consensus_subspace::{
    check_header, ChainConstants, CheckedHeader, FarmerPublicKey, FarmerSignature, SubspaceApi,
    VerificationError, VerificationParams,
};
use sp_core::H256;
use sp_inherents::{CreateInherentDataProviders, InherentDataProvider};
use sp_runtime::traits::One;
use std::cmp::Ordering;
use std::future::Future;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use subspace_archiving::archiver::{Archiver, NewArchivedSegment};
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{
    Blake2b256Hash, BlockWeight, SectorId, SegmentCommitment, SegmentHeader, SegmentIndex,
    Solution, SolutionRange,
};
use subspace_solving::{derive_global_challenge, REWARD_SIGNING_CONTEXT};
use subspace_verification::{
    derive_audit_chunk, Error as VerificationPrimitiveError, VerifySolutionParams,
};

/// Information about new slot that just arrived
#[derive(Debug, Copy, Clone)]
pub struct NewSlotInfo {
    /// Slot
    pub slot: Slot,
    /// Global slot challenge
    pub global_challenge: Blake2b256Hash,
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
    /// Sender for pausing the block import when executor is not fast enough to process
    /// the primary block.
    pub acknowledgement_sender: mpsc::Sender<()>,
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
    /// Solution is outside of solution range
    #[error("Solution is outside of solution range for slot {0}")]
    OutsideOfSolutionRange(Slot),
    /// Invalid encoding of a piece
    #[error("Invalid encoding for slot {0}")]
    InvalidEncoding(Slot),
    /// Parent block has no associated weight
    #[error("Parent block of {0} has no associated weight")]
    ParentBlockNoAssociatedWeight(Header::Hash),
    /// Block has invalid associated global randomness
    #[error("Invalid global randomness for block {0}")]
    InvalidGlobalRandomness(Header::Hash),
    /// Block has invalid associated solution range
    #[error("Invalid solution range for block {0}")]
    InvalidSolutionRange(Header::Hash),
    /// Invalid set of segment headers
    #[error("Invalid set of segment headers")]
    InvalidSetOfSegmentHeaders,
    /// Stored segment header extrinsic was not found
    #[error("Stored segment header extrinsic was not found: {0:?}")]
    SegmentHeadersExtrinsicNotFound(Vec<SegmentHeader>),
    /// Duplicated segment commitment
    #[error(
        "Different segment commitment for segment index {0} was found in storage, likely fork \
        below archiving point"
    )]
    DifferentSegmentCommitment(SegmentIndex),
    /// Farmer in block list
    #[error("Farmer {0} is in block list")]
    FarmerInBlockList(FarmerPublicKey),
    /// Merkle Root not found
    #[error("Segment commitment for segment index {0} not found")]
    SegmentCommitmentNotFound(SegmentIndex),
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
                VerificationPrimitiveError::InvalidPiece => Error::InvalidEncoding(slot),
                VerificationPrimitiveError::OutsideSolutionRange => {
                    Error::OutsideOfSolutionRange(slot)
                }
                VerificationPrimitiveError::InvalidSolutionSignature(err) => {
                    Error::BadSolutionSignature(slot, err)
                }
                VerificationPrimitiveError::MissingKzgInstance => {
                    unreachable!("Implementation bug");
                }
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

/// Read configuration from the runtime state at current best block.
pub fn slot_duration<Block: BlockT, Client>(client: &Client) -> ClientResult<SlotDuration>
where
    Block: BlockT,
    Client: AuxStore + ProvideRuntimeApi<Block> + UsageProvider<Block>,
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
{
    let block_hash = if client.usage_info().chain.finalized_state.is_some() {
        client.usage_info().chain.best_hash
    } else {
        debug!(target: "subspace", "No finalized state is available. Reading config from genesis");
        client.usage_info().chain.genesis_hash
    };

    Ok(SlotDuration::from_millis(
        client
            .runtime_api()
            .slot_duration(block_hash)?
            .as_millis()
            .try_into()
            .expect("Slot duration in ms never exceeds u64; qed"),
    ))
}

/// Parameters for Subspace.
pub struct SubspaceParams<B: BlockT, C, SC, E, I, SO, L, CIDP, BS> {
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
pub fn start_subspace<Block, Client, SC, E, I, SO, CIDP, BS, L, Error>(
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
        block_proposal_slot_portion,
        max_block_proposal_slot_portion,
        telemetry,
    }: SubspaceParams<Block, Client, SC, E, I, SO, L, CIDP, BS>,
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
        subspace_link.slot_duration(),
        select_chain,
        sc_consensus_slots::SimpleSlotWorkerToSlotWorker(worker),
        SlotWorkerSyncOracle {
            force_authoring,
            inner: sync_oracle,
        },
        create_inherent_data_providers,
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
    slot_duration: SlotDuration,
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
    /// Get the slot duration from this link.
    pub fn slot_duration(&self) -> SlotDuration {
        self.slot_duration
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

    /// Get the first found segment commitment by segment index.
    pub fn segment_commitment_by_segment_index(
        &self,
        segment_index: SegmentIndex,
    ) -> Option<SegmentCommitment> {
        self.segment_headers
            .lock()
            .iter()
            .find_map(|(_block_number, segment_headers)| {
                segment_headers.iter().find_map(|segment_header| {
                    if segment_header.segment_index() == segment_index {
                        Some(segment_header.segment_commitment())
                    } else {
                        None
                    }
                })
            })
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
    Client: AuxStore + HeaderBackend<Block> + ProvideRuntimeApi<Block>,
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
            let best_hash = self
                .select_chain
                .best_chain()
                .await
                .map(|h| h.hash())
                .map_err(|e| Error::Client(e.into()))?;

            // submit equivocation report at best block.
            self.client
                .runtime_api()
                .submit_report_equivocation_extrinsic(best_hash, equivocation_proof)
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
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block> + Send + Sync + AuxStore,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey>,
    SelectChain: sp_consensus::SelectChain<Block>,
    SN: Fn() -> Slot + Send + Sync + 'static,
{
    async fn verify(
        &mut self,
        mut block: BlockImportParams<Block, ()>,
    ) -> Result<BlockImportParams<Block, ()>, String> {
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
            .is_in_block_list(*block.header.parent_hash(), &pre_digest.solution.public_key)
            .or_else(|error| {
                if block.state_action.skip_execution_checks() {
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
        // Proof-of-Archival-Storage. In order to verify PoAS randomness and solution range
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
                    verify_solution_params: &VerifySolutionParams {
                        global_randomness: subspace_digest_items.global_randomness,
                        solution_range: subspace_digest_items.solution_range,
                        piece_check_params: None,
                    },
                    reward_signing_context: &self.reward_signing_context,
                },
                Some(pre_digest),
                None,
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

                Ok(block)
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
pub struct SubspaceBlockImport<Block: BlockT, Client, I, CIDP> {
    inner: I,
    client: Arc<Client>,
    block_importing_notification_sender:
        SubspaceNotificationSender<BlockImportingNotification<Block>>,
    subspace_link: SubspaceLink<Block>,
    create_inherent_data_providers: CIDP,
}

impl<Block, I, Client, CIDP> Clone for SubspaceBlockImport<Block, Client, I, CIDP>
where
    Block: BlockT,
    I: Clone,
    CIDP: Clone,
{
    fn clone(&self) -> Self {
        SubspaceBlockImport {
            inner: self.inner.clone(),
            client: self.client.clone(),
            block_importing_notification_sender: self.block_importing_notification_sender.clone(),
            subspace_link: self.subspace_link.clone(),
            create_inherent_data_providers: self.create_inherent_data_providers.clone(),
        }
    }
}

impl<Block, Client, I, CIDP> SubspaceBlockImport<Block, Client, I, CIDP>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block> + HeaderBackend<Block> + AuxStore,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey> + ApiExt<Block>,
    CIDP: CreateInherentDataProviders<Block, SubspaceLink<Block>> + Send + Sync + 'static,
{
    fn new(
        client: Arc<Client>,
        block_import: I,
        block_importing_notification_sender: SubspaceNotificationSender<
            BlockImportingNotification<Block>,
        >,
        subspace_link: SubspaceLink<Block>,
        create_inherent_data_providers: CIDP,
    ) -> Self {
        SubspaceBlockImport {
            client,
            inner: block_import,
            block_importing_notification_sender,
            subspace_link,
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
        root_plot_public_key: &Option<FarmerPublicKey>,
        subspace_digest_items: &SubspaceDigestItems<
            FarmerPublicKey,
            FarmerPublicKey,
            FarmerSignature,
        >,
        skip_runtime_access: bool,
    ) -> Result<(), Error<Block::Header>> {
        let block_number = *header.number();
        let parent_hash = *header.parent_hash();

        let pre_digest = &subspace_digest_items.pre_digest;

        if let Some(root_plot_public_key) = root_plot_public_key {
            if &pre_digest.solution.public_key != root_plot_public_key {
                // Only root plot public key is allowed.
                return Err(Error::OnlyRootPlotPublicKeyAllowed);
            }
        }

        // Check if farmer's plot is burned.
        // TODO: Add to header and store in aux storage?
        if self
            .client
            .runtime_api()
            .is_in_block_list(parent_hash, &pre_digest.solution.public_key)
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
            .header(parent_hash)?
            .ok_or(Error::ParentUnavailable(parent_hash, block_hash))?;

        let (correct_global_randomness, correct_solution_range) = if block_number.is_one() {
            // Genesis block doesn't contain usual digest items, we need to query runtime API
            // instead
            let correct_global_randomness = slot_worker::extract_global_randomness_for_block(
                self.client.as_ref(),
                parent_hash,
            )?;
            let (correct_solution_range, _) =
                slot_worker::extract_solution_ranges_for_block(self.client.as_ref(), parent_hash)?;

            (correct_global_randomness, correct_solution_range)
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

            (correct_global_randomness, correct_solution_range)
        };

        if subspace_digest_items.global_randomness != correct_global_randomness {
            return Err(Error::InvalidGlobalRandomness(block_hash));
        }

        if subspace_digest_items.solution_range != correct_solution_range {
            return Err(Error::InvalidSolutionRange(block_hash));
        }

        let sector_id = SectorId::new(
            &(&pre_digest.solution.public_key).into(),
            pre_digest.solution.sector_index,
        );

        // TODO: Derive `pre_digest.solution.piece_offset` from local challenge instead

        let piece_index = sector_id.derive_piece_index(
            pre_digest.solution.piece_offset,
            pre_digest.solution.total_pieces,
        );
        let position = piece_index.position();
        let segment_index = piece_index.segment_index();

        // This is not a very nice hack due to the fact that at the time first block is produced
        // extrinsics with segment headers are not yet in runtime.
        let maybe_segment_commitment = if block_number.is_one() {
            let genesis_block_hash = self.client.info().genesis_hash;
            let archived_segments = Archiver::new(self.subspace_link.kzg.clone())
                .expect("Incorrect parameters for archiver")
                .add_block(
                    self.client
                        .block(genesis_block_hash)?
                        .ok_or(Error::GenesisUnavailable)?
                        .encode(),
                    BlockObjectMapping::default(),
                );
            archived_segments.into_iter().find_map(|archived_segment| {
                if archived_segment.segment_header.segment_index() == segment_index {
                    Some(archived_segment.segment_header.segment_commitment())
                } else {
                    None
                }
            })
        } else {
            aux_schema::load_segment_commitment(self.client.as_ref(), segment_index)?
        };

        let segment_commitment =
            maybe_segment_commitment.ok_or(Error::SegmentCommitmentNotFound(segment_index))?;

        // Piece is not checked during initial block verification because it requires access to
        // segment header, check it now.
        subspace_verification::check_piece(
            &self.subspace_link.kzg,
            &segment_commitment,
            position,
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

                let inherent_res = self.client.runtime_api().check_inherents_with_context(
                    parent_hash,
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
impl<Block, Client, Inner, CIDP> BlockImport<Block>
    for SubspaceBlockImport<Block, Client, Inner, CIDP>
where
    Block: BlockT,
    Inner: BlockImport<Block, Transaction = TransactionFor<Client, Block>, Error = ConsensusError>
        + Send
        + Sync,
    Inner::Error: Into<ConsensusError>,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + AuxStore
        + Send
        + Sync,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey> + ApiExt<Block>,
    CIDP: CreateInherentDataProviders<Block, SubspaceLink<Block>> + Send + Sync + 'static,
{
    type Error = ConsensusError;
    type Transaction = TransactionFor<Client, Block>;

    async fn import_block(
        &mut self,
        mut block: BlockImportParams<Block, Self::Transaction>,
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
            block.origin,
            block.header.clone(),
            block.body.clone(),
            &root_plot_public_key,
            &subspace_digest_items,
            skip_execution_checks,
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

            let sector_id = SectorId::new(
                &(&pre_digest.solution.public_key).into(),
                pre_digest.solution.sector_index,
            );

            let local_challenge = sector_id.derive_local_challenge(&global_challenge);

            let audit_chunk = derive_audit_chunk(&pre_digest.solution.chunk.to_bytes());

            BlockWeight::from(
                SolutionRange::MAX
                    - subspace_core_primitives::bidirectional_distance(
                        &local_challenge,
                        &audit_chunk,
                    ),
            )
        };
        let total_weight = parent_weight + added_weight;

        let info = self.client.info();

        aux_schema::write_block_weight(block_hash, total_weight, |values| {
            block
                .auxiliary
                .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
        });

        for (&segment_index, segment_commitment) in &subspace_digest_items.segment_commitments {
            if let Some(found_segment_commitment) =
                aux_schema::load_segment_commitment(self.client.as_ref(), segment_index)
                    .map_err(|e| ConsensusError::ClientImport(e.to_string()))?
            {
                if &found_segment_commitment != segment_commitment {
                    return Err(ConsensusError::ClientImport(
                        Error::<Block::Header>::DifferentSegmentCommitment(segment_index)
                            .to_string(),
                    ));
                }
            }

            aux_schema::write_segment_commitment(segment_index, segment_commitment, |values| {
                block
                    .auxiliary
                    .extend(values.iter().map(|(k, v)| (k.to_vec(), Some(v.to_vec()))))
            });
        }

        // The fork choice rule is that we pick the heaviest chain (i.e. smallest solution
        // range), if there's a tie we go with the longest chain.
        let fork_choice = {
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

            ForkChoiceStrategy::Custom(match total_weight.cmp(&last_best_weight) {
                Ordering::Greater => true,
                Ordering::Equal => block_number > last_best_number,
                Ordering::Less => false,
            })
        };
        block.fork_choice = Some(fork_choice);

        let import_result = self.inner.import_block(block).await?;
        let (acknowledgement_sender, mut acknowledgement_receiver) = mpsc::channel(0);

        self.block_importing_notification_sender
            .notify(move || BlockImportingNotification {
                block_number,
                acknowledgement_sender,
            });

        while (acknowledgement_receiver.next().await).is_some() {
            // Wait for all the acknowledgements to finish.
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

/// Get chain constant configurations
pub fn get_chain_constants<Block, Client>(
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
                .chain_constants(client.info().best_hash)
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
pub fn block_import<Client, Block, I, CIDP>(
    slot_duration: SlotDuration,
    wrapped_block_import: I,
    client: Arc<Client>,
    create_inherent_data_providers: CIDP,
) -> ClientResult<(
    SubspaceBlockImport<Block, Client, I, CIDP>,
    SubspaceLink<Block>,
)>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block> + HeaderBackend<Block> + AuxStore,
    Client::Api: BlockBuilderApi<Block> + SubspaceApi<Block, FarmerPublicKey>,
    CIDP: CreateInherentDataProviders<Block, SubspaceLink<Block>> + Send + Sync + 'static,
{
    let (new_slot_notification_sender, new_slot_notification_stream) =
        notification::channel("subspace_new_slot_notification_stream");
    let (reward_signing_notification_sender, reward_signing_notification_stream) =
        notification::channel("subspace_reward_signing_notification_stream");
    let (archived_segment_notification_sender, archived_segment_notification_stream) =
        notification::channel("subspace_archived_segment_notification_stream");
    let (block_importing_notification_sender, block_importing_notification_stream) =
        notification::channel("subspace_block_importing_notification_stream");

    let confirmation_depth_k = get_chain_constants(client.as_ref())
        .expect("Must always be able to get chain constants")
        .confirmation_depth_k();

    // TODO: Probably should have public parameters in chain constants instead
    let kzg = Kzg::new(kzg::embedded_kzg_settings());

    let link = SubspaceLink {
        slot_duration,
        new_slot_notification_sender,
        new_slot_notification_stream,
        reward_signing_notification_sender,
        reward_signing_notification_stream,
        archived_segment_notification_sender,
        archived_segment_notification_stream,
        block_importing_notification_sender: block_importing_notification_sender.clone(),
        block_importing_notification_stream,
        // TODO: Consider making `confirmation_depth_k` non-zero
        segment_headers: Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(confirmation_depth_k as usize)
                .expect("Confirmation depth of zero is not supported"),
        ))),
        kzg,
    };

    let import = SubspaceBlockImport::new(
        client,
        wrapped_block_import,
        block_importing_notification_sender,
        link.clone(),
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
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block> + AuxStore + Send + Sync + 'static,
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

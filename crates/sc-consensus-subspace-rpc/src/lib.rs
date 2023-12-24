// Copyright (C) 2020-2021 Parity Technologies (UK) Ltd.
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

//! RPC api for Subspace.

#![feature(try_blocks)]

use futures::channel::mpsc;
use futures::{future, FutureExt, StreamExt};
use jsonrpsee::core::{async_trait, Error as JsonRpseeError, RpcResult};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::{SubscriptionEmptyError, SubscriptionResult};
use jsonrpsee::SubscriptionSink;
use lru::LruCache;
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_client_api::{AuxStore, BlockBackend};
use sc_consensus_subspace::archiver::{
    recreate_genesis_segment, ArchivedSegmentNotification, SegmentHeadersStore,
};
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::slot_worker::{
    NewSlotNotification, RewardSigningNotification, SubspaceSyncOracle,
};
use sc_rpc::{DenyUnsafe, SubscriptionTaskExecutor};
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus::SyncOracle;
use sp_consensus_subspace::{
    ChainConstants, FarmerPublicKey, FarmerSignature, SubspaceApi as SubspaceRuntimeApi,
};
use sp_core::crypto::ByteArray;
use sp_core::H256;
use sp_objects::ObjectsApi;
use sp_runtime::traits::Block as BlockT;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use subspace_archiving::archiver::NewArchivedSegment;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    PieceIndex, PublicKey, SegmentHeader, SegmentIndex, SlotNumber, Solution,
};
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_networking::libp2p::Multiaddr;
use subspace_rpc_primitives::{
    FarmerAppInfo, NodeSyncStatus, RewardSignatureResponse, RewardSigningInfo, SlotInfo,
    SolutionResponse, MAX_SEGMENT_HEADERS_PER_REQUEST,
};
use tracing::{debug, error, warn};

/// This is essentially equal to expected number of votes per block, one more is added implicitly by
/// the fact that channel sender exists
const SOLUTION_SENDER_CHANNEL_CAPACITY: usize = 9;
const REWARD_SIGNING_TIMEOUT: Duration = Duration::from_millis(500);
const NODE_SYNC_STATUS_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Provides rpc methods for interacting with Subspace.
#[rpc(client, server)]
pub trait SubspaceRpcApi {
    /// Ger metadata necessary for farmer operation
    #[method(name = "subspace_getFarmerAppInfo")]
    fn get_farmer_app_info(&self) -> RpcResult<FarmerAppInfo>;

    #[method(name = "subspace_submitSolutionResponse")]
    fn submit_solution_response(&self, solution_response: SolutionResponse) -> RpcResult<()>;

    /// Slot info subscription
    #[subscription(
        name = "subspace_subscribeSlotInfo" => "subspace_slot_info",
        unsubscribe = "subspace_unsubscribeSlotInfo",
        item = SlotInfo,
    )]
    fn subscribe_slot_info(&self);

    /// Sign block subscription
    #[subscription(
        name = "subspace_subscribeRewardSigning" => "subspace_reward_signing",
        unsubscribe = "subspace_unsubscribeRewardSigning",
        item = RewardSigningInfo,
    )]
    fn subscribe_reward_signing(&self);

    #[method(name = "subspace_submitRewardSignature")]
    fn submit_reward_signature(&self, reward_signature: RewardSignatureResponse) -> RpcResult<()>;

    /// Archived segment header subscription
    #[subscription(
        name = "subspace_subscribeArchivedSegmentHeader" => "subspace_archived_segment_header",
        unsubscribe = "subspace_unsubscribeArchivedSegmentHeader",
        item = SegmentHeader,
    )]
    fn subscribe_archived_segment_header(&self);

    /// Archived segment header subscription
    #[subscription(
        name = "subspace_subscribeNodeSyncStatusChange" => "subspace_node_sync_status_change",
        unsubscribe = "subspace_unsubscribeNodeSyncStatusChange",
        item = NodeSyncStatus,
    )]
    fn subscribe_node_sync_status_change(&self);

    #[method(name = "subspace_segmentHeaders")]
    async fn segment_headers(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> RpcResult<Vec<Option<SegmentHeader>>>;

    #[method(name = "subspace_piece", blocking)]
    fn piece(&self, piece_index: PieceIndex) -> RpcResult<Option<Vec<u8>>>;

    #[method(name = "subspace_acknowledgeArchivedSegmentHeader")]
    async fn acknowledge_archived_segment_header(
        &self,
        segment_index: SegmentIndex,
    ) -> RpcResult<()>;

    #[method(name = "subspace_lastSegmentHeaders")]
    async fn last_segment_headers(&self, limit: u64) -> RpcResult<Vec<Option<SegmentHeader>>>;
}

#[derive(Default)]
struct ArchivedSegmentHeaderAcknowledgementSenders {
    segment_index: SegmentIndex,
    senders: HashMap<u64, TracingUnboundedSender<()>>,
}

#[derive(Default)]
struct BlockSignatureSenders {
    current_hash: H256,
    senders: Vec<async_oneshot::Sender<RewardSignatureResponse>>,
}

/// In-memory cache of last archived segment, such that when request comes back right after
/// archived segment notification, RPC server is able to answer quickly.
///
/// We store weak reference, such that archived segment is not persisted for longer than
/// necessary occupying RAM.
enum CachedArchivedSegment {
    /// Special case for genesis segment when requested over RPC
    Genesis(Arc<NewArchivedSegment>),
    Weak(Weak<NewArchivedSegment>),
}

impl CachedArchivedSegment {
    fn get(&self) -> Option<Arc<NewArchivedSegment>> {
        match self {
            CachedArchivedSegment::Genesis(archived_segment) => Some(Arc::clone(archived_segment)),
            CachedArchivedSegment::Weak(weak_archived_segment) => weak_archived_segment.upgrade(),
        }
    }
}

/// Subspace RPC configuration
pub struct SubspaceRpcConfig<Client, SO, AS>
where
    SO: SyncOracle + Send + Sync + Clone + 'static,
    AS: AuxStore + Send + Sync + 'static,
{
    /// Substrate client
    pub client: Arc<Client>,
    /// Task executor that is being used by RPC subscriptions
    pub subscription_executor: SubscriptionTaskExecutor,
    /// New slot notification stream
    pub new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    /// Reward signing notification stream
    pub reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    /// Archived segment notification stream
    pub archived_segment_notification_stream:
        SubspaceNotificationStream<ArchivedSegmentNotification>,
    /// DSN bootstrap nodes
    pub dsn_bootstrap_nodes: Vec<Multiaddr>,
    /// Segment headers store
    pub segment_headers_store: SegmentHeadersStore<AS>,
    /// Subspace sync oracle
    pub sync_oracle: SubspaceSyncOracle<SO>,
    /// Signifies whether a potentially unsafe RPC should be denied
    pub deny_unsafe: DenyUnsafe,
    /// Kzg instance
    pub kzg: Kzg,
}

/// Implements the [`SubspaceRpcApiServer`] trait for interacting with Subspace.
pub struct SubspaceRpc<Block, Client, SO, AS>
where
    Block: BlockT,
    SO: SyncOracle + Send + Sync + Clone + 'static,
{
    client: Arc<Client>,
    subscription_executor: SubscriptionTaskExecutor,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegmentNotification>,
    #[allow(clippy::type_complexity)]
    solution_response_senders:
        Arc<Mutex<LruCache<SlotNumber, mpsc::Sender<Solution<PublicKey, PublicKey>>>>>,
    reward_signature_senders: Arc<Mutex<BlockSignatureSenders>>,
    dsn_bootstrap_nodes: Vec<Multiaddr>,
    segment_headers_store: SegmentHeadersStore<AS>,
    cached_archived_segment: Arc<Mutex<Option<CachedArchivedSegment>>>,
    archived_segment_acknowledgement_senders:
        Arc<Mutex<ArchivedSegmentHeaderAcknowledgementSenders>>,
    next_subscription_id: AtomicU64,
    sync_oracle: SubspaceSyncOracle<SO>,
    chain_constants: ChainConstants,
    kzg: Kzg,
    deny_unsafe: DenyUnsafe,
    _block: PhantomData<Block>,
}

/// [`SubspaceRpc`] is used for notifying subscribers about arrival of new slots and for
/// submission of solutions (or lack thereof).
///
/// Internally every time slot notifier emits information about new slot, notification is sent to
/// every subscriber, after which RPC server waits for the same number of
/// `subspace_submitSolutionResponse` requests with `SolutionResponse` in them or until
/// timeout is exceeded. The first valid solution for a particular slot wins, others are ignored.
impl<Block, Client, SO, AS> SubspaceRpc<Block, Client, SO, AS>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block> + HeaderBackend<Block>,
    Client::Api: SubspaceRuntimeApi<Block, FarmerPublicKey>,
    SO: SyncOracle + Send + Sync + Clone + 'static,
    AS: AuxStore + Send + Sync + 'static,
{
    /// Creates a new instance of the `SubspaceRpc` handler.
    pub fn new(config: SubspaceRpcConfig<Client, SO, AS>) -> Result<Self, ApiError> {
        let best_hash = config.client.info().best_hash;
        let runtime_api = config.client.runtime_api();
        let chain_constants = runtime_api.chain_constants(best_hash)?;
        let block_authoring_delay = u64::from(chain_constants.block_authoring_delay());
        let block_authoring_delay = usize::try_from(block_authoring_delay)
            .expect("Block authoring delay will never exceed usize on any platform; qed");
        let solution_response_senders_capacity =
            NonZeroUsize::try_from(block_authoring_delay).unwrap_or(NonZeroUsize::MIN);

        Ok(Self {
            client: config.client,
            subscription_executor: config.subscription_executor,
            new_slot_notification_stream: config.new_slot_notification_stream,
            reward_signing_notification_stream: config.reward_signing_notification_stream,
            archived_segment_notification_stream: config.archived_segment_notification_stream,
            solution_response_senders: Arc::new(Mutex::new(LruCache::new(
                solution_response_senders_capacity,
            ))),
            reward_signature_senders: Arc::default(),
            dsn_bootstrap_nodes: config.dsn_bootstrap_nodes,
            segment_headers_store: config.segment_headers_store,
            cached_archived_segment: Arc::default(),
            archived_segment_acknowledgement_senders: Arc::default(),
            next_subscription_id: AtomicU64::default(),
            sync_oracle: config.sync_oracle,
            chain_constants,
            kzg: config.kzg,
            deny_unsafe: config.deny_unsafe,
            _block: PhantomData,
        })
    }
}

#[async_trait]
impl<Block, Client, SO, AS> SubspaceRpcApiServer for SubspaceRpc<Block, Client, SO, AS>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + HeaderBackend<Block>
        + BlockBackend<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceRuntimeApi<Block, FarmerPublicKey> + ObjectsApi<Block>,
    SO: SyncOracle + Send + Sync + Clone + 'static,
    AS: AuxStore + Send + Sync + 'static,
{
    fn get_farmer_app_info(&self) -> RpcResult<FarmerAppInfo> {
        let best_hash = self.client.info().best_hash;
        let runtime_api = self.client.runtime_api();

        let genesis_hash = self
            .client
            .info()
            .genesis_hash
            .as_ref()
            .try_into()
            .map_err(|error| {
                error!("Failed to convert genesis hash: {error}");
                JsonRpseeError::Custom("Internal error".to_string())
            })?;

        let farmer_app_info: Result<FarmerAppInfo, ApiError> = try {
            let chain_constants = &self.chain_constants;
            let protocol_info = FarmerProtocolInfo {
                history_size: runtime_api.history_size(best_hash)?,
                max_pieces_in_sector: runtime_api.max_pieces_in_sector(best_hash)?,
                recent_segments: chain_constants.recent_segments(),
                recent_history_fraction: chain_constants.recent_history_fraction(),
                min_sector_lifetime: chain_constants.min_sector_lifetime(),
            };

            FarmerAppInfo {
                genesis_hash,
                dsn_bootstrap_nodes: self.dsn_bootstrap_nodes.clone(),
                farming_timeout: chain_constants
                    .slot_duration()
                    .as_duration()
                    .mul_f64(SlotNumber::from(chain_constants.block_authoring_delay()) as f64),
                protocol_info,
            }
        };

        farmer_app_info.map_err(|error| {
            error!("Failed to get data from runtime API: {}", error);
            JsonRpseeError::Custom("Internal error".to_string())
        })
    }

    fn submit_solution_response(&self, solution_response: SolutionResponse) -> RpcResult<()> {
        self.deny_unsafe.check_if_safe()?;

        let slot = solution_response.slot_number;
        let mut solution_response_senders = self.solution_response_senders.lock();

        let success = solution_response_senders
            .peek_mut(&slot)
            .and_then(|sender| sender.try_send(solution_response.solution).ok())
            .is_some();

        if !success {
            warn!(
                %slot,
                "Solution was ignored, likely because farmer was too slow"
            );

            return Err(JsonRpseeError::Custom("Solution was ignored".to_string()));
        }

        Ok(())
    }

    fn subscribe_slot_info(&self, mut sink: SubscriptionSink) -> SubscriptionResult {
        let executor = self.subscription_executor.clone();
        let solution_response_senders = self.solution_response_senders.clone();
        let allow_solutions = self.deny_unsafe.check_if_safe().is_ok();

        let handle_slot_notification = move |new_slot_notification| {
            let NewSlotNotification {
                new_slot_info,
                mut solution_sender,
            } = new_slot_notification;

            let slot_number = SlotNumber::from(new_slot_info.slot);

            // Only handle solution responses in case unsafe APIs are allowed
            if allow_solutions {
                // Store solution sender so that we can retrieve it when solution comes from
                // the farmer
                let mut solution_response_senders = solution_response_senders.lock();
                if solution_response_senders.peek(&slot_number).is_none() {
                    let (response_sender, mut response_receiver) =
                        mpsc::channel(SOLUTION_SENDER_CHANNEL_CAPACITY);

                    solution_response_senders.push(slot_number, response_sender);

                    // Wait for solutions and transform proposed proof of space solutions
                    // into data structure `sc-consensus-subspace` expects
                    let forward_solution_fut = async move {
                        while let Some(solution) = response_receiver.next().await {
                            let public_key =
                                FarmerPublicKey::from_slice(solution.public_key.as_ref())
                                    .expect("Always correct length; qed");
                            let reward_address =
                                FarmerPublicKey::from_slice(solution.reward_address.as_ref())
                                    .expect("Always correct length; qed");

                            let sector_index = solution.sector_index;

                            let solution = Solution {
                                public_key: public_key.clone(),
                                reward_address,
                                sector_index,
                                history_size: solution.history_size,
                                piece_offset: solution.piece_offset,
                                record_commitment: solution.record_commitment,
                                record_witness: solution.record_witness,
                                chunk: solution.chunk,
                                chunk_witness: solution.chunk_witness,
                                proof_of_space: solution.proof_of_space,
                            };

                            if solution_sender.try_send(solution).is_err() {
                                warn!(
                                    slot = %slot_number,
                                    %sector_index,
                                    %public_key,
                                    "Solution receiver is closed, likely because farmer was too slow"
                                );
                            }
                        }
                    };

                    executor.spawn(
                        "subspace-slot-info-forward",
                        Some("rpc"),
                        Box::pin(forward_solution_fut),
                    );
                }
            }

            let global_challenge = new_slot_info
                .global_randomness
                .derive_global_challenge(slot_number);

            // This will be sent to the farmer
            SlotInfo {
                slot_number,
                global_challenge,
                solution_range: new_slot_info.solution_range,
                voting_solution_range: new_slot_info.voting_solution_range,
            }
        };
        let stream = self
            .new_slot_notification_stream
            .subscribe()
            .map(handle_slot_notification);

        let fut = async move {
            sink.pipe_from_stream(stream).await;
        };

        self.subscription_executor.spawn(
            "subspace-slot-info-subscription",
            Some("rpc"),
            fut.boxed(),
        );

        Ok(())
    }

    fn subscribe_reward_signing(&self, mut sink: SubscriptionSink) -> SubscriptionResult {
        self.deny_unsafe
            .check_if_safe()
            .map_err(|_error| SubscriptionEmptyError)?;

        let executor = self.subscription_executor.clone();
        let reward_signature_senders = self.reward_signature_senders.clone();

        let stream = self.reward_signing_notification_stream.subscribe().map(
            move |reward_signing_notification| {
                let RewardSigningNotification {
                    hash,
                    public_key,
                    signature_sender,
                } = reward_signing_notification;

                let (response_sender, response_receiver) = async_oneshot::oneshot();

                // Store signature sender so that we can retrieve it when solution comes from
                // the farmer
                {
                    let mut reward_signature_senders = reward_signature_senders.lock();

                    if reward_signature_senders.current_hash != hash {
                        reward_signature_senders.current_hash = hash;
                        reward_signature_senders.senders.clear();
                    }

                    reward_signature_senders.senders.push(response_sender);
                }

                // Wait for solutions and transform proposed proof of space solutions into
                // data structure `sc-consensus-subspace` expects
                let forward_signature_fut = async move {
                    if let Ok(reward_signature) = response_receiver.await {
                        if let Some(signature) = reward_signature.signature {
                            match FarmerSignature::decode(&mut signature.encode().as_ref()) {
                                Ok(signature) => {
                                    let _ = signature_sender.unbounded_send(signature);
                                }
                                Err(error) => {
                                    warn!(
                                        "Failed to convert signature of length {}: {}",
                                        signature.len(),
                                        error
                                    );
                                }
                            }
                        }
                    }
                };

                // Run above future with timeout
                executor.spawn(
                    "subspace-block-signing-forward",
                    Some("rpc"),
                    future::select(
                        futures_timer::Delay::new(REWARD_SIGNING_TIMEOUT),
                        Box::pin(forward_signature_fut),
                    )
                    .map(|_| ())
                    .boxed(),
                );

                // This will be sent to the farmer
                RewardSigningInfo {
                    hash: hash.into(),
                    public_key: public_key
                        .as_slice()
                        .try_into()
                        .expect("Public key is always 32 bytes; qed"),
                }
            },
        );

        let fut = async move {
            sink.pipe_from_stream(stream).await;
        };

        self.subscription_executor.spawn(
            "subspace-block-signing-subscription",
            Some("rpc"),
            fut.boxed(),
        );

        Ok(())
    }

    fn submit_reward_signature(&self, reward_signature: RewardSignatureResponse) -> RpcResult<()> {
        self.deny_unsafe.check_if_safe()?;

        let reward_signature_senders = self.reward_signature_senders.clone();

        // TODO: This doesn't track what client sent a solution, allowing some clients to send
        //  multiple (https://github.com/paritytech/jsonrpsee/issues/452)
        let mut reward_signature_senders = reward_signature_senders.lock();

        if reward_signature_senders.current_hash == reward_signature.hash.into() {
            if let Some(mut sender) = reward_signature_senders.senders.pop() {
                let _ = sender.send(reward_signature);
            }
        }

        Ok(())
    }

    fn subscribe_archived_segment_header(&self, mut sink: SubscriptionSink) -> SubscriptionResult {
        let archived_segment_acknowledgement_senders =
            self.archived_segment_acknowledgement_senders.clone();

        let cached_archived_segment = Arc::clone(&self.cached_archived_segment);
        let subscription_id = self.next_subscription_id.fetch_add(1, Ordering::Relaxed);
        let allow_acknowledgements = self.deny_unsafe.check_if_safe().is_ok();

        let stream = self
            .archived_segment_notification_stream
            .subscribe()
            .filter_map(move |archived_segment_notification| {
                let ArchivedSegmentNotification {
                    archived_segment,
                    acknowledgement_sender,
                } = archived_segment_notification;

                let segment_index = archived_segment.segment_header.segment_index();

                // Store acknowledgment sender so that we can retrieve it when acknowledgement
                // comes from the farmer, but only if unsafe APIs are allowed
                let maybe_archived_segment_header = if allow_acknowledgements {
                    let mut archived_segment_acknowledgement_senders =
                        archived_segment_acknowledgement_senders.lock();

                    if archived_segment_acknowledgement_senders.segment_index != segment_index {
                        archived_segment_acknowledgement_senders.segment_index = segment_index;
                        archived_segment_acknowledgement_senders.senders.clear();
                    }

                    let maybe_archived_segment_header =
                        match archived_segment_acknowledgement_senders
                            .senders
                            .entry(subscription_id)
                        {
                            Entry::Occupied(_) => {
                                // No need to do anything, farmer is processing request
                                None
                            }
                            Entry::Vacant(entry) => {
                                entry.insert(acknowledgement_sender);

                                // This will be sent to the farmer
                                Some(archived_segment.segment_header)
                            }
                        };

                    cached_archived_segment
                        .lock()
                        .replace(CachedArchivedSegment::Weak(Arc::downgrade(
                            &archived_segment,
                        )));

                    maybe_archived_segment_header
                } else {
                    // In case unsafe APIs are not allowed, just return segment header without
                    // requiring it to be acknowledged
                    Some(archived_segment.segment_header)
                };

                Box::pin(async move { maybe_archived_segment_header })
            });

        let archived_segment_acknowledgement_senders =
            self.archived_segment_acknowledgement_senders.clone();
        let fut = async move {
            sink.pipe_from_stream(stream).await;

            let mut archived_segment_acknowledgement_senders =
                archived_segment_acknowledgement_senders.lock();

            archived_segment_acknowledgement_senders
                .senders
                .remove(&subscription_id);
        };

        self.subscription_executor.spawn(
            "subspace-archived-segment-header-subscription",
            Some("rpc"),
            fut.boxed(),
        );

        Ok(())
    }

    fn subscribe_node_sync_status_change(&self, mut sink: SubscriptionSink) -> SubscriptionResult {
        let sync_oracle = self.sync_oracle.clone();
        let fut = async move {
            let mut last_is_major_syncing = None;
            loop {
                let is_major_syncing = sync_oracle.is_major_syncing();

                // Update subscriber if value has changed
                if last_is_major_syncing != Some(is_major_syncing) {
                    // In case change is detected, wait for another interval to confirm.
                    // TODO: This is primarily because Substrate seems to lose peers for brief
                    //  periods of time sometimes that needs to be investigated separately
                    futures_timer::Delay::new(NODE_SYNC_STATUS_CHECK_INTERVAL).await;

                    // If status returned back to what it was, ignore
                    if last_is_major_syncing == Some(sync_oracle.is_major_syncing()) {
                        futures_timer::Delay::new(NODE_SYNC_STATUS_CHECK_INTERVAL).await;
                        continue;
                    }

                    // Otherwise save new status
                    last_is_major_syncing.replace(is_major_syncing);

                    let node_sync_status = if is_major_syncing {
                        NodeSyncStatus::MajorSyncing
                    } else {
                        NodeSyncStatus::Synced
                    };
                    match sink.send(&node_sync_status) {
                        Ok(true) => {
                            // Success
                        }
                        Ok(false) => {
                            // Subscription closed
                            return;
                        }
                        Err(error) => {
                            error!("Failed to serialize node sync status: {}", error);
                        }
                    }
                }

                futures_timer::Delay::new(NODE_SYNC_STATUS_CHECK_INTERVAL).await;
            }
        };

        self.subscription_executor.spawn(
            "subspace-node-sync-status-change-subscription",
            Some("rpc"),
            fut.boxed(),
        );

        Ok(())
    }

    async fn acknowledge_archived_segment_header(
        &self,
        segment_index: SegmentIndex,
    ) -> RpcResult<()> {
        self.deny_unsafe.check_if_safe()?;

        let archived_segment_acknowledgement_senders =
            self.archived_segment_acknowledgement_senders.clone();

        let maybe_sender = {
            let mut archived_segment_acknowledgement_senders_guard =
                archived_segment_acknowledgement_senders.lock();

            (archived_segment_acknowledgement_senders_guard.segment_index == segment_index)
                .then(|| {
                    let last_key = *archived_segment_acknowledgement_senders_guard
                        .senders
                        .keys()
                        .next()?;

                    archived_segment_acknowledgement_senders_guard
                        .senders
                        .remove(&last_key)
                })
                .flatten()
        };

        if let Some(sender) = maybe_sender {
            if let Err(error) = sender.unbounded_send(()) {
                if !error.is_closed() {
                    warn!("Failed to acknowledge archived segment: {error}");
                }
            }
        }

        debug!(%segment_index, "Acknowledged archived segment.");

        Ok(())
    }

    fn piece(&self, requested_piece_index: PieceIndex) -> RpcResult<Option<Vec<u8>>> {
        self.deny_unsafe.check_if_safe()?;

        let archived_segment = {
            let mut cached_archived_segment = self.cached_archived_segment.lock();

            match cached_archived_segment
                .as_ref()
                .and_then(CachedArchivedSegment::get)
            {
                Some(archived_segment) => archived_segment,
                None => {
                    if requested_piece_index > SegmentIndex::ZERO.last_piece_index() {
                        return Ok(None);
                    }

                    debug!(%requested_piece_index, "Re-creating genesis segment on demand");

                    // Try to re-create genesis segment on demand
                    match recreate_genesis_segment(&*self.client, self.kzg.clone()) {
                        Ok(Some(archived_segment)) => {
                            let archived_segment = Arc::new(archived_segment);
                            cached_archived_segment.replace(CachedArchivedSegment::Genesis(
                                Arc::clone(&archived_segment),
                            ));
                            archived_segment
                        }
                        Ok(None) => {
                            return Ok(None);
                        }
                        Err(error) => {
                            error!(%error, "Failed to re-create genesis segment");

                            return Err(JsonRpseeError::Custom(
                                "Failed to re-create genesis segment".to_string(),
                            ));
                        }
                    }
                }
            }
        };

        let pieces = &archived_segment.pieces;
        if requested_piece_index.segment_index() == archived_segment.segment_header.segment_index()
        {
            return Ok(Some(
                pieces[requested_piece_index.position() as usize].to_vec(),
            ));
        }

        Ok(None)
    }

    async fn segment_headers(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> RpcResult<Vec<Option<SegmentHeader>>> {
        if segment_indexes.len() > MAX_SEGMENT_HEADERS_PER_REQUEST {
            error!(
                "segment_indexes length exceed the limit: {} ",
                segment_indexes.len()
            );

            return Err(JsonRpseeError::Custom(format!(
                "segment_indexes length exceed the limit {MAX_SEGMENT_HEADERS_PER_REQUEST}"
            )));
        };

        Ok(segment_indexes
            .into_iter()
            .map(|segment_index| self.segment_headers_store.get_segment_header(segment_index))
            .collect())
    }

    async fn last_segment_headers(&self, limit: u64) -> RpcResult<Vec<Option<SegmentHeader>>> {
        if limit as usize > MAX_SEGMENT_HEADERS_PER_REQUEST {
            error!(
                "Request limit ({}) exceed the server limit: {} ",
                limit, MAX_SEGMENT_HEADERS_PER_REQUEST
            );

            return Err(JsonRpseeError::Custom(format!(
                "Request limit ({}) exceed the server limit: {} ",
                limit, MAX_SEGMENT_HEADERS_PER_REQUEST
            )));
        };

        let runtime_api = self.client.runtime_api();
        let best_hash = self.client.info().best_hash;

        let last_segment_index = match runtime_api.history_size(best_hash) {
            Ok(history_size) => history_size.segment_index(),
            Err(error) => {
                error!(?best_hash, "Failed to get history size: {}", error);

                SegmentIndex::ZERO
            }
        };

        let last_segment_headers = (SegmentIndex::ZERO..=last_segment_index)
            .rev()
            .take(limit as usize)
            .map(|segment_index| self.segment_headers_store.get_segment_header(segment_index))
            .collect::<Vec<_>>();

        Ok(last_segment_headers)
    }
}

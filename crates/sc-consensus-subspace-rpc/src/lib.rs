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

use futures::{future, FutureExt, SinkExt, StreamExt};
use jsonrpsee::core::{async_trait, Error as JsonRpseeError, RpcResult};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::PendingSubscription;
use log::{error, warn};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_client_api::BlockBackend;
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::{
    ArchivedSegmentNotification, NewSlotNotification, RewardSigningNotification,
};
use sc_rpc::SubscriptionTaskExecutor;
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature, SubspaceApi as SubspaceRuntimeApi};
use sp_core::crypto::ByteArray;
use sp_core::H256;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::Block as BlockT;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::Solution;
use subspace_rpc_primitives::{
    FarmerMetadata, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
};

const SOLUTION_TIMEOUT: Duration = Duration::from_secs(2);
const REWARD_SIGNING_TIMEOUT: Duration = Duration::from_millis(500);

/// Provides rpc methods for interacting with Subspace.
#[rpc(client, server)]
pub trait SubspaceRpcApi {
    /// Ger metadata necessary for farmer operation
    #[method(name = "subspace_getFarmerMetadata")]
    fn get_farmer_metadata(&self) -> RpcResult<FarmerMetadata>;

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

    /// Archived segment subscription
    #[subscription(
        name = "subspace_subscribeArchivedSegment" => "subspace_archived_segment",
        unsubscribe = "subspace_unsubscribeArchivedSegment",
        item = ArchivedSegment,
    )]
    fn subscribe_archived_segment(&self);

    #[method(name = "subspace_acknowledgeArchivedSegment")]
    async fn acknowledge_archived_segment(&self, segment_index: u64) -> RpcResult<()>;
}

#[derive(Default)]
struct SolutionResponseSenders {
    current_slot: Slot,
    senders: Vec<async_oneshot::Sender<SolutionResponse>>,
}

#[derive(Default)]
struct BlockSignatureSenders {
    current_hash: H256,
    senders: Vec<async_oneshot::Sender<RewardSignatureResponse>>,
}

#[derive(Default)]
struct ArchivedSegmentAcknowledgementSenders {
    segment_index: u64,
    senders: HashMap<u64, TracingUnboundedSender<()>>,
}

/// Implements the [`SubspaceRpcApiServer`] trait for interacting with Subspace.
pub struct SubspaceRpc<Block, Client> {
    client: Arc<Client>,
    executor: SubscriptionTaskExecutor,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegmentNotification>,
    solution_response_senders: Arc<Mutex<SolutionResponseSenders>>,
    reward_signature_senders: Arc<Mutex<BlockSignatureSenders>>,
    archived_segment_acknowledgement_senders: Arc<Mutex<ArchivedSegmentAcknowledgementSenders>>,
    next_subscription_id: AtomicU64,
    _phantom: PhantomData<Block>,
}

/// [`SubspaceRpc`] is used for notifying subscribers about arrival of new slots and for
/// submission of solutions (or lack thereof).
///
/// Internally every time slot notifier emits information about new slot, notification is sent to
/// every subscriber, after which RPC server waits for the same number of
/// `subspace_submitSolutionResponse` requests with `SolutionResponse` in them or until
/// timeout is exceeded. The first valid solution for a particular slot wins, others are ignored.
impl<Block, Client> SubspaceRpc<Block, Client>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceRuntimeApi<Block, FarmerPublicKey>,
{
    /// Creates a new instance of the `SubspaceRpc` handler.
    pub fn new(
        client: Arc<Client>,
        executor: SubscriptionTaskExecutor,
        new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
        reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
        archived_segment_notification_stream: SubspaceNotificationStream<
            ArchivedSegmentNotification,
        >,
    ) -> Self {
        Self {
            client,
            executor,
            new_slot_notification_stream,
            reward_signing_notification_stream,
            archived_segment_notification_stream,
            solution_response_senders: Arc::default(),
            reward_signature_senders: Arc::default(),
            archived_segment_acknowledgement_senders: Arc::default(),
            next_subscription_id: AtomicU64::default(),
            _phantom: PhantomData::default(),
        }
    }
}

#[async_trait]
impl<Block, Client> SubspaceRpcApiServer for SubspaceRpc<Block, Client>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceRuntimeApi<Block, FarmerPublicKey>,
{
    fn get_farmer_metadata(&self) -> RpcResult<FarmerMetadata> {
        let best_block_id = BlockId::Hash(self.client.info().best_hash);
        let runtime_api = self.client.runtime_api();

        let farmer_metadata: Result<FarmerMetadata, ApiError> = try {
            FarmerMetadata {
                record_size: runtime_api.record_size(&best_block_id)?,
                recorded_history_segment_size: runtime_api
                    .recorded_history_segment_size(&best_block_id)?,
                max_plot_size: runtime_api.max_plot_size(&best_block_id)?,
            }
        };

        farmer_metadata.map_err(|error| {
            error!("Failed to get data from runtime API: {}", error);
            JsonRpseeError::Custom("Internal error".to_string())
        })
    }

    fn submit_solution_response(&self, solution_response: SolutionResponse) -> RpcResult<()> {
        let solution_response_senders = self.solution_response_senders.clone();

        // TODO: This doesn't track what client sent a solution, allowing some clients to send
        //  multiple (https://github.com/paritytech/jsonrpsee/issues/452)

        let mut solution_response_senders = solution_response_senders.lock();

        if *solution_response_senders.current_slot == solution_response.slot_number {
            if let Some(mut sender) = solution_response_senders.senders.pop() {
                let _ = sender.send(solution_response);
            }
        }

        Ok(())
    }

    fn subscribe_slot_info(&self, pending: PendingSubscription) {
        let executor = self.executor.clone();
        let solution_response_senders = self.solution_response_senders.clone();

        let stream =
            self.new_slot_notification_stream
                .subscribe()
                .map(move |new_slot_notification| {
                    let NewSlotNotification {
                        new_slot_info,
                        mut solution_sender,
                    } = new_slot_notification;

                    let (response_sender, response_receiver) = async_oneshot::oneshot();

                    // Store solution sender so that we can retrieve it when solution comes from
                    // the farmer
                    {
                        let mut solution_response_senders = solution_response_senders.lock();

                        if solution_response_senders.current_slot != new_slot_info.slot {
                            solution_response_senders.current_slot = new_slot_info.slot;
                            solution_response_senders.senders.clear();
                        }

                        solution_response_senders.senders.push(response_sender);
                    }

                    // Wait for solutions and transform proposed proof of space solutions into
                    // data structure `sc-consensus-subspace` expects
                    let forward_solution_fut = async move {
                        if let Ok(solution_response) = response_receiver.await {
                            if let Some(solution) = solution_response.maybe_solution {
                                let public_key = FarmerPublicKey::from_slice(&solution.public_key)
                                    .expect("Always correct length; qed");
                                let reward_address =
                                    FarmerPublicKey::from_slice(&solution.reward_address)
                                        .expect("Always correct length; qed");

                                let solution = Solution {
                                    public_key,
                                    reward_address,
                                    piece_index: solution.piece_index,
                                    encoding: solution.encoding,
                                    tag_signature: solution.tag_signature,
                                    local_challenge: solution.local_challenge,
                                    tag: solution.tag,
                                };

                                let _ = solution_sender.send(solution).await;
                            }
                        }
                    };

                    // Run above future with timeout
                    executor.spawn(
                        "subspace-slot-info-forward",
                        Some("rpc"),
                        future::select(
                            futures_timer::Delay::new(SOLUTION_TIMEOUT),
                            Box::pin(forward_solution_fut),
                        )
                        .map(|_| ())
                        .boxed(),
                    );

                    // This will be sent to the farmer
                    SlotInfo {
                        slot_number: new_slot_info.slot.into(),
                        global_challenge: new_slot_info.global_challenge,
                        salt: new_slot_info.salt,
                        next_salt: new_slot_info.next_salt,
                        solution_range: new_slot_info.solution_range,
                        voting_solution_range: new_slot_info.voting_solution_range,
                    }
                });

        let fut = async move {
            if let Some(mut sink) = pending.accept() {
                sink.pipe_from_stream(stream).await;
            }
        };

        self.executor
            .spawn("subspace-slot-info-subscription", Some("rpc"), fut.boxed());
    }

    fn subscribe_reward_signing(&self, pending: PendingSubscription) {
        let executor = self.executor.clone();
        let reward_signature_senders = self.reward_signature_senders.clone();

        let stream = self.reward_signing_notification_stream.subscribe().map(
            move |reward_signing_notification| {
                let RewardSigningNotification {
                    hash,
                    public_key,
                    mut signature_sender,
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
                                    let _ = signature_sender.send(signature).await;
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
            if let Some(mut sink) = pending.accept() {
                sink.pipe_from_stream(stream).await;
            }
        };

        self.executor.spawn(
            "subspace-block-signing-subscription",
            Some("rpc"),
            fut.boxed(),
        );
    }

    fn submit_reward_signature(&self, reward_signature: RewardSignatureResponse) -> RpcResult<()> {
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

    fn subscribe_archived_segment(&self, pending: PendingSubscription) {
        let archived_segment_acknowledgement_senders =
            self.archived_segment_acknowledgement_senders.clone();

        let subscription_id = self.next_subscription_id.fetch_add(1, Ordering::Relaxed);

        let stream = self
            .archived_segment_notification_stream
            .subscribe()
            .filter_map(move |archived_segment_notification| {
                let ArchivedSegmentNotification {
                    archived_segment,
                    acknowledgement_sender,
                } = archived_segment_notification;

                let segment_index = archived_segment.root_block.segment_index();

                // Store acknowledgment sender so that we can retrieve it when acknowledgement
                // comes from the farmer
                {
                    let mut archived_segment_acknowledgement_senders =
                        archived_segment_acknowledgement_senders.lock();

                    if archived_segment_acknowledgement_senders.segment_index != segment_index {
                        archived_segment_acknowledgement_senders.segment_index = segment_index;
                        archived_segment_acknowledgement_senders.senders.clear();
                    }

                    let maybe_archived_segment = match archived_segment_acknowledgement_senders
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
                            Some(archived_segment.as_ref().clone())
                        }
                    };

                    Box::pin(async move { maybe_archived_segment })
                }
            });

        let fut = async move {
            if let Some(mut sink) = pending.accept() {
                sink.pipe_from_stream(stream).await;
            }
        };

        self.executor.spawn(
            "subspace-archived-segment-subscription",
            Some("rpc"),
            fut.boxed(),
        );
    }

    async fn acknowledge_archived_segment(&self, segment_index: u64) -> RpcResult<()> {
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

        if let Some(mut sender) = maybe_sender {
            if let Err(error) = sender.send(()).await {
                if !error.is_disconnected() {
                    warn!("Failed to acknowledge archived segment: {error}");
                }
            }
        }

        Ok(())
    }
}

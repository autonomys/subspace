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

//! RPC api for PoC.

use futures::task::SpawnExt;
use futures::{future, task::Spawn, FutureExt, SinkExt, StreamExt};
use jsonrpc_core::{Error as RpcError, Result as RpcResult};
use jsonrpc_derive::rpc;
use jsonrpc_pubsub::{manager::SubscriptionManager, typed::Subscriber, SubscriptionId};
use log::warn;
use parking_lot::Mutex;
use sc_consensus_poc::notification::SubspaceNotificationStream;
use sc_consensus_poc::{ArchivedSegmentNotification, NewSlotNotification};
use serde::{Deserialize, Serialize};
use sp_consensus_poc::digests::Solution;
use sp_consensus_poc::{FarmerId, Slot};
use sp_core::crypto::Public;
use std::sync::Arc;
use std::time::Duration;

const SOLUTION_TIMEOUT: Duration = Duration::from_secs(5);

type SlotNumber = u64;
type FutureResult<T> = jsonrpc_core::BoxFuture<Result<T, RpcError>>;

/// Information about new slot that just arrived
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcNewSlotInfo {
    /// Slot number
    pub slot_number: SlotNumber,
    /// Slot challenge
    pub challenge: [u8; 8],
    /// Salt
    pub salt: [u8; 8],
    /// Salt for the next eon
    pub next_salt: Option<[u8; 8]>,
    /// Acceptable solution range
    pub solution_range: u64,
}

/// Information about new slot that just arrived
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcArchivedSegment {
    /// Segment index
    pub segment_index: u64,
    /// Pieces that correspond to this segment
    pub pieces: Vec<Vec<u8>>,
}

impl From<ArchivedSegmentNotification> for RpcArchivedSegment {
    fn from(archived_segment_notification: ArchivedSegmentNotification) -> Self {
        let ArchivedSegmentNotification {
            segment_index,
            pieces,
        } = archived_segment_notification;

        Self {
            segment_index,
            pieces: pieces.into_iter().map(|piece| piece.to_vec()).collect(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcSolution {
    pub public_key: [u8; 32],
    pub nonce: u64,
    pub encoding: Vec<u8>,
    pub signature: Vec<u8>,
    pub tag: [u8; 8],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProposedProofOfSpaceResult {
    pub slot_number: SlotNumber,
    pub solution: Option<RpcSolution>,
    pub secret_key: Vec<u8>,
}

/// Provides rpc methods for interacting with PoC.
#[rpc]
pub trait PoCApi {
    /// RPC metadata
    type Metadata;

    #[rpc(name = "poc_proposeProofOfSpace")]
    fn propose_proof_of_space(
        &self,
        proposed_proof_of_space_result: ProposedProofOfSpaceResult,
    ) -> FutureResult<()>;

    /// Slot info subscription
    #[pubsub(
        subscription = "poc_slot_info",
        subscribe,
        name = "poc_subscribeSlotInfo"
    )]
    fn subscribe_slot_info(&self, metadata: Self::Metadata, subscriber: Subscriber<RpcNewSlotInfo>);

    /// Unsubscribe from slot info subscription.
    #[pubsub(
        subscription = "poc_slot_info",
        unsubscribe,
        name = "poc_unsubscribeSlotInfo"
    )]
    fn unsubscribe_slot_info(
        &self,
        metadata: Option<Self::Metadata>,
        id: SubscriptionId,
    ) -> RpcResult<bool>;

    /// Archived segment subscription
    #[pubsub(
        subscription = "poc_archived_segment",
        subscribe,
        name = "poc_subscribeArchivedSegment"
    )]
    fn subscribe_archived_segment(
        &self,
        metadata: Self::Metadata,
        subscriber: Subscriber<RpcArchivedSegment>,
    );

    /// Unsubscribe from archived segment subscription.
    #[pubsub(
        subscription = "poc_archived_segment",
        unsubscribe,
        name = "poc_unsubscribeArchivedSegment"
    )]
    fn unsubscribe_archived_segment(
        &self,
        metadata: Option<Self::Metadata>,
        id: SubscriptionId,
    ) -> RpcResult<bool>;
}

#[derive(Default)]
struct ResponseSenders {
    current_slot: Slot,
    senders: Vec<async_oneshot::Sender<ProposedProofOfSpaceResult>>,
}

/// Implements the PoCRpc trait for interacting with PoC.
pub struct PoCRpcHandler {
    subscription_manager: SubscriptionManager,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegmentNotification>,
    response_senders: Arc<Mutex<ResponseSenders>>,
}

/// PoCRpcHandler is used for notifying subscribers about arrival of new slots and for submission of
/// solutions (or lack thereof).
///
/// Internally every time slot notifier emits information about new slot, notification is sent to
/// every subscriber, after which RPC server waits for the same number of `poc_proposeProofOfSpace`
/// requests with `ProposedProofOfSpaceResult` in them or until timeout is exceeded. The first valid
/// solution for a particular slot wins, others are ignored.
impl PoCRpcHandler {
    /// Creates a new instance of the PoCRpc handler.
    pub fn new<E>(
        executor: E,
        new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
        archived_segment_notification_stream: SubspaceNotificationStream<
            ArchivedSegmentNotification,
        >,
    ) -> Self
    where
        E: Spawn + Send + Sync + 'static,
    {
        Self {
            subscription_manager: SubscriptionManager::new(Arc::new(executor)),
            new_slot_notification_stream,
            archived_segment_notification_stream,
            response_senders: Arc::default(),
        }
    }
}

impl PoCApi for PoCRpcHandler {
    type Metadata = sc_rpc_api::Metadata;

    fn propose_proof_of_space(
        &self,
        proposed_proof_of_space_result: ProposedProofOfSpaceResult,
    ) -> FutureResult<()> {
        let response_senders = Arc::clone(&self.response_senders);

        // TODO: This doesn't track what client sent a solution, allowing some clients to send
        //  multiple (https://github.com/paritytech/jsonrpsee/issues/452)
        Box::pin(async move {
            let mut response_senders = response_senders.lock();

            if response_senders.current_slot
                == Slot::from(proposed_proof_of_space_result.slot_number)
            {
                if let Some(mut sender) = response_senders.senders.pop() {
                    let _ = sender.send(proposed_proof_of_space_result);
                }
            }

            Ok(())
        })
    }

    fn subscribe_slot_info(
        &self,
        _metadata: Self::Metadata,
        subscriber: Subscriber<RpcNewSlotInfo>,
    ) {
        self.subscription_manager.add(subscriber, |sink| {
            let executor = self.subscription_manager.executor().clone();
            let response_senders = Arc::clone(&self.response_senders);

            self.new_slot_notification_stream
                .subscribe()
                .map(move |new_slot_notification| {
                    let NewSlotNotification {
                        new_slot_info,
                        mut response_sender,
                    } = new_slot_notification;

                    let (solution_sender, solution_receiver) = async_oneshot::oneshot();

                    // Store solution sender so that we can retrieve it when solution comes from
                    // the farmer
                    {
                        let mut response_senders = response_senders.lock();

                        if response_senders.current_slot != new_slot_info.slot {
                            response_senders.current_slot = new_slot_info.slot;
                            response_senders.senders.clear();
                        }

                        response_senders.senders.push(solution_sender);
                    }

                    // Wait for solutions and transform proposed proof of space solutions into
                    // data structure `sc-consensus-poc` expects
                    let forward_solution_fut = async move {
                        if let Ok(proposed_proof_of_space_result) = solution_receiver.await {
                            if let Some(solution) = proposed_proof_of_space_result.solution {
                                let solution = Solution {
                                    public_key: FarmerId::from_slice(&solution.public_key),
                                    nonce: solution.nonce,
                                    encoding: solution.encoding,
                                    signature: solution.signature,
                                    tag: solution.tag,
                                };

                                let _ = response_sender
                                    .send((solution, proposed_proof_of_space_result.secret_key))
                                    .await;
                            }
                        }
                    };

                    // Run above future with timeout
                    let _ = executor.spawn(
                        future::select(
                            futures_timer::Delay::new(SOLUTION_TIMEOUT),
                            Box::pin(forward_solution_fut),
                        )
                        .map(|_| ()),
                    );

                    // This will be sent to the farmer
                    Ok(Ok(RpcNewSlotInfo {
                        slot_number: new_slot_info.slot.into(),
                        challenge: new_slot_info.challenge,
                        salt: new_slot_info.salt,
                        next_salt: new_slot_info.next_salt,
                        solution_range: new_slot_info.solution_range,
                    }))
                })
                .forward(sink.sink_map_err(|e| warn!("Error sending notifications: {:?}", e)))
                .map(|_| ())
        });
    }

    fn unsubscribe_slot_info(
        &self,
        _metadata: Option<Self::Metadata>,
        id: SubscriptionId,
    ) -> RpcResult<bool> {
        Ok(self.subscription_manager.cancel(id))
    }

    fn subscribe_archived_segment(
        &self,
        _metadata: Self::Metadata,
        subscriber: Subscriber<RpcArchivedSegment>,
    ) {
        self.subscription_manager.add(subscriber, |sink| {
            self.archived_segment_notification_stream
                .subscribe()
                .map(|archived_segment_notification| {
                    // This will be sent to the farmer
                    Ok(Ok(archived_segment_notification.into()))
                })
                .forward(sink.sink_map_err(|e| warn!("Error sending notifications: {:?}", e)))
                .map(|_| ())
        });
    }

    fn unsubscribe_archived_segment(
        &self,
        _metadata: Option<Self::Metadata>,
        id: SubscriptionId,
    ) -> RpcResult<bool> {
        Ok(self.subscription_manager.cancel(id))
    }
}

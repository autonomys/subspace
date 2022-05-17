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
use jsonrpsee::{
    core::{async_trait, Error as JsonRpseeError, RpcResult},
    proc_macros::rpc,
    PendingSubscription,
};
use log::{error, warn};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_client_api::BlockBackend;
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::{
    ArchivedSegmentNotification, BlockSigningNotification, NewSlotNotification,
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
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::{BlockNumber, Solution};
use subspace_rpc_primitives::{
    BlockSignature, BlockSigningInfo, FarmerMetadata, SlotInfo, SolutionResponse,
};

const SOLUTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Provides rpc methods for interacting with Subspace.
#[rpc(client, server)]
pub trait SubspaceRpcApi {
    /// Ger metadata necessary for farmer operation
    #[method(name = "subspace_getFarmerMetadata")]
    fn get_farmer_metadata(&self) -> RpcResult<FarmerMetadata>;

    /// Get best block number
    #[method(name = "subspace_getBestBlockNumber")]
    fn get_best_block_number(&self) -> RpcResult<BlockNumber>;

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
        name = "subspace_subscribeBlockSigning" => "subspace_block_signing",
        unsubscribe = "subspace_unsubscribeBlockSigning",
        item = BlockSigningInfo,
    )]
    fn subscribe_block_signing(&self);

    #[method(name = "subspace_submitBlockSignature")]
    fn submit_block_signature(&self, block_signature: BlockSignature) -> RpcResult<()>;

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
    current_header_hash: H256,
    senders: Vec<async_oneshot::Sender<BlockSignature>>,
}

#[derive(Default)]
struct ArchivedSegmentAcknowledgementSenders {
    segment_index: u64,
    senders: Vec<TracingUnboundedSender<()>>,
}

/// Implements the [`SubspaceRpcApi`] trait for interacting with Subspace.
pub struct SubspaceRpc<Block, Client> {
    client: Arc<Client>,
    executor: SubscriptionTaskExecutor,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    block_signing_notification_stream: SubspaceNotificationStream<BlockSigningNotification>,
    archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegmentNotification>,
    solution_response_senders: Arc<Mutex<SolutionResponseSenders>>,
    block_signature_senders: Arc<Mutex<BlockSignatureSenders>>,
    archived_segment_acknowledgement_senders: Arc<Mutex<ArchivedSegmentAcknowledgementSenders>>,
    _phantom: PhantomData<Block>,
}

/// [`SubspaceRpcHandler`] is used for notifying subscribers about arrival of new slots and for
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
    Client::Api: SubspaceRuntimeApi<Block>,
{
    /// Creates a new instance of the `SubspaceRpc` handler.
    pub fn new(
        client: Arc<Client>,
        executor: SubscriptionTaskExecutor,
        new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
        block_signing_notification_stream: SubspaceNotificationStream<BlockSigningNotification>,
        archived_segment_notification_stream: SubspaceNotificationStream<
            ArchivedSegmentNotification,
        >,
    ) -> Self {
        Self {
            client,
            executor,
            new_slot_notification_stream,
            block_signing_notification_stream,
            archived_segment_notification_stream,
            solution_response_senders: Arc::default(),
            block_signature_senders: Arc::default(),
            archived_segment_acknowledgement_senders: Arc::default(),
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
    Client::Api: SubspaceRuntimeApi<Block>,
{
    fn get_farmer_metadata(&self) -> RpcResult<FarmerMetadata> {
        let best_block_id = BlockId::Hash(self.client.info().best_hash);
        let runtime_api = self.client.runtime_api();

        let farmer_metadata: Result<FarmerMetadata, ApiError> = try {
            FarmerMetadata {
                record_size: runtime_api.record_size(&best_block_id)?,
                recorded_history_segment_size: runtime_api
                    .recorded_history_segment_size(&best_block_id)?,
                max_plot_size: runtime_api
                    .max_plot_size(&best_block_id)
                    // TODO: Remove once we switch genesis runtime from `snapshot-2022-mar-09`
                    //  to newer
                    .unwrap_or(
                        100 * 1024 * 1024 * 1024 / subspace_core_primitives::PIECE_SIZE as u64,
                    ),
            }
        };

        farmer_metadata.map_err(|error| {
            error!("Failed to get data from runtime API: {}", error);
            JsonRpseeError::Custom("Internal error".to_string())
        })
    }

    fn get_best_block_number(&self) -> RpcResult<BlockNumber> {
        let best_number = TryInto::<BlockNumber>::try_into(self.client.info().best_number)
            .unwrap_or_else(|_| {
                panic!("Block number can't be converted into BlockNumber");
            });

        Ok(best_number)
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
                                let public_key =
                                    match FarmerPublicKey::from_slice(&solution.public_key) {
                                        Ok(public_key) => public_key,
                                        Err(()) => {
                                            warn!(
                                                "Failed to convert public key: {:?}",
                                                solution.public_key
                                            );
                                            return;
                                        }
                                    };
                                let reward_address =
                                    match FarmerPublicKey::from_slice(&solution.reward_address) {
                                        Ok(public_key) => public_key,
                                        Err(()) => {
                                            warn!(
                                                "Failed to convert reward address: {:?}",
                                                solution.reward_address,
                                            );
                                            return;
                                        }
                                    };

                                let solution = Solution {
                                    public_key,
                                    reward_address,
                                    piece_index: solution.piece_index,
                                    encoding: solution.encoding,
                                    signature: solution.signature,
                                    local_challenge: solution.local_challenge,
                                    tag: solution.tag,
                                };

                                let _ = solution_sender.send(solution).await;
                            }
                        }
                    };

                    // Run above future with timeout
                    let _ = executor.spawn(
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

    fn subscribe_block_signing(&self, pending: PendingSubscription) {
        let executor = self.executor.clone();
        let block_signature_senders = self.block_signature_senders.clone();

        let stream = self.block_signing_notification_stream.subscribe().map(
            move |block_signing_notification| {
                let BlockSigningNotification {
                    header_hash,
                    mut signature_sender,
                } = block_signing_notification;

                let (response_sender, response_receiver) = async_oneshot::oneshot();

                // Store signature sender so that we can retrieve it when solution comes from
                // the farmer
                {
                    let mut block_signature_senders = block_signature_senders.lock();

                    if block_signature_senders.current_header_hash != header_hash {
                        block_signature_senders.current_header_hash = header_hash;
                        block_signature_senders.senders.clear();
                    }

                    block_signature_senders.senders.push(response_sender);
                }

                // Wait for solutions and transform proposed proof of space solutions into
                // data structure `sc-consensus-subspace` expects
                let forward_signature_fut = async move {
                    if let Ok(block_signature) = response_receiver.await {
                        if let Some(signature) = block_signature.signature {
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
                let _ = executor.spawn(
                    "subspace-block-signing-forward",
                    Some("rpc"),
                    future::select(
                        futures_timer::Delay::new(SOLUTION_TIMEOUT),
                        Box::pin(forward_signature_fut),
                    )
                    .map(|_| ())
                    .boxed(),
                );

                // This will be sent to the farmer
                BlockSigningInfo {
                    header_hash: header_hash.into(),
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

    fn submit_block_signature(&self, block_signature: BlockSignature) -> RpcResult<()> {
        let block_signature_senders = self.block_signature_senders.clone();

        // TODO: This doesn't track what client sent a solution, allowing some clients to send
        //  multiple (https://github.com/paritytech/jsonrpsee/issues/452)
        let mut block_signature_senders = block_signature_senders.lock();

        if block_signature_senders.current_header_hash == block_signature.header_hash.into() {
            if let Some(mut sender) = block_signature_senders.senders.pop() {
                let _ = sender.send(block_signature);
            }
        }

        Ok(())
    }

    fn subscribe_archived_segment(&self, pending: PendingSubscription) {
        let archived_segment_acknowledgement_senders =
            self.archived_segment_acknowledgement_senders.clone();

        let stream = self.archived_segment_notification_stream.subscribe().map(
            move |archived_segment_notification| {
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

                    archived_segment_acknowledgement_senders
                        .senders
                        .push(acknowledgement_sender);
                }

                // This will be sent to the farmer
                archived_segment.as_ref().clone()
            },
        );

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
                .then(|| archived_segment_acknowledgement_senders_guard.senders.pop())
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

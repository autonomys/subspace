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

use futures::task::SpawnExt;
use futures::{future, task::Spawn, FutureExt, SinkExt, StreamExt};
use jsonrpc_core::{Error as RpcError, ErrorCode, Result as RpcResult};
use jsonrpc_derive::rpc;
use jsonrpc_pubsub::{manager::SubscriptionManager, typed::Subscriber, SubscriptionId};
use log::{error, warn};
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_client_api::BlockBackend;
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::{ArchivedSegment, BlockSigningNotification, NewSlotNotification};
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::Solution;
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature, SubspaceApi as SubspaceRuntimeApi};
use sp_core::crypto::ByteArray;
use sp_core::H256;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;
use subspace_rpc_primitives::{
    BlockSignature, BlockSigningInfo, EncodedBlockWithObjectMapping, FarmerMetadata, SlotInfo,
    SolutionResponse,
};

const SOLUTION_TIMEOUT: Duration = Duration::from_secs(5);

type FutureResult<T> = jsonrpc_core::BoxFuture<Result<T, RpcError>>;

/// Provides rpc methods for interacting with Subspace.
#[rpc]
pub trait SubspaceRpcApi {
    /// RPC metadata
    type Metadata;

    /// Ger metadata necessary for farmer operation
    #[rpc(name = "subspace_getFarmerMetadata")]
    fn get_farmer_metadata(&self) -> FutureResult<FarmerMetadata>;

    /// Get encoded block by given block number
    #[rpc(name = "subspace_getBlockByNumber")]
    fn get_block_by_number(
        &self,
        block_number: u32,
    ) -> FutureResult<Option<EncodedBlockWithObjectMapping>>;

    #[rpc(name = "subspace_submitSolutionResponse")]
    fn submit_solution_response(&self, solution_response: SolutionResponse) -> FutureResult<()>;

    /// Slot info subscription
    #[pubsub(
        subscription = "subspace_slot_info",
        subscribe,
        name = "subspace_subscribeSlotInfo"
    )]
    fn subscribe_slot_info(&self, metadata: Self::Metadata, subscriber: Subscriber<SlotInfo>);

    /// Unsubscribe from slot info subscription.
    #[pubsub(
        subscription = "subspace_slot_info",
        unsubscribe,
        name = "subspace_unsubscribeSlotInfo"
    )]
    fn unsubscribe_slot_info(
        &self,
        metadata: Option<Self::Metadata>,
        id: SubscriptionId,
    ) -> RpcResult<bool>;

    /// Sign block subscription
    #[pubsub(
        subscription = "subspace_block_signing",
        subscribe,
        name = "subspace_subscribeBlockSigning"
    )]
    fn subscribe_block_signing(
        &self,
        metadata: Self::Metadata,
        subscriber: Subscriber<BlockSigningInfo>,
    );

    /// Unsubscribe from sign block subscription.
    #[pubsub(
        subscription = "subspace_block_signing",
        unsubscribe,
        name = "subspace_unsubscribeBlockSigning"
    )]
    fn unsubscribe_block_signing(
        &self,
        metadata: Option<Self::Metadata>,
        id: SubscriptionId,
    ) -> RpcResult<bool>;

    #[rpc(name = "subspace_submitBlockSignature")]
    fn submit_block_signature(&self, block_signature: BlockSignature) -> FutureResult<()>;

    /// Archived segment subscription
    #[pubsub(
        subscription = "subspace_archived_segment",
        subscribe,
        name = "subspace_subscribeArchivedSegment"
    )]
    fn subscribe_archived_segment(
        &self,
        metadata: Self::Metadata,
        subscriber: Subscriber<ArchivedSegment>,
    );

    /// Unsubscribe from archived segment subscription.
    #[pubsub(
        subscription = "subspace_archived_segment",
        unsubscribe,
        name = "subspace_unsubscribeArchivedSegment"
    )]
    fn unsubscribe_archived_segment(
        &self,
        metadata: Option<Self::Metadata>,
        id: SubscriptionId,
    ) -> RpcResult<bool>;
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

/// Implements the [`SubspaceRpcApi`] trait for interacting with Subspace.
pub struct SubspaceRpcHandler<Block, Client> {
    client: Arc<Client>,
    subscription_manager: SubscriptionManager,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    block_signing_notification_stream: SubspaceNotificationStream<BlockSigningNotification>,
    archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegment>,
    solution_response_senders: Arc<Mutex<SolutionResponseSenders>>,
    block_signature_senders: Arc<Mutex<BlockSignatureSenders>>,
    _phantom: PhantomData<Block>,
}

/// [`SubspaceRpcHandler`] is used for notifying subscribers about arrival of new slots and for
/// submission of solutions (or lack thereof).
///
/// Internally every time slot notifier emits information about new slot, notification is sent to
/// every subscriber, after which RPC server waits for the same number of
/// `subspace_submitSolutionResponse` requests with `SolutionResponse` in them or until
/// timeout is exceeded. The first valid solution for a particular slot wins, others are ignored.
impl<Block, Client> SubspaceRpcHandler<Block, Client>
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
    pub fn new<E>(
        client: Arc<Client>,
        executor: E,
        new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
        block_signing_notification_stream: SubspaceNotificationStream<BlockSigningNotification>,
        archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegment>,
    ) -> Self
    where
        E: Spawn + Send + Sync + 'static,
    {
        Self {
            client,
            subscription_manager: SubscriptionManager::new(Arc::new(executor)),
            new_slot_notification_stream,
            block_signing_notification_stream,
            archived_segment_notification_stream,
            solution_response_senders: Arc::default(),
            block_signature_senders: Arc::default(),
            _phantom: PhantomData::default(),
        }
    }
}

impl<Block, Client> SubspaceRpcApi for SubspaceRpcHandler<Block, Client>
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
    type Metadata = sc_rpc_api::Metadata;

    fn get_farmer_metadata(&self) -> FutureResult<FarmerMetadata> {
        let client = Arc::clone(&self.client);
        Box::pin(async move {
            let best_block_id = BlockId::Hash(client.info().best_hash);
            let runtime_api = client.runtime_api();

            let farmer_metadata: Result<FarmerMetadata, ApiError> = try {
                FarmerMetadata {
                    confirmation_depth_k: runtime_api.confirmation_depth_k(&best_block_id)?,
                    record_size: runtime_api.record_size(&best_block_id)?,
                    recorded_history_segment_size: runtime_api
                        .recorded_history_segment_size(&best_block_id)?,
                }
            };

            farmer_metadata.map_err(|error| {
                error!("Failed to get data from runtime API: {}", error);
                RpcError::new(ErrorCode::InternalError)
            })
        })
    }

    fn get_block_by_number(
        &self,
        block_number: u32,
    ) -> FutureResult<Option<EncodedBlockWithObjectMapping>> {
        let result = self
            .client
            .block(&BlockId::Number(block_number.into()))
            .map_err(|error| {
                error!("Failed to get block by number: {}", error);
                RpcError::new(ErrorCode::InternalError)
            })
            .and_then(|block| {
                Ok(if let Some(block) = block {
                    let encoded_block = block.encode();
                    let object_mapping = self
                        .client
                        .runtime_api()
                        .extract_block_object_mapping(
                            &BlockId::Number(block_number.saturating_sub(1).into()),
                            block.block,
                        )
                        .map_err(|error| {
                            error!("Failed to extract object mapping: {}", error);
                            RpcError::new(ErrorCode::InternalError)
                        })?;

                    Some(EncodedBlockWithObjectMapping {
                        block: encoded_block,
                        object_mapping,
                    })
                } else {
                    None
                })
            });

        Box::pin(async move { result })
    }

    fn submit_solution_response(&self, solution_response: SolutionResponse) -> FutureResult<()> {
        let solution_response_senders = self.solution_response_senders.clone();

        // TODO: This doesn't track what client sent a solution, allowing some clients to send
        //  multiple (https://github.com/paritytech/jsonrpsee/issues/452)
        Box::pin(async move {
            let mut solution_response_senders = solution_response_senders.lock();

            if *solution_response_senders.current_slot == solution_response.slot_number {
                if let Some(mut sender) = solution_response_senders.senders.pop() {
                    let _ = sender.send(solution_response);
                }
            }

            Ok(())
        })
    }

    fn subscribe_slot_info(&self, _metadata: Self::Metadata, subscriber: Subscriber<SlotInfo>) {
        self.subscription_manager.add(subscriber, |sink| {
            let executor = self.subscription_manager.executor().clone();
            let solution_response_senders = self.solution_response_senders.clone();

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
                                        Err(_) => {
                                            warn!(
                                                "Failed to convert public key: {:?}",
                                                solution.public_key
                                            );
                                            return;
                                        }
                                    };
                                let solution = Solution {
                                    public_key,
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
                        future::select(
                            futures_timer::Delay::new(SOLUTION_TIMEOUT),
                            Box::pin(forward_solution_fut),
                        )
                        .map(|_| ()),
                    );

                    // This will be sent to the farmer
                    Ok(Ok(SlotInfo {
                        slot_number: new_slot_info.slot.into(),
                        global_challenge: new_slot_info.global_challenge,
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

    fn subscribe_block_signing(
        &self,
        _metadata: Self::Metadata,
        subscriber: Subscriber<BlockSigningInfo>,
    ) {
        self.subscription_manager.add(subscriber, |sink| {
            let executor = self.subscription_manager.executor().clone();
            let block_signature_senders = self.block_signature_senders.clone();

            self.block_signing_notification_stream
                .subscribe()
                .map(move |block_signing_notification| {
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
                        future::select(
                            futures_timer::Delay::new(SOLUTION_TIMEOUT),
                            Box::pin(forward_signature_fut),
                        )
                        .map(|_| ()),
                    );

                    // This will be sent to the farmer
                    Ok(Ok(BlockSigningInfo {
                        header_hash: header_hash.into(),
                    }))
                })
                .forward(sink.sink_map_err(|e| warn!("Error sending notifications: {:?}", e)))
                .map(|_| ())
        });
    }

    fn unsubscribe_block_signing(
        &self,
        _metadata: Option<Self::Metadata>,
        id: SubscriptionId,
    ) -> RpcResult<bool> {
        Ok(self.subscription_manager.cancel(id))
    }

    fn submit_block_signature(&self, block_signature: BlockSignature) -> FutureResult<()> {
        let block_signature_senders = self.block_signature_senders.clone();

        // TODO: This doesn't track what client sent a solution, allowing some clients to send
        //  multiple (https://github.com/paritytech/jsonrpsee/issues/452)
        Box::pin(async move {
            let mut block_signature_senders = block_signature_senders.lock();

            if block_signature_senders.current_header_hash == block_signature.header_hash.into() {
                if let Some(mut sender) = block_signature_senders.senders.pop() {
                    let _ = sender.send(block_signature);
                }
            }

            Ok(())
        })
    }

    fn subscribe_archived_segment(
        &self,
        _metadata: Self::Metadata,
        subscriber: Subscriber<ArchivedSegment>,
    ) {
        self.subscription_manager.add(subscriber, |sink| {
            self.archived_segment_notification_stream
                .subscribe()
                .map(|archived_segment_notification| {
                    // This will be sent to the farmer
                    Ok(Ok(archived_segment_notification))
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

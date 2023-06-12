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

use futures::{future, FutureExt, StreamExt};
use jsonrpsee::core::{async_trait, Error as JsonRpseeError, RpcResult};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::SubscriptionResult;
use jsonrpsee::SubscriptionSink;
use parity_scale_codec::{Decode, Encode};
use parking_lot::Mutex;
use sc_client_api::BlockBackend;
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::{
    ArchivedSegmentNotification, NewSlotNotification, RewardSigningNotification, SubspaceLink,
};
use sc_rpc::SubscriptionTaskExecutor;
use sp_api::{ApiError, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus_slots::Slot;
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature, SubspaceApi as SubspaceRuntimeApi};
use sp_core::crypto::ByteArray;
use sp_core::H256;
use sp_runtime::traits::{Block as BlockT, Zero};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::{
    Piece, PieceIndex, SegmentCommitment, SegmentHeader, SegmentIndex, Solution,
};
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_networking::libp2p::Multiaddr;
use subspace_rpc_primitives::{
    FarmerAppInfo, RewardSignatureResponse, RewardSigningInfo, SlotInfo, SolutionResponse,
    MAX_SEGMENT_INDEXES_PER_REQUEST,
};
use tracing::{error, warn};

const SOLUTION_TIMEOUT: Duration = Duration::from_secs(2);
const REWARD_SIGNING_TIMEOUT: Duration = Duration::from_millis(500);

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

    #[method(name = "subspace_recordsRoots")]
    async fn segment_commitments(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> RpcResult<Vec<Option<SegmentCommitment>>>;

    #[method(name = "subspace_SegmentHeaders")]
    async fn segment_headers(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> RpcResult<Vec<Option<SegmentHeader>>>;

    #[method(name = "subspace_Piece", blocking)]
    fn piece(&self, piece_index: PieceIndex) -> RpcResult<Option<Vec<u8>>>;
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

pub trait SegmentHeaderProvider {
    fn get_segment_header(
        &self,
        segment_index: SegmentIndex,
    ) -> Result<Option<SegmentHeader>, Box<dyn Error>>;
}

pub trait PieceProvider {
    fn get_piece_by_index(
        &self,
        piece_index: PieceIndex,
    ) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>>;
}

/// Implements the [`SubspaceRpcApiServer`] trait for interacting with Subspace.
pub struct SubspaceRpc<Block: BlockT, Client, RBP: SegmentHeaderProvider, PP: PieceProvider> {
    client: Arc<Client>,
    executor: SubscriptionTaskExecutor,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    archived_segment_notification_stream: SubspaceNotificationStream<ArchivedSegmentNotification>,
    solution_response_senders: Arc<Mutex<SolutionResponseSenders>>,
    reward_signature_senders: Arc<Mutex<BlockSignatureSenders>>,
    dsn_bootstrap_nodes: Vec<Multiaddr>,
    subspace_link: SubspaceLink<Block>,
    segment_header_provider: RBP,
    piece_provider: Option<PP>,
}

/// [`SubspaceRpc`] is used for notifying subscribers about arrival of new slots and for
/// submission of solutions (or lack thereof).
///
/// Internally every time slot notifier emits information about new slot, notification is sent to
/// every subscriber, after which RPC server waits for the same number of
/// `subspace_submitSolutionResponse` requests with `SolutionResponse` in them or until
/// timeout is exceeded. The first valid solution for a particular slot wins, others are ignored.
impl<Block: BlockT, Client, RBP: SegmentHeaderProvider, PP: PieceProvider>
    SubspaceRpc<Block, Client, RBP, PP>
{
    #[allow(clippy::too_many_arguments)]
    /// Creates a new instance of the `SubspaceRpc` handler.
    pub fn new(
        client: Arc<Client>,
        executor: SubscriptionTaskExecutor,
        new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
        reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
        archived_segment_notification_stream: SubspaceNotificationStream<
            ArchivedSegmentNotification,
        >,
        dsn_bootstrap_nodes: Vec<Multiaddr>,
        subspace_link: SubspaceLink<Block>,
        segment_header_provider: RBP,
        piece_provider: Option<PP>,
    ) -> Self {
        Self {
            client,
            executor,
            new_slot_notification_stream,
            reward_signing_notification_stream,
            archived_segment_notification_stream,
            solution_response_senders: Arc::default(),
            reward_signature_senders: Arc::default(),
            dsn_bootstrap_nodes,
            subspace_link,
            segment_header_provider,
            piece_provider,
        }
    }
}

#[async_trait]
impl<Block, Client, RBP, PP> SubspaceRpcApiServer for SubspaceRpc<Block, Client, RBP, PP>
where
    Block: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceRuntimeApi<Block, FarmerPublicKey>,
    RBP: SegmentHeaderProvider + Send + Sync + 'static,
    PP: PieceProvider + Send + Sync + 'static,
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
            let protocol_info = FarmerProtocolInfo {
                history_size: runtime_api.history_size(best_hash)?,
                max_pieces_in_sector: runtime_api.max_pieces_in_sector(best_hash)?,
                // TODO: Fetch this from the runtime
                sector_expiration: SegmentIndex::from(100),
            };

            FarmerAppInfo {
                genesis_hash,
                dsn_bootstrap_nodes: self.dsn_bootstrap_nodes.clone(),
                protocol_info,
            }
        };

        farmer_app_info.map_err(|error| {
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

    fn subscribe_slot_info(&self, mut sink: SubscriptionSink) -> SubscriptionResult {
        let executor = self.executor.clone();
        let solution_response_senders = self.solution_response_senders.clone();

        let stream =
            self.new_slot_notification_stream
                .subscribe()
                .map(move |new_slot_notification| {
                    let NewSlotNotification {
                        new_slot_info,
                        solution_sender,
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
                            for solution in solution_response.solutions {
                                let public_key =
                                    FarmerPublicKey::from_slice(solution.public_key.as_ref())
                                        .expect("Always correct length; qed");
                                let reward_address =
                                    FarmerPublicKey::from_slice(solution.reward_address.as_ref())
                                        .expect("Always correct length; qed");

                                let solution = Solution {
                                    public_key,
                                    reward_address,
                                    sector_index: solution.sector_index,
                                    history_size: solution.history_size,
                                    piece_offset: solution.piece_offset,
                                    record_commitment: solution.record_commitment,
                                    record_witness: solution.record_witness,
                                    chunk: solution.chunk,
                                    chunk_witness: solution.chunk_witness,
                                    audit_chunk_offset: solution.audit_chunk_offset,
                                    proof_of_space: solution.proof_of_space,
                                };

                                let _ = solution_sender.unbounded_send(solution);
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
                        solution_range: new_slot_info.solution_range,
                        voting_solution_range: new_slot_info.voting_solution_range,
                    }
                });

        let fut = async move {
            sink.pipe_from_stream(stream).await;
        };

        self.executor
            .spawn("subspace-slot-info-subscription", Some("rpc"), fut.boxed());

        Ok(())
    }

    fn subscribe_reward_signing(&self, mut sink: SubscriptionSink) -> SubscriptionResult {
        let executor = self.executor.clone();
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

        self.executor.spawn(
            "subspace-block-signing-subscription",
            Some("rpc"),
            fut.boxed(),
        );

        Ok(())
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

    fn subscribe_archived_segment_header(&self, mut sink: SubscriptionSink) -> SubscriptionResult {
        let stream = self.archived_segment_notification_stream.subscribe().map(
            |archived_segment_notification| {
                archived_segment_notification
                    .archived_segment
                    .segment_header
            },
        );

        let fut = async move {
            sink.pipe_from_stream(stream).await;
        };

        self.executor.spawn(
            "subspace-archived-segment-header-subscription",
            Some("rpc"),
            fut.boxed(),
        );

        Ok(())
    }

    async fn segment_commitments(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> RpcResult<Vec<Option<SegmentCommitment>>> {
        if segment_indexes.len() > MAX_SEGMENT_INDEXES_PER_REQUEST {
            error!(
                "segment_indexes length exceed the limit: {} ",
                segment_indexes.len()
            );

            return Err(JsonRpseeError::Custom(format!(
                "segment_indexes length exceed the limit {MAX_SEGMENT_INDEXES_PER_REQUEST}"
            )));
        };

        let runtime_api = self.client.runtime_api();
        let best_hash = self.client.info().best_hash;
        let best_block_number = self.client.info().best_number;

        let segment_commitment_result: Result<Vec<_>, JsonRpseeError> = segment_indexes
            .into_iter()
            .map(|segment_index| {
                let api_result = runtime_api
                    .segment_commitment(best_hash, segment_index)
                    .map_err(|_| {
                        JsonRpseeError::Custom(
                            "Internal error during `segment_commitment` call".to_string(),
                        )
                    });

                api_result.map(|maybe_segment_commitment| {
                    // This is not a very nice hack due to the fact that at the time first block is
                    //  produced extrinsics with segment headers are not yet in runtime.
                    if maybe_segment_commitment.is_none() && best_block_number.is_zero() {
                        self.subspace_link
                            .segment_commitment_by_segment_index(segment_index)
                    } else {
                        maybe_segment_commitment
                    }
                })
            })
            .collect();

        if let Err(ref err) = segment_commitment_result {
            error!(
                "Failed to get data from runtime API (segment_commitment): {}",
                err
            );
        }

        segment_commitment_result
    }

    async fn segment_headers(
        &self,
        segment_indexes: Vec<SegmentIndex>,
    ) -> RpcResult<Vec<Option<SegmentHeader>>> {
        if segment_indexes.len() > MAX_SEGMENT_INDEXES_PER_REQUEST {
            error!(
                "segment_indexes length exceed the limit: {} ",
                segment_indexes.len()
            );

            return Err(JsonRpseeError::Custom(format!(
                "segment_indexes length exceed the limit {MAX_SEGMENT_INDEXES_PER_REQUEST}"
            )));
        };

        let segment_commitment_result: Result<Vec<_>, JsonRpseeError> = segment_indexes
            .into_iter()
            .map(|segment_index| {
                let api_result = self
                    .segment_header_provider
                    .get_segment_header(segment_index)
                    .map_err(|_| {
                        JsonRpseeError::Custom(
                            "Internal error during `segment_headers` call".to_string(),
                        )
                    });

                api_result
            })
            .collect();

        if let Err(err) = &segment_commitment_result {
            error!(?err, "Failed to get segment headers.");
        }

        segment_commitment_result
    }

    fn piece(&self, piece_index: PieceIndex) -> RpcResult<Option<Vec<u8>>> {
        if let Some(piece_provider) = self.piece_provider.as_ref() {
            let result = piece_provider.get_piece_by_index(piece_index).map_err(|_| {
                JsonRpseeError::Custom("Internal error during `piece` call".to_string())
            });

            if let Err(err) = &result {
                error!(?err, %piece_index, "Failed to get a piece.");
            }

            result.map(|piece| piece.map(|piece| piece.to_vec()))
        } else {
            Err(JsonRpseeError::Custom(
                "Piece provider is not set.".to_string(),
            ))
        }
    }
}

// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

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

//! Subspace test client only.

#![warn(missing_docs, unused_crate_dependencies)]

pub mod chain_spec;

use futures::{SinkExt, StreamExt};
use rand::prelude::*;
use sc_client_api::BlockBackend;
use sc_consensus_subspace::{
    notification::SubspaceNotificationStream, BlockSigningNotification, NewSlotNotification,
};
use sp_api::ProvideRuntimeApi;
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature, SubspaceApi};
use sp_core::crypto::UncheckedFrom;
use sp_core::{Decode, Encode};
use std::sync::Arc;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{FlatPieces, Piece, Solution, Tag};
use subspace_runtime_primitives::opaque::{Block, BlockId};
use subspace_service::{FullClient, NewFull};
use subspace_solving::{SubspaceCodec, SOLUTION_SIGNING_CONTEXT};
use zeroize::Zeroizing;

/// Subspace native executor instance.
pub struct TestExecutorDispatch;

impl sc_executor::NativeExecutionDispatch for TestExecutorDispatch {
    /// Otherwise we only use the default Substrate host functions.
    type ExtendHostFunctions = sp_executor::fraud_proof_ext::fraud_proof::HostFunctions;

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        subspace_test_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        subspace_test_runtime::native_version()
    }
}

/// The client type being used by the test service.
pub type Client = FullClient<subspace_test_runtime::RuntimeApi, TestExecutorDispatch>;

/// The backend type being used by the test service.
pub type Backend = sc_service::TFullBackend<Block>;

/// Run a farmer.
pub fn start_farmer(new_full: &NewFull<Arc<Client>>) {
    let client = new_full.client.clone();
    let new_slot_notification_stream = new_full.new_slot_notification_stream.clone();
    let block_signing_notification_stream = new_full.block_signing_notification_stream.clone();

    let keypair = schnorrkel::Keypair::generate();
    let subspace_farming = start_farming(keypair.clone(), client, new_slot_notification_stream);
    new_full
        .task_manager
        .spawn_essential_handle()
        .spawn_blocking("subspace-farmer", Some("farming"), subspace_farming);

    new_full
        .task_manager
        .spawn_essential_handle()
        .spawn_blocking("subspace-farmer", Some("block-signing"), async move {
            const SUBSTRATE_SIGNING_CONTEXT: &[u8] = b"substrate";

            let substrate_ctx = schnorrkel::context::signing_context(SUBSTRATE_SIGNING_CONTEXT);
            let signing_pair: Zeroizing<schnorrkel::Keypair> = Zeroizing::new(keypair);

            let mut block_signing_notification_stream =
                block_signing_notification_stream.subscribe();

            while let Some(BlockSigningNotification {
                header_hash,
                mut signature_sender,
            }) = block_signing_notification_stream.next().await
            {
                let header_hash: [u8; 32] = header_hash.into();
                let block_signature: schnorrkel::Signature =
                    signing_pair.sign(substrate_ctx.bytes(&header_hash));
                let signature: subspace_core_primitives::Signature =
                    block_signature.to_bytes().into();
                signature_sender
                    .send(
                        FarmerSignature::decode(&mut signature.encode().as_ref())
                            .expect("Failed to decode schnorrkel block signature"),
                    )
                    .await
                    .unwrap();
            }
        });
}

async fn start_farming<Client>(
    keypair: schnorrkel::Keypair,
    client: Arc<Client>,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
) where
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block> + Send + Sync + 'static,
    Client::Api: SubspaceApi<Block>,
{
    let (archived_pieces_sender, archived_pieces_receiver) = futures::channel::oneshot::channel();

    std::thread::spawn({
        move || {
            let archived_pieces = get_archived_pieces(&client);
            archived_pieces_sender.send(archived_pieces).unwrap();
        }
    });

    let subspace_solving = SubspaceCodec::new(&keypair.public);
    let ctx = schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT);
    let (piece_index, mut encoding) = archived_pieces_receiver
        .await
        .unwrap()
        .iter()
        .flat_map(|flat_pieces| flat_pieces.as_pieces())
        .enumerate()
        .choose(&mut rand::thread_rng())
        .map(|(piece_index, piece)| (piece_index as u64, Piece::try_from(piece).unwrap()))
        .unwrap();
    subspace_solving.encode(&mut encoding, piece_index).unwrap();

    let mut new_slot_notification_stream = new_slot_notification_stream.subscribe();

    while let Some(NewSlotNotification {
        new_slot_info,
        mut solution_sender,
    }) = new_slot_notification_stream.next().await
    {
        if Into::<u64>::into(new_slot_info.slot) % 2 == 0 {
            let tag: Tag = subspace_solving::create_tag(&encoding, new_slot_info.salt);

            let _ = solution_sender
                .send(Solution {
                    public_key: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
                    reward_address: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
                    piece_index,
                    encoding,
                    signature: keypair.sign(ctx.bytes(&tag)).to_bytes().into(),
                    local_challenge: keypair
                        .sign(ctx.bytes(&new_slot_info.global_challenge))
                        .to_bytes()
                        .into(),
                    tag,
                })
                .await;
        }
    }
}

fn get_archived_pieces<Client>(client: &Arc<Client>) -> Vec<FlatPieces>
where
    Client: ProvideRuntimeApi<Block> + BlockBackend<Block>,
    Client::Api: SubspaceApi<Block>,
{
    let genesis_block_id = BlockId::Number(sp_runtime::traits::Zero::zero());
    let runtime_api = client.runtime_api();

    let record_size = runtime_api.record_size(&genesis_block_id).unwrap();
    let recorded_history_segment_size = runtime_api
        .recorded_history_segment_size(&genesis_block_id)
        .unwrap();

    let mut archiver = subspace_archiving::archiver::Archiver::new(
        record_size as usize,
        recorded_history_segment_size as usize,
    )
    .expect("Incorrect parameters for archiver");

    let genesis_block = client.block(&genesis_block_id).unwrap().unwrap();
    archiver
        .add_block(genesis_block.encode(), BlockObjectMapping::default())
        .into_iter()
        .map(|archived_segment| archived_segment.pieces)
        .collect()
}

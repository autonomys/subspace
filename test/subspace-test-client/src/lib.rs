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
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::{NewSlotNotification, RewardSigningNotification};
use sp_api::{BlockId, ProvideRuntimeApi};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature, SubspaceApi};
use sp_core::crypto::UncheckedFrom;
use sp_core::{Decode, Encode};
use std::sync::Arc;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{
    FlatPieces, Piece, Solution, Tag, RECORDED_HISTORY_SEGMENT_SIZE, RECORD_SIZE,
};
use subspace_runtime_primitives::opaque::Block;
use subspace_service::{FullClient, NewFull};
use subspace_solving::{
    create_chunk_signature, create_tag, derive_local_challenge, SubspaceCodec,
    REWARD_SIGNING_CONTEXT,
};
use zeroize::Zeroizing;

/// Subspace native executor instance.
pub struct TestExecutorDispatch;

impl sc_executor::NativeExecutionDispatch for TestExecutorDispatch {
    /// Otherwise we only use the default Substrate host functions.
    type ExtendHostFunctions = ();

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

/// The fraud proof verifier being used the test service.
pub type FraudProofVerifier =
    subspace_service::FraudProofVerifier<subspace_test_runtime::RuntimeApi, TestExecutorDispatch>;

/// Run a farmer.
pub fn start_farmer(new_full: &NewFull<Client, FraudProofVerifier>) {
    let client = new_full.client.clone();
    let new_slot_notification_stream = new_full.new_slot_notification_stream.clone();
    let reward_signing_notification_stream = new_full.reward_signing_notification_stream.clone();
    let mut archived_segment_notification_stream =
        new_full.archived_segment_notification_stream.subscribe();

    new_full.task_manager.spawn_essential_handle().spawn(
        "archived_segment_notification_stream",
        None,
        async move {
            while let Some(mut archived_segment_notification) =
                archived_segment_notification_stream.next().await
            {
                println!("\n\n\nSending acknowledgement!\n\n\n");
                let _ = archived_segment_notification
                    .acknowledgement_sender
                    .send(())
                    .await;
            }
        },
    );

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
            let substrate_ctx = schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT);
            let signing_pair: Zeroizing<schnorrkel::Keypair> = Zeroizing::new(keypair);

            let mut reward_signing_notification_stream =
                reward_signing_notification_stream.subscribe();

            while let Some(RewardSigningNotification {
                hash: header_hash,
                mut signature_sender,
                ..
            }) = reward_signing_notification_stream.next().await
            {
                let header_hash: [u8; 32] = header_hash.into();
                let signature: subspace_core_primitives::RewardSignature = signing_pair
                    .sign(substrate_ctx.bytes(&header_hash))
                    .to_bytes()
                    .into();
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
    Client::Api: SubspaceApi<Block, FarmerPublicKey>,
{
    let (archived_pieces_sender, archived_pieces_receiver) = futures::channel::oneshot::channel();

    std::thread::spawn({
        move || {
            let archived_pieces = get_archived_pieces(client.as_ref());
            archived_pieces_sender.send(archived_pieces).unwrap();
        }
    });

    let subspace_codec = SubspaceCodec::new(keypair.public.as_ref());
    let (piece_index, mut encoding) = archived_pieces_receiver
        .await
        .unwrap()
        .iter()
        .flat_map(|flat_pieces| flat_pieces.as_pieces())
        .enumerate()
        .choose(&mut rand::thread_rng())
        .map(|(piece_index, piece)| (piece_index as u64, Piece::try_from(piece).unwrap()))
        .unwrap();
    subspace_codec.encode(&mut encoding, piece_index).unwrap();

    let mut new_slot_notification_stream = new_slot_notification_stream.subscribe();

    while let Some(NewSlotNotification {
        new_slot_info,
        mut solution_sender,
    }) = new_slot_notification_stream.next().await
    {
        if Into::<u64>::into(new_slot_info.slot) % 2 == 0 {
            let tag: Tag = create_tag(&encoding, new_slot_info.salt);

            // TODO: Update implementation for V2 consensus
            // let _ = solution_sender
            //     .send(Solution {
            //         public_key: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
            //         reward_address: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
            //         piece_index,
            //         encoding: encoding.clone(),
            //         tag_signature: create_chunk_signature(&keypair, tag),
            //         local_challenge: derive_local_challenge(
            //             &keypair,
            //             new_slot_info.global_challenge,
            //         ),
            //         tag,
            //     })
            //     .await;
        }
    }
}

fn get_archived_pieces<Client>(client: &Client) -> Vec<FlatPieces>
where
    Client: BlockBackend<Block>,
{
    let genesis_block_id = BlockId::Number(sp_runtime::traits::Zero::zero());

    let kzg = Kzg::new(kzg::test_public_parameters());
    let mut archiver = subspace_archiving::archiver::Archiver::new(
        RECORD_SIZE,
        RECORDED_HISTORY_SEGMENT_SIZE,
        kzg,
    )
    .expect("Incorrect parameters for archiver");

    let genesis_block = client.block(&genesis_block_id).unwrap().unwrap();
    archiver
        .add_block(genesis_block.encode(), BlockObjectMapping::default())
        .into_iter()
        .map(|archived_segment| archived_segment.pieces)
        .collect()
}

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

use bitvec::prelude::*;
use futures::{SinkExt, StreamExt};
use sc_client_api::BlockBackend;
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::{NewSlotNotification, RewardSigningNotification};
use sp_api::{BlockId, ProvideRuntimeApi};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature, SubspaceApi};
use sp_core::crypto::UncheckedFrom;
use sp_core::{Decode, Encode};
use std::num::{NonZeroU16, NonZeroU64};
use std::sync::Arc;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::crypto::kzg::{Kzg, Witness};
use subspace_core_primitives::crypto::{blake2b_256_254_hash, kzg};
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{
    Chunk, Piece, PieceIndex, PublicKey, SectorId, Solution, PIECE_SIZE,
    RECORDED_HISTORY_SEGMENT_SIZE, RECORD_SIZE,
};
use subspace_runtime_primitives::opaque::Block;
use subspace_service::{FullClient, NewFull};
use subspace_solving::{create_chunk_signature, derive_chunk_otp, REWARD_SIGNING_CONTEXT};
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
    let (archived_segment_sender, archived_segment_receiver) = futures::channel::oneshot::channel();

    std::thread::spawn({
        move || {
            let archived_segment = get_archived_segment(client.as_ref());
            archived_segment_sender.send(archived_segment).unwrap();
        }
    });

    // TODO: This constant should come from the chain itself
    let space_l = NonZeroU16::new(20).unwrap();
    let chunks_in_sector = u64::from(RECORD_SIZE) * u64::from(u8::BITS) / u64::from(space_l.get());
    let archived_segment = archived_segment_receiver.await.unwrap();
    let total_pieces = NonZeroU64::new(archived_segment.pieces.count() as PieceIndex).unwrap();
    let sector_index = 0;

    let mut new_slot_notification_stream = new_slot_notification_stream.subscribe();

    while let Some(NewSlotNotification {
        new_slot_info,
        mut solution_sender,
    }) = new_slot_notification_stream.next().await
    {
        if u64::from(new_slot_info.slot) % 2 == 0 {
            let sector_id =
                SectorId::new(&PublicKey::from(keypair.public.to_bytes()), sector_index);
            let local_challenge = sector_id.derive_local_challenge(&new_slot_info.global_challenge);
            let audit_index: u64 = local_challenge % chunks_in_sector;
            let audit_piece_offset = (audit_index / u64::from(u8::BITS)) / PIECE_SIZE as u64;
            // Offset of the piece in sector (in bytes)
            let audit_piece_bytes_offset = audit_piece_offset * PIECE_SIZE as u64;
            // Audit index (chunk) within corresponding piece
            let audit_index_within_piece =
                audit_index - audit_piece_bytes_offset * u64::from(u8::BITS);
            let piece_index = sector_id.derive_piece_index(audit_piece_offset, total_pieces);
            let mut piece = Piece::try_from(
                archived_segment
                    .pieces
                    .as_pieces()
                    .nth(piece_index as usize)
                    .unwrap(),
            )
            .unwrap();
            // Encode piece
            let (record, witness_bytes) = piece.split_at_mut(RECORD_SIZE as usize);
            let piece_witness =
                Witness::try_from_bytes((&*witness_bytes).try_into().unwrap()).unwrap();
            let piece_record_hash = blake2b_256_254_hash(record);

            // TODO: Extract encoding into separate function reusable in
            //  farmer and otherwise
            record
                .view_bits_mut::<Lsb0>()
                .chunks_mut(space_l.get() as usize)
                .enumerate()
                .for_each(|(chunk_index, bits)| {
                    // Derive one-time pad
                    let mut otp = derive_chunk_otp(&sector_id, witness_bytes, chunk_index as u32);
                    // XOR chunk bit by bit with one-time pad
                    bits.iter_mut()
                        .zip(otp.view_bits_mut::<Lsb0>().iter())
                        .for_each(|(mut a, b)| {
                            *a ^= *b;
                        });
                });

            // TODO: We are skipping witness part of the piece or else it is not
            //  decodable
            let maybe_chunk = piece[..RECORD_SIZE as usize]
                .view_bits()
                .chunks_exact(space_l.get() as usize)
                .nth(audit_index_within_piece as usize);

            let chunk = match maybe_chunk {
                Some(chunk) => Chunk::from(chunk),
                None => {
                    // TODO: Record size is not multiple of `space_l`, last bits
                    //  were not encoded and should not be used for solving
                    continue;
                }
            };

            let chunk_signature = create_chunk_signature(&keypair, &chunk);

            let _ = solution_sender
                .send(Solution {
                    public_key: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
                    reward_address: FarmerPublicKey::unchecked_from(keypair.public.to_bytes()),
                    sector_index,
                    total_pieces,
                    piece_offset: audit_piece_offset,
                    piece_record_hash,
                    piece_witness,
                    chunk,
                    chunk_signature,
                })
                .await;
        }
    }
}

fn get_archived_segment<Client>(client: &Client) -> ArchivedSegment
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
        .next()
        .expect("First block is always producing one segment; qed")
}

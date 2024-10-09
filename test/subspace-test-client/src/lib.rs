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

#![warn(unused_crate_dependencies)]

pub mod auto_id_domain_chain_spec;
pub mod chain_spec;
pub mod evm_domain_chain_spec;

use futures::executor::block_on;
use futures::StreamExt;
use sc_client_api::{BlockBackend, HeaderBackend};
use sc_consensus_subspace::archiver::encode_block;
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::slot_worker::{NewSlotNotification, RewardSigningNotification};
use sp_api::ProvideRuntimeApi;
use sp_consensus_subspace::SubspaceApi;
use sp_core::{Decode, Encode};
use std::num::{NonZeroU64, NonZeroUsize};
use std::slice;
use std::sync::Arc;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::pieces::Record;
use subspace_core_primitives::pos::PosSeed;
use subspace_core_primitives::segments::{HistorySize, SegmentIndex};
use subspace_core_primitives::solutions::{RewardSignature, Solution};
use subspace_core_primitives::{PublicKey, REWARD_SIGNING_CONTEXT};
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::auditing::audit_sector_sync;
use subspace_farmer_components::plotting::{
    plot_sector, CpuRecordsEncoder, PlotSectorOptions, PlottedSector,
};
use subspace_farmer_components::reading::ReadSectorRecordChunksMode;
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_kzg::Kzg;
use subspace_proof_of_space::{Table, TableGenerator};
use subspace_runtime_primitives::opaque::Block;
use subspace_service::{FullClient, NewFull};
use zeroize::Zeroizing;

// Smaller value for testing purposes
const MAX_PIECES_IN_SECTOR: u16 = 32;

/// The client type being used by the test service.
pub type Client = FullClient<subspace_test_runtime::RuntimeApi>;

/// The backend type being used by the test service.
pub type Backend = sc_service::TFullBackend<Block>;

/// Run a farmer.
pub fn start_farmer<PosTable>(new_full: &NewFull<Client>)
where
    PosTable: Table,
{
    let client = new_full.client.clone();
    let new_slot_notification_stream = new_full.new_slot_notification_stream.clone();
    let reward_signing_notification_stream = new_full.reward_signing_notification_stream.clone();

    let keypair = schnorrkel::Keypair::generate();
    let subspace_farming =
        start_farming::<PosTable, _>(keypair.clone(), client, new_slot_notification_stream);
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
                signature_sender,
                ..
            }) = reward_signing_notification_stream.next().await
            {
                let header_hash: [u8; 32] = header_hash.into();
                let signature = RewardSignature::from(
                    signing_pair
                        .sign(substrate_ctx.bytes(&header_hash))
                        .to_bytes(),
                );
                signature_sender.unbounded_send(signature).unwrap();
            }
        });
}

async fn start_farming<PosTable, Client>(
    keypair: schnorrkel::Keypair,
    client: Arc<Client>,
    new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
) where
    PosTable: Table,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + Send
        + Sync
        + 'static,
    Client::Api: SubspaceApi<Block, PublicKey>,
{
    let (plotting_result_sender, plotting_result_receiver) = futures::channel::oneshot::channel();

    let kzg = Kzg::new();
    let erasure_coding = ErasureCoding::new(
        NonZeroUsize::new(Record::NUM_S_BUCKETS.next_power_of_two().ilog2() as usize)
            .expect("Not zero; qed"),
    )
    .unwrap();

    let table_generator = PosTable::generator();

    std::thread::spawn({
        let keypair = keypair.clone();
        let erasure_coding = erasure_coding.clone();

        move || {
            let (sector, sector_metadata, table_generator) =
                block_on(plot_one_segment::<PosTable, _>(
                    client.as_ref(),
                    &keypair,
                    MAX_PIECES_IN_SECTOR,
                    &erasure_coding,
                    table_generator,
                ));
            plotting_result_sender
                .send((sector, sector_metadata, table_generator))
                .unwrap();
        }
    });

    let (sector, plotted_sector, mut table_generator) = plotting_result_receiver.await.unwrap();
    let public_key = PublicKey::from(keypair.public.to_bytes());

    let mut new_slot_notification_stream = new_slot_notification_stream.subscribe();

    while let Some(NewSlotNotification {
        new_slot_info,
        mut solution_sender,
    }) = new_slot_notification_stream.next().await
    {
        if u64::from(new_slot_info.slot) % 2 == 0 {
            let global_challenge = new_slot_info
                .proof_of_time
                .derive_global_randomness()
                .derive_global_challenge(new_slot_info.slot.into());
            let audit_result = audit_sector_sync(
                &public_key,
                &global_challenge,
                new_slot_info.solution_range,
                &sector,
                &plotted_sector.sector_metadata,
            );

            let solution = audit_result
                .unwrap()
                .unwrap()
                .solution_candidates
                .into_solutions(
                    &public_key,
                    &kzg,
                    &erasure_coding,
                    ReadSectorRecordChunksMode::ConcurrentChunks,
                    |seed: &PosSeed| table_generator.generate_parallel(seed),
                )
                .unwrap()
                .next()
                .expect("With max solution range there must be a solution; qed")
                .unwrap();
            // Lazy conversion to a different type of public key and reward address
            let solution = Solution::decode(&mut solution.encode().as_slice()).unwrap();
            let _ = solution_sender.try_send(solution);
        }
    }
}

async fn plot_one_segment<PosTable, Client>(
    client: &Client,
    keypair: &schnorrkel::Keypair,
    pieces_in_sector: u16,
    erasure_coding: &ErasureCoding,
    mut table_generator: PosTable::Generator,
) -> (Vec<u8>, PlottedSector, PosTable::Generator)
where
    PosTable: Table,
    Client: BlockBackend<Block> + HeaderBackend<Block>,
{
    let kzg = Kzg::new();
    let mut archiver =
        subspace_archiving::archiver::Archiver::new(kzg.clone(), erasure_coding.clone());

    let genesis_block = client.block(client.info().genesis_hash).unwrap().unwrap();
    let archived_segment = archiver
        .add_block(
            encode_block(genesis_block),
            BlockObjectMapping::default(),
            true,
        )
        .archived_segments
        .into_iter()
        .next()
        .expect("First block is always producing one segment; qed");
    let history_size = HistorySize::from(SegmentIndex::ZERO);
    let mut sector = Vec::new();
    let sector_index = 0;
    let public_key = PublicKey::from(keypair.public.to_bytes());
    let farmer_protocol_info = FarmerProtocolInfo {
        history_size,
        max_pieces_in_sector: pieces_in_sector,
        recent_segments: HistorySize::from(NonZeroU64::new(5).unwrap()),
        recent_history_fraction: (
            HistorySize::from(NonZeroU64::new(1).unwrap()),
            HistorySize::from(NonZeroU64::new(10).unwrap()),
        ),
        min_sector_lifetime: HistorySize::from(NonZeroU64::new(4).unwrap()),
    };

    let plotted_sector = plot_sector(PlotSectorOptions {
        public_key: &public_key,
        sector_index,
        piece_getter: &archived_segment.pieces,
        farmer_protocol_info,
        kzg: &kzg,
        erasure_coding,
        pieces_in_sector,
        sector_output: &mut sector,
        downloading_semaphore: None,
        encoding_semaphore: None,
        records_encoder: &mut CpuRecordsEncoder::<PosTable>::new(
            slice::from_mut(&mut table_generator),
            erasure_coding,
            &Default::default(),
        ),
        abort_early: &Default::default(),
    })
    .await
    .expect("Plotting one sector in memory must not fail");

    (sector, plotted_sector, table_generator)
}

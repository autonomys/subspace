use crate::archiving::Archiving;
use crate::commitments::Commitments;
use crate::identity::Identity;
use crate::object_mappings::ObjectMappings;
use crate::plot::Plot;
use crate::rpc_client::mock_rpc_client::MockRpcClient;
use crate::rpc_client::RpcClient;
use crate::single_disk_farm::SingleDiskSemaphore;
use crate::single_plot_farm::SinglePlotPlotter;
use rand::prelude::*;
use rand::Rng;
use std::num::{NonZeroU16, NonZeroU32};
use std::sync::atomic::AtomicBool;
use subspace_archiving::archiver::Archiver;
use subspace_core_primitives::objects::BlockObjectMapping;
use subspace_core_primitives::{PieceIndexHash, Salt, PIECE_SIZE, SHA256_HASH_SIZE};
use subspace_rpc_primitives::FarmerProtocolInfo;
use subspace_solving::{create_tag, SubspaceCodec};
use tempfile::TempDir;
use tracing::error;

const MERKLE_NUM_LEAVES: usize = 8_usize;
const WITNESS_SIZE: usize = SHA256_HASH_SIZE * MERKLE_NUM_LEAVES.log2() as usize; // 96
const RECORD_SIZE: usize = PIECE_SIZE - WITNESS_SIZE; // 4000
const SEGMENT_SIZE: usize = RECORD_SIZE * MERKLE_NUM_LEAVES / 2; // 16000

fn init() {
    let _ = tracing_subscriber::fmt::try_init();
}

#[tokio::test(flavor = "multi_thread")]
async fn plotting_happy_path() {
    init();

    let base_directory = TempDir::new().unwrap();

    let identity =
        Identity::open_or_create(&base_directory).expect("Could not open/create identity!");

    let public_key = identity.public_key().to_bytes().into();
    let plot = Plot::open_or_create(
        &0usize.into(),
        base_directory.as_ref(),
        base_directory.as_ref(),
        public_key,
        u64::MAX,
    )
    .unwrap();
    let commitments = Commitments::new(base_directory.path().join("commitments")).unwrap();
    let object_mappings = ObjectMappings::open_or_create(
        &base_directory.as_ref().join("object-mappings"),
        public_key,
        u64::MAX,
    )
    .unwrap();

    let client = MockRpcClient::new();

    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();
    let farmer_protocol_info = FarmerProtocolInfo {
        genesis_hash: [0; 32],
        record_size: NonZeroU32::new(RECORD_SIZE as u32).unwrap(),
        recorded_history_segment_size: SEGMENT_SIZE as u32,
        max_plot_size: u64::MAX,
        total_pieces: 0,
    };

    client.send_farmer_protocol_info(farmer_protocol_info).await;

    let farmer_protocol_info = client
        .farmer_protocol_info()
        .await
        .expect("Could not retrieve farmer_protocol_info");

    let encoded_block0 = vec![0u8; SEGMENT_SIZE / 2];
    let encoded_block1 = vec![1u8; SEGMENT_SIZE / 2];
    let encoded_blocks = vec![encoded_block0, encoded_block1];

    // This test does not concern with the object mappings at the moment.
    for encoded_block in encoded_blocks.clone() {
        for archived_segment in archiver.add_block(encoded_block, Default::default()) {
            client.send_archived_segment(archived_segment).await;
        }
    }

    let subspace_codec = SubspaceCodec::new_with_gpu(identity.public_key().as_ref());

    let single_plot_plotter = SinglePlotPlotter::new(
        subspace_codec,
        plot.clone(),
        commitments,
        SingleDiskSemaphore::new(NonZeroU16::try_from(1).unwrap()),
    );

    // Start archiving task
    let archiving_instance = Archiving::start(
        farmer_protocol_info,
        vec![object_mappings],
        vec![],
        client.clone(),
        move |pieces_to_plot| match single_plot_plotter.plot_pieces(pieces_to_plot) {
            Ok(()) => true,
            Err(error) => {
                error!(%error, "Failed to plot pieces");
                false
            }
        },
    )
    .await
    .unwrap();

    // let the farmer know we are done by closing the channel(s)
    client.drop_archived_segment_sender().await;

    // wait for farmer to finish
    if let Err(e) = archiving_instance.wait().await {
        panic!("Panicked with error...{:?}", e);
    }

    assert!(!plot.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn plotting_piece_eviction() {
    init();

    let base_directory = TempDir::new().unwrap();

    // Mnemonic and random number generator and configured such that there pieces in the second
    // segment are plotted with some skipped in the middle of the segment due to plot being already,
    // as well as such that will not be skipped (will override existing) if their piece index
    // started with 0. This tests edge case where indexes of pieces in this case are handled
    // properly during piece replacement.
    let entropy = "7d202f848f8c59b98906d5cca6c1533279fcf4535f089611e7d0e44695a34d04";
    let identity = Identity::from_entropy(&base_directory, hex::decode(entropy).unwrap())
        .expect("Could not open/create identity!");
    let mut rng = StdRng::seed_from_u64(0);

    let public_key = identity.public_key().to_bytes().into();
    let salt = Salt::default();
    let plot = Plot::open_or_create(
        &0usize.into(),
        base_directory.as_ref(),
        base_directory.as_ref(),
        public_key,
        5 * PIECE_SIZE as u64,
    )
    .unwrap();
    let commitments = Commitments::new(base_directory.path().join("commitments")).unwrap();
    let object_mappings = ObjectMappings::open_or_create(
        &base_directory.as_ref().join("object-mappings"),
        public_key,
        u64::MAX,
    )
    .unwrap();

    // There are no pieces, but we need to create empty commitments database for this salt, such
    //  that plotter will create commitments for plotted pieces
    commitments
        .create(salt, plot.clone(), &AtomicBool::new(false))
        .unwrap();

    let client = MockRpcClient::new();

    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();
    let farmer_protocol_info = FarmerProtocolInfo {
        genesis_hash: [0; 32],
        record_size: NonZeroU32::new(RECORD_SIZE as u32).unwrap(),
        recorded_history_segment_size: SEGMENT_SIZE as u32,
        max_plot_size: u64::MAX,
        total_pieces: 0,
    };

    client.send_farmer_protocol_info(farmer_protocol_info).await;

    let farmer_protocol_info = client
        .farmer_protocol_info()
        .await
        .expect("Could not retrieve farmer_protocol_info");

    let encoded_block0 = {
        let mut block = vec![0u8; SEGMENT_SIZE];
        rng.fill(block.as_mut_slice());
        block
    };
    let encoded_block1 = {
        let mut block = vec![0u8; SEGMENT_SIZE];
        rng.fill(block.as_mut_slice());
        block
    };
    let encoded_blocks = vec![encoded_block0, encoded_block1];

    // This test does not concern with the object mappings at the moment.
    for encoded_block in encoded_blocks.clone() {
        for archived_segment in archiver.add_block(encoded_block, Default::default()) {
            client.send_archived_segment(archived_segment).await;
        }
    }

    let subspace_codec = SubspaceCodec::new_with_gpu(identity.public_key().as_ref());

    let single_plot_plotter = SinglePlotPlotter::new(
        subspace_codec.clone(),
        plot.clone(),
        commitments.clone(),
        SingleDiskSemaphore::new(NonZeroU16::try_from(1).unwrap()),
    );

    // Start archiving task
    let archiving_instance = Archiving::start(
        farmer_protocol_info,
        vec![object_mappings],
        vec![],
        client.clone(),
        move |pieces_to_plot| match single_plot_plotter.plot_pieces(pieces_to_plot) {
            Ok(()) => true,
            Err(error) => {
                error!(%error, "Failed to plot pieces");
                false
            }
        },
    )
    .await
    .unwrap();

    // let the farmer know we are done by closing the channel(s)
    client.drop_archived_segment_sender().await;

    // wait for farmer to finish
    if let Err(e) = archiving_instance.wait().await {
        panic!("Panicked with error...{:?}", e);
    }

    let mut archiver = Archiver::new(RECORD_SIZE, SEGMENT_SIZE).unwrap();

    for encoded_block in encoded_blocks {
        for archived_segment in archiver.add_block(encoded_block, BlockObjectMapping::default()) {
            for (piece, piece_index) in archived_segment
                .pieces
                .as_pieces()
                .zip(archived_segment.root_block.segment_index() * MERKLE_NUM_LEAVES as u64..)
            {
                // TODO: `read_piece` should have returned `Result<Option<T>, E>` instead, only
                //  allow `None` and not errors once that is the case
                if let Ok(mut read_piece) = plot.read_piece(PieceIndexHash::from_index(piece_index))
                {
                    let correct_tag = create_tag(&read_piece, salt);

                    subspace_codec.decode(&mut read_piece, piece_index).unwrap();

                    // Must be able to find correct tag in the database
                    assert!(!commitments
                        .find_by_range(correct_tag, u64::MIN, salt, 1)
                        .is_empty());

                    assert!(
                        read_piece.as_ref() == piece,
                        "Read incorrect piece for piece index {}",
                        piece_index
                    );
                }
            }
        }
    }
}

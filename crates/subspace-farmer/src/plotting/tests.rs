use crate::commitments::Commitments;
use crate::identity::Identity;
use crate::mock_rpc::MockRpc;
use crate::object_mappings::ObjectMappings;
use crate::plot::Plot;
use crate::plotting::{FarmerData, Plotting};
use crate::rpc::{NewHead, RpcClient};
use subspace_core_primitives::{PIECE_SIZE, SHA256_HASH_SIZE};
use subspace_rpc_primitives::{EncodedBlockWithObjectMapping, FarmerMetadata};
use subspace_solving::SubspaceCodec;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};

const MERKLE_NUM_LEAVES: usize = 8_usize;
const WITNESS_SIZE: usize = SHA256_HASH_SIZE * MERKLE_NUM_LEAVES.log2() as usize; // 96
const RECORD_SIZE: usize = PIECE_SIZE - WITNESS_SIZE; // 4000
const SEGMENT_SIZE: usize = RECORD_SIZE * MERKLE_NUM_LEAVES / 2; // 16000
const BEST_BLOCK_NUMBER_CHECK_INTERVAL: Duration = Duration::from_secs(5);

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[tokio::test(flavor = "multi_thread")]
async fn plotting_happy_path() {
    init();

    let base_directory = TempDir::new().unwrap();

    let identity =
        Identity::open_or_create(&base_directory).expect("Could not open/create identity!");

    let address = <&[u8; 32]>::try_from(identity.public_key().as_ref())
        .expect("Length of public key is always correct");
    let plot = Plot::open_or_create(&base_directory, (*address).into(), None).unwrap();
    let commitments = Commitments::new(base_directory.path().join("commitments")).unwrap();
    let object_mappings = ObjectMappings::open_or_create(&base_directory).unwrap();

    let client = MockRpc::new();

    let farmer_metadata = FarmerMetadata {
        confirmation_depth_k: 0,
        record_size: RECORD_SIZE as u32,
        recorded_history_segment_size: SEGMENT_SIZE as u32,
    };

    client.send_metadata(farmer_metadata).await;

    let farmer_metadata = client
        .farmer_metadata()
        .await
        .expect("Could not retrieve farmer_metadata");

    let subspace_codec = SubspaceCodec::new(identity.public_key());

    let farmer_data = FarmerData::new(plot.clone(), commitments, object_mappings, farmer_metadata);

    let encoded_block0 = EncodedBlockWithObjectMapping {
        block: vec![0u8; SEGMENT_SIZE / 2],
        object_mapping: Default::default(), // This test does not concern with the object mappings at the moment.
    };
    let encoded_block1 = EncodedBlockWithObjectMapping {
        block: vec![1u8; SEGMENT_SIZE / 2],
        object_mapping: Default::default(), // This test does not concern with the object mappings at the moment.
    };
    let encoded_blocks = vec![encoded_block0, encoded_block1];

    let new_head0 = NewHead {
        number: "0x0".to_string(),
    };
    let new_head1 = NewHead {
        number: "0x1".to_string(),
    };
    let new_heads = vec![new_head0, new_head1];

    let plotting_instance = Plotting::start(
        farmer_data,
        client.clone(),
        subspace_codec,
        BEST_BLOCK_NUMBER_CHECK_INTERVAL,
    );

    for (block, new_head) in encoded_blocks.into_iter().zip(new_heads) {
        let client_copy = client.clone();
        async move {
            // putting 250 milliseconds here to give plotter some time
            sleep(Duration::from_millis(250)).await;
            client_copy.send_block(block).await;
            client_copy.send_new_head(new_head).await;
            // putting 250 milliseconds here to give plotter some time
            sleep(Duration::from_millis(250)).await;
        }
        .await;
    }

    assert_eq!(
        plot.get_last_root_block().unwrap().unwrap().records_root(),
        [
            128, 88, 79, 62, 14, 50, 76, 101, 5, 140, 34, 124, 28, 140, 2, 80, 84, 108, 192, 253,
            210, 159, 59, 132, 116, 250, 177, 226, 192, 188, 79, 230
        ]
    );

    assert_eq!(
        plot.get_last_root_block().unwrap().unwrap().hash(),
        [
            229, 128, 200, 204, 79, 205, 9, 80, 237, 216, 133, 217, 228, 30, 8, 241, 142, 197, 74,
            127, 148, 245, 255, 254, 179, 108, 138, 16, 180, 92, 31, 140
        ]
    );

    assert_eq!(
        plot.get_last_root_block().unwrap().unwrap().segment_index(),
        0
    );
    assert_eq!(
        plot.get_last_root_block()
            .unwrap()
            .unwrap()
            .last_archived_block()
            .number,
        1
    );

    // let the farmer know we are done by closing the channel(s)
    client.drop_new_head_sender().await;

    // wait for farmer to finish
    if let Err(e) = plotting_instance.wait().await {
        panic!("Panicked with error...{:?}", e);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn plotting_continue() {
    // phase 1 - initial plotting
    init();

    let base_directory = TempDir::new().unwrap();
    let identity =
        Identity::open_or_create(&base_directory).expect("Could not open/create identity!");

    let address = <&[u8; 32]>::try_from(identity.public_key().as_ref())
        .expect("Length of public key is always correct");
    let plot = Plot::open_or_create(&base_directory, (*address).into(), None).unwrap();
    let commitments = Commitments::new(base_directory.path().join("commitments")).unwrap();
    let object_mappings = ObjectMappings::open_or_create(&base_directory).unwrap();

    let client = MockRpc::new();

    let farmer_metadata = FarmerMetadata {
        confirmation_depth_k: 0,
        record_size: RECORD_SIZE as u32,
        recorded_history_segment_size: SEGMENT_SIZE as u32,
    };

    client.send_metadata(farmer_metadata).await;

    let farmer_metadata = client
        .farmer_metadata()
        .await
        .expect("Could not retrieve farmer_metadata");

    let subspace_codec = SubspaceCodec::new(identity.public_key());

    let farmer_data = FarmerData::new(
        plot.clone(),
        commitments.clone(),
        object_mappings.clone(),
        farmer_metadata.clone(),
    );

    let encoded_block0 = EncodedBlockWithObjectMapping {
        block: vec![0u8; SEGMENT_SIZE / 2],
        object_mapping: Default::default(), // This test does not concern with the object mappings at the moment.
    };
    let encoded_block1 = EncodedBlockWithObjectMapping {
        block: vec![1u8; SEGMENT_SIZE / 2],
        object_mapping: Default::default(), // This test does not concern with the object mappings at the moment.
    };
    let encoded_blocks = vec![encoded_block0, encoded_block1];

    let new_head0 = NewHead {
        number: "0x0".to_string(),
    };
    let new_head1 = NewHead {
        number: "0x1".to_string(),
    };
    let new_heads = vec![new_head0, new_head1];

    let plotting_instance = Plotting::start(
        farmer_data,
        client.clone(),
        subspace_codec,
        BEST_BLOCK_NUMBER_CHECK_INTERVAL,
    );

    for (block, new_head) in encoded_blocks.into_iter().zip(new_heads) {
        let client_copy = client.clone();
        async move {
            // putting 250 milliseconds here to give plotter some time
            sleep(Duration::from_millis(250)).await;
            client_copy.send_block(block).await;
            client_copy.send_new_head(new_head).await;
            // putting 250 milliseconds here to give plotter some time
            sleep(Duration::from_millis(250)).await;
        }
        .await;
    }

    assert_eq!(
        plot.get_last_root_block().unwrap().unwrap().records_root(),
        [
            128, 88, 79, 62, 14, 50, 76, 101, 5, 140, 34, 124, 28, 140, 2, 80, 84, 108, 192, 253,
            210, 159, 59, 132, 116, 250, 177, 226, 192, 188, 79, 230
        ]
    );

    // let the farmer know we are done by closing the channel(s)
    client.drop_new_head_sender().await;

    // wait for farmer to finish
    if let Err(e) = plotting_instance.wait().await {
        panic!("Panicked with error...{:?}", e);
    }

    // phase 2 - continue with new blocks after dropping the old plotting
    let client = MockRpc::new();

    let farmer_data = FarmerData::new(
        plot.clone(),
        commitments.clone(),
        object_mappings.clone(),
        farmer_metadata.clone(),
    );

    // plotting will ask for the last encoded block to continue from where it's left off
    let prev_encoded_block = EncodedBlockWithObjectMapping {
        block: vec![1u8; SEGMENT_SIZE / 2],
        object_mapping: Default::default(), // This test does not concern with the object mappings at the moment.
    };
    let encoded_block0 = EncodedBlockWithObjectMapping {
        block: vec![2u8; SEGMENT_SIZE / 2],
        object_mapping: Default::default(), // This test does not concern with the object mappings at the moment.
    };
    let encoded_block1 = EncodedBlockWithObjectMapping {
        block: vec![3u8; SEGMENT_SIZE / 2],
        object_mapping: Default::default(), // This test does not concern with the object mappings at the moment.
    };

    let encoded_blocks = vec![encoded_block0, encoded_block1];

    let new_head0 = NewHead {
        number: "0x2".to_string(),
    };
    let new_head1 = NewHead {
        number: "0x3".to_string(),
    };
    let new_heads = vec![new_head0, new_head1];

    // plotter is continuing from where it's left off, and requires the last block again
    client.send_block(prev_encoded_block).await;
    // putting 250 milliseconds here to give plotter some time
    sleep(Duration::from_millis(250)).await;

    let plotting_instance = Plotting::start(
        farmer_data,
        client.clone(),
        subspace_codec,
        BEST_BLOCK_NUMBER_CHECK_INTERVAL,
    );

    for (block, new_head) in encoded_blocks.into_iter().zip(new_heads) {
        let client_copy = client.clone();
        async move {
            // putting 250 milliseconds here to give plotter some time
            sleep(Duration::from_millis(250)).await;
            client_copy.send_block(block).await;
            client_copy.send_new_head(new_head).await;
            // putting 250 milliseconds here to give plotter some time
            sleep(Duration::from_millis(250)).await;
        }
        .await;
    }

    assert_eq!(
        plot.get_last_root_block().unwrap().unwrap().records_root(),
        [
            203, 164, 66, 4, 2, 175, 85, 212, 86, 89, 88, 119, 67, 85, 197, 241, 56, 17, 47, 39,
            206, 10, 167, 83, 189, 125, 152, 1, 166, 145, 248, 238
        ]
    );

    assert_eq!(
        plot.get_last_root_block()
            .unwrap()
            .unwrap()
            .prev_root_block_hash(),
        [
            229, 128, 200, 204, 79, 205, 9, 80, 237, 216, 133, 217, 228, 30, 8, 241, 142, 197, 74,
            127, 148, 245, 255, 254, 179, 108, 138, 16, 180, 92, 31, 140
        ]
    );
    assert_eq!(
        plot.get_last_root_block().unwrap().unwrap().segment_index(),
        1
    );
    assert_eq!(
        plot.get_last_root_block().unwrap().unwrap().hash(),
        [
            239, 193, 131, 124, 194, 113, 154, 202, 239, 184, 106, 99, 247, 139, 25, 184, 152, 228,
            118, 194, 6, 0, 81, 139, 172, 178, 95, 121, 175, 99, 103, 115
        ]
    );

    // let the farmer know we are done by closing the channel(s)
    client.drop_new_head_sender().await;

    // wait for farmer to finish
    if let Err(e) = plotting_instance.wait().await {
        panic!("Panicked with error...{:?}", e);
    }
}

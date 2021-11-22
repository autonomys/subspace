use crate::commitments::Commitments;
use crate::farming::Farming;
use crate::identity::Identity;
use crate::mock_rpc::MockRpc;
use crate::plot::Plot;
use std::sync::Arc;
use subspace_core_primitives::{Piece, Salt, Tag, TAG_SIZE};
use subspace_rpc_primitives::SlotInfo;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

async fn farming_simulator(slots: Vec<SlotInfo>, tags: Vec<Tag>) {
    init();

    let base_directory = TempDir::new().unwrap();

    let piece: Piece = [9u8; 4096].into();
    let salt: Salt = slots[0].salt.clone(); // the first slots salt should be used for the initial commitments
    let index = 0;

    let plot = Plot::open_or_create(&base_directory).await.unwrap();
    let commitments = Commitments::new(base_directory.path().join("commitments").into())
        .await
        .unwrap();
    plot.write_many(Arc::new(vec![piece]), index).await.unwrap();
    commitments.create(salt, plot.clone()).await.unwrap();

    let identity;
    let res = Identity::open_or_create(&base_directory);
    match res {
        Ok(result) => identity = result,
        Err(_) => panic!("Identity fail!"),
    }

    let (_metadata_sender, metadata_recv) = mpsc::channel(10);
    let (_block_sender, block_recv) = mpsc::channel(10);
    let (_newhead_sender, newhead_recv) = mpsc::channel(10);
    let (slot_sender, slot_recv) = mpsc::channel(10);
    let (tag_sender, tag_recv) = mpsc::channel(10);

    let _ = slot_sender.send(slots[0].clone()).await; // send only the first slot, so that farmer can start
    for tag in tags {
        let _ = tag_sender.send(tag).await; // we can send all the correct tags to the MockRPC, will not create any racy behaviour
    }

    let client = MockRpc::new(metadata_recv, block_recv, newhead_recv, slot_recv, tag_recv);

    // start the farming task
    let farming_instance =
        Farming::start(plot.clone(), commitments.clone(), client, identity.clone());

    // if we have more than 1 slot, we will send the remaining with interleaving delays
    if slots.len() >= 2 {
        for slot in 1..slots.len() {
            sleep(Duration::from_millis(500)).await;
            let _ = slot_sender.send(slots[slot].clone()).await;
        }
    }

    if let Err(e) = farming_instance.wait().await {
        panic!("Panicked with error...{:?}", e);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn farming_happy_path() {
    let slot_info = SlotInfo {
        slot_number: 3,
        global_challenge: [1; TAG_SIZE],
        salt: [1, 1, 1, 1, 1, 1, 1, 1],
        next_salt: None,
        solution_range: u64::MAX,
    };
    let slots = vec![slot_info];

    let correct_tag: Tag = [23, 245, 162, 52, 107, 135, 192, 210];
    let tags = vec![correct_tag];

    farming_simulator(slots, tags).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn farming_salt_change() {
    let first_slot = SlotInfo {
        slot_number: 1,
        global_challenge: [1; TAG_SIZE],
        salt: [1, 1, 1, 1, 1, 1, 1, 1],
        next_salt: Some([1, 1, 1, 1, 1, 1, 1, 2]),
        solution_range: u64::MAX,
    };
    let second_slot = SlotInfo {
        slot_number: 2,
        global_challenge: [1; TAG_SIZE],
        salt: [1, 1, 1, 1, 1, 1, 1, 1],
        next_salt: Some([1, 1, 1, 1, 1, 1, 1, 2]),
        solution_range: u64::MAX,
    };
    let third_slot = SlotInfo {
        slot_number: 3,
        global_challenge: [1; TAG_SIZE],
        salt: [1, 1, 1, 1, 1, 1, 1, 2],
        next_salt: None,
        solution_range: u64::MAX,
    };
    let slots = vec![first_slot, second_slot, third_slot];

    let first_tag: Tag = [23, 245, 162, 52, 107, 135, 192, 210];
    let second_tag: Tag = [23, 245, 162, 52, 107, 135, 192, 210];
    let third_tag: Tag = [255, 69, 97, 5, 186, 24, 136, 245];
    let tags = vec![first_tag, second_tag, third_tag];

    farming_simulator(slots, tags).await;
}

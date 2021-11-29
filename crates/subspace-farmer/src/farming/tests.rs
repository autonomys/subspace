use crate::commitments::Commitments;
use crate::farming::Farming;
use crate::identity::Identity;
use crate::mock_rpc::MockRpc;
use crate::plot::Plot;
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, Salt, Tag, TAG_SIZE};
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

    let pieces: FlatPieces = vec![9u8; 4096].try_into().unwrap();
    let salt: Salt = slots[0].salt; // the first slots salt should be used for the initial commitments
    let index = 0;

    let plot = Plot::open_or_create(&base_directory).await.unwrap();

    let commitments = Commitments::new(base_directory.path().join("commitments").into())
        .await
        .unwrap();

    plot.write_many(Arc::new(pieces), index).await.unwrap();
    commitments.create(salt, plot.clone()).await.unwrap();

    let identity =
        Identity::open_or_create(&base_directory).expect("Could not open/create identity!");

    let (_metadata_sender, metadata_recv) = mpsc::channel(10);
    let (_block_sender, block_recv) = mpsc::channel(10);
    let (_new_head_sender, new_head_recv) = mpsc::channel(10);
    let (slot_sender, slot_recv) = mpsc::channel(10);
    let (solution_sender, mut solution_recv) = mpsc::channel(1);

    let client = MockRpc::new(
        metadata_recv,
        block_recv,
        new_head_recv,
        slot_recv,
        solution_sender,
    );

    // start the farming task
    let farming_instance =
        Farming::start(plot.clone(), commitments.clone(), client, identity.clone());

    // send only the first slot, so that farmer can start
    slot_sender.send(slots[0].clone()).await.unwrap();

    for index in 0..slots.len() - 1 {
        // race between receiving a solution, and waiting for 1 sec
        tokio::select! {
            Some(solution) = solution_recv.recv() => {
                if let Some(solution) = solution.maybe_solution {
                    if solution.tag != tags[index] {
                        panic!("Wrong Tag! The expected value was: {:?}", tags[index]);
                    }
                } else {
                    panic!("Solution was None!")
                }
            },
            _ = sleep(Duration::from_secs(1)) => {},
        }
        // commitment in the background cannot keep up with the speed, so putting a little delay in here
        // commitment usually takes around 0.002-0.003 second on my machine (M1 iMac), putting 100 microseconds here to be safe
        sleep(Duration::from_millis(100)).await;
        slot_sender.send(slots[index + 1].clone()).await.unwrap();
    }

    // let the farmer know we are done by closing the channels
    drop(slot_sender);

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

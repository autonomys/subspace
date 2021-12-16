use crate::commitments::{CommitmentStatusChange, Commitments};
use crate::farming::Farming;
use crate::identity::Identity;
use crate::mock_rpc::MockRpc;
use crate::plot::Plot;
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use subspace_core_primitives::{FlatPieces, Salt, Tag, TAG_SIZE};
use subspace_rpc_primitives::SlotInfo;
use tempfile::TempDir;
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

    let plot = Plot::open_or_create(&base_directory).unwrap();

    let commitments = Commitments::new(base_directory.path().join("commitments")).unwrap();

    plot.write_many(Arc::new(pieces), index).unwrap();
    commitments.create(salt, plot.clone()).unwrap();

    let identity =
        Identity::open_or_create(&base_directory).expect("Could not open/create identity!");

    let client = MockRpc::new();

    // start the farming task
    let farming_instance = Farming::start(
        plot.clone(),
        commitments.clone(),
        client.clone(),
        identity.clone(),
    );

    let mut counter = 0;
    let mut latest_salt = slots.first().unwrap().salt;
    for (slot, tag) in slots.into_iter().zip(tags) {
        counter += 1;

        let (commitment_created_sender, mut commitment_created_receiver) =
            mpsc::unbounded::<Salt>();

        let _handler = commitments.on_status_change(Arc::new(move |commitment_status_change| {
            if let CommitmentStatusChange::Created { salt } = commitment_status_change {
                let _ = futures::executor::block_on(commitment_created_sender.clone().send(*salt));
            }
        }));

        client.send_slot_info(slot.clone()).await;

        // if salt will change, wait for background recommitment to finish first
        if let Some(next_salt) = slot.next_salt {
            if next_salt != latest_salt {
                latest_salt = next_salt;
                assert_eq!(
                    latest_salt,
                    commitment_created_receiver.next().await.unwrap()
                );
            }
        }

        tokio::select! {
            Some(solution) = client.receive_solution() => {
                if let Some(solution) = solution.maybe_solution {
                    if solution.tag != tag {
                        panic!("Wrong Tag! The expected value was: {:?}", tag);
                    }
                } else {
                    panic!("Solution was None! For challenge #: {}", counter);
                }
            },
            _ = sleep(Duration::from_secs(1)) => { panic!("Something is taking too much time!"); },
        }
    }

    // let the farmer know we are done by closing the channel(s)
    client.drop_slot_sender().await;

    // wait for farmer to finish
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
        next_salt: Some([1, 1, 1, 1, 1, 1, 1, 2]),
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
        next_salt: Some([1, 1, 1, 1, 1, 1, 1, 2]),
        solution_range: u64::MAX,
    };
    let slots = vec![first_slot, second_slot, third_slot];

    let first_tag: Tag = [23, 245, 162, 52, 107, 135, 192, 210];
    let second_tag: Tag = [23, 245, 162, 52, 107, 135, 192, 210];
    let third_tag: Tag = [255, 69, 97, 5, 186, 24, 136, 245];
    let tags = vec![first_tag, second_tag, third_tag];

    farming_simulator(slots, tags).await;
}

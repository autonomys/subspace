use crate::plot::{Plot, WeakPlot};
use crate::{crypto, Salt, Tag, SIGNING_CONTEXT};
use futures::channel::oneshot;
use jsonrpsee::types::traits::{Client, SubscriptionClient};
use jsonrpsee::types::v2::params::JsonRpcParams;
use jsonrpsee::types::Subscription;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use log::{debug, error, info, trace, warn};
use ring::digest;
use schnorrkel::context::SigningContext;
use schnorrkel::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use std::{fs, io};
use subspace_archiving::archiver::{ArchivedSegment, BlockArchiver, ObjectArchiver};
use subspace_archiving::pre_genesis_data;
use subspace_codec::SubspaceCodec;

type SlotNumber = u64;

/// Metadata necessary for farmer operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FarmerMetadata {
    /// Depth `K` after which a block enters the recorded history (a global constant, as opposed
    /// to the client-dependent transaction confirmation depth `k`).
    pub confirmation_depth_k: u32,
    /// The size of data in one piece (in bytes).
    pub record_size: u32,
    /// Recorded history is encoded and plotted in segments of this size (in bytes).
    pub recorded_history_segment_size: u32,
    /// This constant defines the size (in bytes) of one pre-genesis object.
    pub pre_genesis_object_size: u32,
    /// This constant defines the number of a pre-genesis objects that will bootstrap the
    /// history.
    pub pre_genesis_object_count: u32,
    /// This constant defines the seed used for deriving pre-genesis objects that will bootstrap
    /// the history.
    pub pre_genesis_object_seed: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct Solution {
    public_key: [u8; 32],
    piece_index: u64,
    encoding: Vec<u8>,
    signature: Vec<u8>,
    tag: Tag,
}

/// Proposed proof of space consisting of solution and farmer's secret key for block signing
#[derive(Debug, Serialize)]
struct ProposedProofOfSpaceResponse {
    /// Slot number
    slot_number: SlotNumber,
    /// Solution (if present) from farmer's plot corresponding to slot number above
    solution: Option<Solution>,
    // Secret key, used for signing blocks on the client node
    secret_key: Vec<u8>,
}

/// Information about new slot that just arrived
#[derive(Debug, Deserialize)]
struct SlotInfo {
    /// Slot number
    slot_number: SlotNumber,
    /// Slot challenge
    challenge: [u8; 8],
    /// Salt
    salt: Salt,
    /// Salt for the next eon
    next_salt: Option<Salt>,
    /// Acceptable solution range
    solution_range: u64,
}

/// Start farming by using plot in specified path and connecting to WebSocket server at specified
/// address.
pub(crate) async fn farm(path: PathBuf, ws_server: &str) -> Result<(), anyhow::Error> {
    info!("Connecting to RPC server");
    let client = Arc::new(WsClientBuilder::default().build(ws_server).await?);

    let identity_file = path.join("identity.bin");
    let keypair = if identity_file.exists() {
        info!("Opening existing keypair");
        Keypair::from_bytes(&fs::read(identity_file)?).map_err(anyhow::Error::msg)?
    } else {
        info!("Generating new keypair");
        let keypair = Keypair::generate();
        fs::write(identity_file, keypair.to_bytes())?;
        keypair
    };
    let ctx = schnorrkel::context::signing_context(SIGNING_CONTEXT);

    let farmer_metadata = client
        .request("subspace_getFarmerMetadata", JsonRpcParams::NoParams)
        .await?;

    // TODO: This doesn't account for the fact that node can have a completely different history to
    //  what farmer expects
    info!("Opening plot");
    let plot = Plot::open_or_create(&path.into()).await?;

    tokio::spawn({
        // let client = Arc::clone(&client);
        let weak_plot = plot.downgrade();
        let public_key = keypair.public;

        async move {
            match background_plotting(/*&client, */ weak_plot, farmer_metadata, &public_key).await {
                Ok(()) => {
                    info!("Background plotting finished successfully");
                }
                Err(error) => {
                    error!("Background plotting error: {}", error);
                }
            }
        }
    });

    subscribe_to_slot_info(&client, &plot, &keypair, &ctx).await?;

    let (tx, rx) = oneshot::channel();

    let _handler = plot.on_close(move || {
        let _ = tx.send(());
    });

    drop(plot);

    rx.await?;

    Ok(())
}

/// Maintains plot in up to date state plotting new pieces as they are produced on the network.
async fn background_plotting(
    // client: &WsClient,
    weak_plot: WeakPlot,
    farmer_metadata: FarmerMetadata,
    public_key: &PublicKey,
) -> Result<(), anyhow::Error> {
    let FarmerMetadata {
        record_size,
        recorded_history_segment_size,
        pre_genesis_object_size,
        pre_genesis_object_count,
        pre_genesis_object_seed,
        ..
    } = farmer_metadata;

    // TODO: This assumes fixed size segments, which might not be the case
    let merkle_num_leaves = u64::from(recorded_history_segment_size / record_size * 2);

    let subspace_codec = SubspaceCodec::new(public_key);

    // TODO: This doesn't support continuation of the plotting
    // TODO: This doesn't support joining the network that already has non-genesis blocks
    let block_archiver_handle = tokio::task::spawn_blocking({
        let weak_plot = weak_plot.clone();

        move || -> Result<Option<BlockArchiver>, anyhow::Error> {
            let runtime_handle = tokio::runtime::Handle::current();
            let mut object_archiver =
                ObjectArchiver::new(record_size as usize, recorded_history_segment_size as usize)?;

            info!("Plotting pre-genesis objects");
            // These archived segments are a part of the public parameters of network setup
            for index in 0..pre_genesis_object_count {
                // Erasure coding in archiver is a CPU-intensive operation, but since we are doing this
                let archived_segments = object_archiver.add_object(&pre_genesis_data::from_seed(
                    &pre_genesis_object_seed,
                    index,
                    pre_genesis_object_size,
                ));

                for archived_segment in archived_segments {
                    let ArchivedSegment {
                        root_block,
                        mut pieces,
                    } = archived_segment;
                    let piece_index_offset = merkle_num_leaves * root_block.segment_index();

                    // TODO: Batch encoding
                    for (position, piece) in pieces.iter_mut().enumerate() {
                        subspace_codec.encode(piece_index_offset + position as u64, piece)?;
                    }

                    if let Some(plot) = weak_plot.upgrade() {
                        // TODO: There is no internal mapping between pieces and their indexes yet
                        // TODO: Then we might want to send indexes as a separate vector
                        runtime_handle.block_on(plot.write_many(pieces, piece_index_offset))?;
                    } else {
                        return Ok(None);
                    }
                }
            }

            info!("Finished plotting pre-genesis objects");

            Ok(Some(object_archiver.into_block_archiver()))
        }
    });

    let block_archiver = match block_archiver_handle.await?? {
        Some(block_archiver) => block_archiver,
        None => {
            // Plot was dropped, time to exit already
            return Ok(());
        }
    };

    // TODO: Use block archiver for ongoing plotting of post-genesis pieces
    drop(block_archiver);

    Ok(())
}

async fn subscribe_to_slot_info(
    client: &WsClient,
    plot: &Plot,
    keypair: &Keypair,
    ctx: &SigningContext,
) -> Result<(), anyhow::Error> {
    let public_key_hash = crypto::hash_public_key(&keypair.public);

    info!("Subscribing to slot info notifications");
    let mut sub: Subscription<SlotInfo> = client
        .subscribe(
            "poc_subscribeSlotInfo",
            JsonRpcParams::NoParams,
            "poc_unsubscribeSlotInfo",
        )
        .await?;

    let mut salts = Salts::default();

    while let Some(slot_info) = sub.next().await? {
        debug!("New slot: {:?}", slot_info);

        update_commitments(plot, &mut salts, &slot_info).await?;

        let local_challenge = derive_local_challenge(&slot_info.challenge, &public_key_hash);

        let solution = match plot
            .find_by_range(local_challenge, slot_info.solution_range, slot_info.salt)
            .await?
        {
            Some((tag, piece_index)) => {
                let encoding = plot.read(piece_index).await?;
                let solution = Solution {
                    public_key: keypair.public.to_bytes(),
                    piece_index,
                    encoding: encoding.to_vec(),
                    signature: keypair.sign(ctx.bytes(&tag)).to_bytes().to_vec(),
                    tag,
                };

                debug!("Solution found");
                trace!("Solution found: {:?}", solution);

                Some(solution)
            }
            None => {
                debug!("Solution not found");
                None
            }
        };

        client
            .request(
                "poc_proposeProofOfSpace",
                JsonRpcParams::Array(vec![serde_json::to_value(&ProposedProofOfSpaceResponse {
                    slot_number: slot_info.slot_number,
                    solution,
                    secret_key: keypair.secret.to_bytes().into(),
                })
                .unwrap()]),
            )
            .await?;
    }

    Ok(())
}

#[derive(Default)]
struct Salts {
    current: Option<Salt>,
    next: Option<Salt>,
}

/// Compare salts in `slot_info` to those known from `salts` and start update plot commitments
/// accordingly if necessary
async fn update_commitments(
    plot: &Plot,
    salts: &mut Salts,
    slot_info: &SlotInfo,
) -> io::Result<()> {
    if salts.current.is_none() {
        let mut salts = vec![slot_info.salt];
        if let Some(salt) = slot_info.next_salt {
            salts.push(salt);
        }
        plot.retain_commitments(salts).await?;
    }

    // Check if current salt has changed
    if salts.current != Some(slot_info.salt) {
        // If previous `salts.next` is the same as current (expected behavior) remove old commitment
        if salts.next == Some(slot_info.salt) {
            let old_salt = salts.current.replace(slot_info.salt);
            if let Some(old_salt) = old_salt {
                info!(
                    "Salt {} is out of date, removing commitment",
                    hex::encode(old_salt)
                );

                tokio::spawn({
                    let plot = plot.clone();

                    async move {
                        if let Err(error) = plot.remove_commitment(old_salt).await {
                            error!(
                                "Failed to remove old commitment for {}: {}",
                                hex::encode(old_salt),
                                error
                            );
                        }
                    }
                });
            }
        } else {
            // `salts.next` is not the same as new salt, need to re-commit
            tokio::spawn({
                let salt = slot_info.salt;
                let plot = plot.clone();

                async move {
                    let started = Instant::now();
                    info!(
                        "Salt updated to {}, recommitting in background",
                        hex::encode(salt)
                    );

                    if let Err(error) = plot.create_commitment(salt).await {
                        error!(
                            "Failed to create commitment for {}: {}",
                            hex::encode(salt),
                            error
                        );
                    } else {
                        info!(
                            "Finished recommitment for {} in {} seconds",
                            hex::encode(salt),
                            started.elapsed().as_secs_f32()
                        );
                    }
                }
            });

            let old_salt = salts.current.replace(slot_info.salt);
            if let Some(old_salt) = old_salt {
                warn!(
                    "New salt {} is not the same as previously known next salt {:?}",
                    hex::encode(slot_info.salt),
                    salts.next.map(hex::encode)
                );
                info!(
                    "Salt {} is out of date, removing commitment",
                    hex::encode(old_salt)
                );

                tokio::spawn({
                    let plot = plot.clone();

                    async move {
                        if let Err(error) = plot.remove_commitment(old_salt).await {
                            error!(
                                "Failed to remove old commitment for {}: {}",
                                hex::encode(old_salt),
                                error
                            );
                        }
                    }
                });
            }
        }
    }

    if let Some(new_next_salt) = slot_info.next_salt {
        if Some(new_next_salt) != salts.next {
            let old_salt = salts.next.replace(new_next_salt);
            if old_salt != salts.current {
                if let Some(old_salt) = old_salt {
                    warn!(
                        "Previous next salt {} is out of date (current is {:?}), \
                            removing commitment",
                        hex::encode(old_salt),
                        salts.current.map(hex::encode)
                    );

                    tokio::spawn({
                        let plot = plot.clone();

                        async move {
                            if let Err(error) = plot.remove_commitment(old_salt).await {
                                error!(
                                    "Failed to remove old commitment for {}: {}",
                                    hex::encode(old_salt),
                                    error
                                );
                            }
                        }
                    });
                }
            }

            tokio::spawn({
                let plot = plot.clone();

                async move {
                    let started = Instant::now();
                    info!(
                        "Salt will update to {} soon, recommitting in background",
                        hex::encode(new_next_salt)
                    );
                    if let Err(error) = plot.create_commitment(new_next_salt).await {
                        error!(
                            "Recommitting salt in background failed for {}: {}",
                            hex::encode(new_next_salt),
                            error
                        );
                        return;
                    }
                    info!(
                        "Finished recommitment in background for {} in {} seconds",
                        hex::encode(new_next_salt),
                        started.elapsed().as_secs_f32()
                    );
                }
            });
        }
    }

    Ok(())
}

fn derive_local_challenge(global_challenge: &[u8], farmer_id: &[u8]) -> [u8; 8] {
    digest::digest(&digest::SHA256, &{
        let mut data = Vec::with_capacity(global_challenge.len() + farmer_id.len());
        data.extend_from_slice(global_challenge);
        data.extend_from_slice(farmer_id);
        data
    })
    .as_ref()[..8]
        .try_into()
        .unwrap()
}

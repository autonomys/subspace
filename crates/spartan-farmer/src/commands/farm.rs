use crate::commitments::Commitments;
use crate::plot::Plot;
use crate::{crypto, Salt, Tag, SIGNING_CONTEXT};
use anyhow::{anyhow, Result};
use futures::future;
use futures::future::Either;
use jsonrpsee::types::traits::{Client, SubscriptionClient};
use jsonrpsee::types::v2::params::JsonRpcParams;
use jsonrpsee::types::Subscription;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use log::{debug, error, info, trace};
use ring::digest;
use schnorrkel::context::SigningContext;
use schnorrkel::{Keypair, PublicKey};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use subspace_archiving::archiver::{ArchivedSegment, BlockArchiver, ObjectArchiver};
use subspace_archiving::pre_genesis_data;
use subspace_codec::SubspaceCodec;

type SlotNumber = u64;

/// Metadata necessary for farmer operation
#[derive(Debug, Deserialize)]
struct FarmerMetadata {
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

// There are more fields in this struct, but we only care about one
#[derive(Debug, Deserialize)]
struct NewHead {
    number: String,
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
pub(crate) async fn farm(base_directory: PathBuf, ws_server: &str) -> Result<()> {
    info!("Connecting to RPC server");
    let client = Arc::new(WsClientBuilder::default().build(ws_server).await?);

    let identity_file = base_directory.join("identity.bin");
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

    // TODO: This doesn't account for the fact that node can have a completely different history to
    //  what farmer expects
    info!("Opening plot");
    let plot = Plot::open_or_create(&base_directory.clone().into()).await?;
    info!("Opening commitments");
    let commitments = Commitments::new(base_directory.join("commitments").into()).await?;

    match future::select(
        {
            let client = Arc::clone(&client);
            let plot = plot.clone();
            let commitments = commitments.clone();
            let public_key = keypair.public;

            Box::pin(
                async move { background_plotting(client, plot, commitments, &public_key).await },
            )
        },
        Box::pin(async move {
            subscribe_to_slot_info(&client, &plot, &commitments, &keypair, &ctx).await
        }),
    )
    .await
    {
        Either::Left((result, _)) => match result {
            Ok(()) => {
                info!("Background plotting finished successfully");

                Ok(())
            }
            Err(error) => Err(anyhow!("Background plotting error: {}", error)),
        },
        Either::Right((result, _)) => result.map_err(Into::into),
    }
}

// TODO: Blocks that are coming form substrate node are fully trusted right now, which we probably
//  don't want eventually
/// Maintains plot in up to date state plotting new pieces as they are produced on the network.
async fn background_plotting(
    client: Arc<WsClient>,
    plot: Plot,
    commitments: Commitments,
    public_key: &PublicKey,
) -> Result<()> {
    let weak_plot = plot.downgrade();
    let FarmerMetadata {
        confirmation_depth_k,
        record_size,
        recorded_history_segment_size,
        pre_genesis_object_size,
        pre_genesis_object_count,
        pre_genesis_object_seed,
    } = client
        .request("subspace_getFarmerMetadata", JsonRpcParams::NoParams)
        .await?;

    // TODO: This assumes fixed size segments, which might not be the case
    let merkle_num_leaves = u64::from(recorded_history_segment_size / record_size * 2);

    let subspace_codec = SubspaceCodec::new(public_key);

    let mut archiver = if let Some(last_root_block) = plot.get_last_root_block().await? {
        // Continuing from existing initial state
        if plot.is_empty() {
            return Err(anyhow!("Plot is empty on restart, can't continue",));
        }

        drop(plot);

        let last_archived_block_number = last_root_block.last_archived_block().number;
        info!("Last archived block {}", last_archived_block_number);

        let maybe_last_archived_block: Option<Vec<u8>> = client
            .request(
                "subspace_getEncodedBlockByNumber",
                JsonRpcParams::Array(vec![serde_json::to_value(last_archived_block_number)?]),
            )
            .await?;
        let last_archived_block = match maybe_last_archived_block {
            Some(block) => block,
            None => {
                return Err(anyhow!(
                    "Failed to get block {} from the chain, probably need to erase existing plot",
                    last_archived_block_number
                ));
            }
        };

        BlockArchiver::with_initial_state(
            record_size as usize,
            recorded_history_segment_size as usize,
            last_root_block,
            &last_archived_block,
        )?
    } else {
        // Starting from genesis
        if !plot.is_empty() {
            // Restart before first block was archived, erase the plot
            // TODO: Erase plot
        }

        drop(plot);

        let mut object_archiver =
            ObjectArchiver::new(record_size as usize, recorded_history_segment_size as usize)?;

        // Erasure coding in archiver and piece encoding are a CPU-intensive operations
        let maybe_block_archiver_handle = tokio::task::spawn_blocking({
            let weak_plot = weak_plot.clone();
            let commitments = commitments.clone();
            let subspace_codec = subspace_codec.clone();

            move || -> Result<Option<BlockArchiver>, anyhow::Error> {
                let runtime_handle = tokio::runtime::Handle::current();
                info!("Plotting pre-genesis objects");

                // These archived segments are a part of the public parameters of network setup
                for index in 0..pre_genesis_object_count {
                    let archived_segments =
                        object_archiver.add_object(pre_genesis_data::from_seed(
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
                            if let Err(error) =
                                subspace_codec.encode(piece_index_offset + position as u64, piece)
                            {
                                error!("Failed to encode a piece: error: {}", error);
                                continue;
                            }
                        }

                        if let Some(plot) = weak_plot.upgrade() {
                            let pieces = Arc::new(pieces);
                            // TODO: There is no internal mapping between pieces and their indexes yet
                            // TODO: Then we might want to send indexes as a separate vector
                            runtime_handle.block_on(
                                plot.write_many(Arc::clone(&pieces), piece_index_offset),
                            )?;
                            runtime_handle.block_on(
                                commitments.create_for_pieces(pieces, piece_index_offset),
                            )?;
                            info!(
                                "Archived segment {} at object {}",
                                root_block.segment_index(),
                                index
                            );
                        } else {
                            return Ok(None);
                        }
                    }
                }

                info!("Finished plotting pre-genesis objects");

                Ok(Some(object_archiver.into_block_archiver()))
            }
        });

        match maybe_block_archiver_handle.await?? {
            Some(block_archiver) => block_archiver,
            None => {
                // Plot was dropped, time to exit already
                return Ok(());
            }
        }
    };

    let (new_block_to_archive_sender, new_block_to_archive_receiver) =
        std::sync::mpsc::sync_channel::<Arc<AtomicU32>>(0);
    // Process blocks since last fully archived block (or genesis) up to the current head minus K
    let mut blocks_to_archive_from = archiver
        .last_archived_block_number()
        .map(|n| n + 1)
        .unwrap_or_default();

    // Erasure coding in archiver and piece encoding are a CPU-intensive operations
    tokio::task::spawn_blocking({
        let client = Arc::clone(&client);
        let weak_plot = weak_plot.clone();

        #[allow(clippy::mut_range_bound)]
        move || {
            let runtime_handle = tokio::runtime::Handle::current();
            info!("Plotting new blocks in the background");

            'outer: while let Ok(blocks_to_archive_to) = new_block_to_archive_receiver.recv() {
                let blocks_to_archive_to = blocks_to_archive_to.load(Ordering::Relaxed);
                if blocks_to_archive_to >= blocks_to_archive_from {
                    debug!(
                        "Archiving blocks {}..={}",
                        blocks_to_archive_from, blocks_to_archive_to,
                    );
                }

                let mut last_root_block = None;
                for block_to_archive in blocks_to_archive_from..=blocks_to_archive_to {
                    let block_fut = client.request::<'_, '_, '_, Option<Vec<u8>>>(
                        "subspace_getEncodedBlockByNumber",
                        JsonRpcParams::Array(vec![serde_json::to_value(block_to_archive).unwrap()]),
                    );
                    let block = match runtime_handle.block_on(block_fut) {
                        Ok(Some(block)) => block,
                        Ok(None) => {
                            error!(
                                "Failed to get block #{} from RPC: Block not found",
                                block_to_archive,
                            );

                            blocks_to_archive_from = block_to_archive;
                            continue 'outer;
                        }
                        Err(error) => {
                            error!(
                                "Failed to get block #{} from RPC: {}",
                                block_to_archive, error,
                            );

                            blocks_to_archive_from = block_to_archive;
                            continue 'outer;
                        }
                    };

                    for archived_segment in archiver.add_block(block) {
                        let ArchivedSegment {
                            root_block,
                            mut pieces,
                        } = archived_segment;
                        let piece_index_offset = merkle_num_leaves * root_block.segment_index();

                        // TODO: Batch encoding
                        for (position, piece) in pieces.iter_mut().enumerate() {
                            if let Err(error) =
                                subspace_codec.encode(piece_index_offset + position as u64, piece)
                            {
                                error!("Failed to encode a piece: error: {}", error);
                                continue;
                            }
                        }

                        if let Some(plot) = weak_plot.upgrade() {
                            let pieces = Arc::new(pieces);
                            // TODO: There is no internal mapping between pieces and their indexes yet
                            // TODO: Then we might want to send indexes as a separate vector
                            if let Err(error) = runtime_handle
                                .block_on(plot.write_many(Arc::clone(&pieces), piece_index_offset))
                            {
                                error!("Failed to write encoded pieces: {}", error);
                            }
                            if let Err(error) = runtime_handle
                                .block_on(commitments.create_for_pieces(pieces, piece_index_offset))
                            {
                                error!("Failed to create commitments for pieces: {}", error);
                            }

                            let segment_index = root_block.segment_index();
                            last_root_block.replace(root_block);

                            info!(
                                "Archived segment {} at block {}",
                                segment_index, block_to_archive
                            );
                        }
                    }
                }

                if let Some(last_root_block) = last_root_block {
                    if let Some(plot) = weak_plot.upgrade() {
                        if let Err(error) =
                            runtime_handle.block_on(plot.set_last_root_block(&last_root_block))
                        {
                            error!("Failed to store last root block: {:?}", error);
                        }
                    }
                }

                blocks_to_archive_from = blocks_to_archive_to + 1;
            }
        }
    });

    info!("Subscribing to new heads notifications");

    let mut subscription: Subscription<NewHead> = client
        .subscribe(
            "chain_subscribeNewHead",
            JsonRpcParams::NoParams,
            "chain_unsubscribeNewHead",
        )
        .await?;

    let block_to_archive = Arc::new(AtomicU32::default());
    // Listen for new blocks produced on the network
    while let Some(new_head) = subscription.next().await? {
        // Numbers are in the format `0xabcd`, so strip `0x` prefix and interpret the rest as an
        // integer in hex
        let block_number = u32::from_str_radix(&new_head.number[2..], 16).unwrap();
        debug!("Last block number: {:#?}", block_number);

        if let Some(block) = block_number.checked_sub(confirmation_depth_k) {
            // We send block that should be archived over channel that doesn't have a buffer, atomic
            // integer is used to make sure archiving process always read up to date value
            block_to_archive.store(block, Ordering::Relaxed);
            let _ = new_block_to_archive_sender.try_send(Arc::clone(&block_to_archive));
        }
    }

    Ok(())
}

async fn subscribe_to_slot_info(
    client: &WsClient,
    plot: &Plot,
    commitments: &Commitments,
    keypair: &Keypair,
    ctx: &SigningContext,
) -> Result<()> {
    let public_key_hash = crypto::hash_public_key(&keypair.public);

    info!("Subscribing to slot info notifications");
    let mut subscription: Subscription<SlotInfo> = client
        .subscribe(
            "poc_subscribeSlotInfo",
            JsonRpcParams::NoParams,
            "poc_unsubscribeSlotInfo",
        )
        .await?;

    let mut salts = Salts::default();

    while let Some(slot_info) = subscription.next().await? {
        debug!("New slot: {:?}", slot_info);

        update_commitments(plot, commitments, &mut salts, &slot_info);

        let local_challenge = derive_local_challenge(&slot_info.challenge, &public_key_hash);

        let solution = match commitments
            .find_by_range(local_challenge, slot_info.solution_range, slot_info.salt)
            .await
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
                })?]),
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
/// accordingly if necessary (in background)
fn update_commitments(
    plot: &Plot,
    commitments: &Commitments,
    salts: &mut Salts,
    slot_info: &SlotInfo,
) {
    // Check if current salt has changed
    if salts.current != Some(slot_info.salt) {
        salts.current.replace(slot_info.salt);

        if salts.next != Some(slot_info.salt) {
            // If previous `salts.next` is the same as current (expected behavior), need to re-commit

            tokio::spawn({
                let salt = slot_info.salt;
                let plot = plot.clone();
                let commitments = commitments.clone();

                async move {
                    let started = Instant::now();
                    info!(
                        "Salt updated to {}, recommitting in background",
                        hex::encode(salt)
                    );

                    if let Err(error) = commitments.create(salt, plot).await {
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
        }
    }

    if let Some(new_next_salt) = slot_info.next_salt {
        if salts.next != Some(new_next_salt) {
            salts.next.replace(new_next_salt);

            tokio::spawn({
                let plot = plot.clone();
                let commitments = commitments.clone();

                async move {
                    let started = Instant::now();
                    info!(
                        "Salt will update to {} soon, recommitting in background",
                        hex::encode(new_next_salt)
                    );
                    if let Err(error) = commitments.create(new_next_salt, plot).await {
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

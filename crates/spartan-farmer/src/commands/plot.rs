use crate::plot::Plot;
use crate::{crypto, Piece, BATCH_SIZE, CUDA_BATCH_SIZE, PIECE_SIZE};
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use indicatif::ProgressBar;
use log::{info, warn};
use rayon::prelude::*;
use schnorrkel::Keypair;
use std::convert::TryInto;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use subspace_codec::Spartan;

/// Create a new plot with specified genesis piece and piece count.
pub(crate) async fn plot(
    path: PathBuf,
    genesis_piece: Piece,
    piece_count: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity_file = path.join("identity.bin");
    let keypair = if identity_file.exists() {
        info!("Opening existing keypair");
        Keypair::from_bytes(&fs::read(identity_file)?).map_err(|error| error.to_string())?
    } else {
        info!("Generating new keypair");
        let keypair = Keypair::generate();
        fs::write(identity_file, keypair.to_bytes())?;
        keypair
    };

    let plot = Plot::open_or_create(&path.into()).await?;
    let public_key_hash = crypto::hash_public_key(&keypair.public);
    let spartan = Spartan::new();

    if plot.is_empty().await {
        let plotting_fut = {
            let plot = plot.clone();

            async move {
                let (mut batch_sender, mut batch_receiver) = mpsc::channel(1);

                std::thread::spawn(move || {
                    let bar = ProgressBar::new(piece_count);

                    if spartan.is_cuda_available() {
                        info!("Using the GPU for plotting!");

                        let mut piece_array: Vec<u8> =
                            Vec::with_capacity(PIECE_SIZE * piece_count as usize);
                        for _ in 0..piece_count {
                            piece_array.extend_from_slice(&genesis_piece);
                        }
                        let nonce_array: Vec<u64> = (0..piece_count).collect();
                        for batch_start in (0..piece_count).step_by(CUDA_BATCH_SIZE as usize) {
                            let batch_end =
                                (batch_start + CUDA_BATCH_SIZE).min(piece_count) as usize;

                            spartan.cuda_batch_encode(
                                &mut piece_array
                                    [(batch_start as usize) * PIECE_SIZE..batch_end * PIECE_SIZE],
                                public_key_hash,
                                &nonce_array[(batch_start as usize)..batch_end],
                            );
                            bar.inc(CUDA_BATCH_SIZE);

                            let encoded_piece = piece_array
                                [(batch_start as usize) * PIECE_SIZE..batch_end * PIECE_SIZE]
                                .to_vec();

                            let piece_vec = encoded_piece
                                .chunks_exact(PIECE_SIZE)
                                .map(|x| x.try_into().unwrap())
                                .collect::<Vec<Piece>>();

                            if futures::executor::block_on(
                                batch_sender.send((batch_start, piece_vec)),
                            )
                            .is_err()
                            {
                                return;
                            }
                        }
                    } else {
                        info!("Using only CPU for plotting!");
                        for batch_start in (0..piece_count).step_by(BATCH_SIZE as usize) {
                            let batch_end = (batch_start + BATCH_SIZE).min(piece_count);
                            let encoded_batch: Vec<Piece> = (batch_start..batch_end)
                                .into_par_iter()
                                .map(|index| {
                                    let encoding = spartan.encode(public_key_hash, index);

                                    bar.inc(1);

                                    encoding
                                })
                                .collect();

                            if futures::executor::block_on(
                                batch_sender.send((batch_start, encoded_batch)),
                            )
                            .is_err()
                            {
                                return;
                            }
                        }
                    }

                    bar.finish();
                });
                while let Some((batch_start, encoded_batch)) = batch_receiver.next().await {
                    let result = plot.write_many(encoded_batch, batch_start).await;

                    if let Err(error) = result {
                        warn!("{}", error);
                    }
                }
            }
        };

        let plot_time = Instant::now();

        info!("Slowly plotting {} pieces...", piece_count);

        info!(
            r#"
          `""==,,__
            `"==..__"=..__ _    _..-==""_
                 .-,`"=/ /\ \""/_)==""``
                ( (    | | | \/ |
                 \ '.  |  \;  \ /
                  |  \ |   |   ||
             ,-._.'  |_|   |   ||
            .\_/\     -'   ;   Y
           |  `  |        /    |-.
           '. __/_    _.-'     /'
                  `'-.._____.-'
        "#
        );

        plotting_fut.await;

        let (tx, rx) = oneshot::channel();

        let _handler = plot.on_close(move || {
            let _ = tx.send(());
        });

        drop(plot);

        info!("Finishing writing to disk...");

        rx.await?;

        let total_plot_time = plot_time.elapsed();
        let average_plot_time =
            (total_plot_time.as_nanos() / piece_count as u128) as f32 / (1000f32 * 1000f32);

        info!("Average plot time is {:.3} ms per piece", average_plot_time);

        info!(
            "Total plot time is {:.3} minutes",
            total_plot_time.as_secs_f32() / 60f32
        );

        info!(
            "Plotting throughput is {} MB/sec\n",
            ((piece_count as u64 * PIECE_SIZE as u64) / (1000 * 1000)) as f32
                / (total_plot_time.as_secs_f32())
        );
    } else {
        info!("Using existing plot...");
        info!("NOTE: Use erase-plot command if you want to re-plot before running plot again.");

        let (tx, rx) = oneshot::channel();

        let _handler = plot.on_close(move || {
            let _ = tx.send(());
        });

        drop(plot);

        rx.await?;
    }

    Ok(())
}

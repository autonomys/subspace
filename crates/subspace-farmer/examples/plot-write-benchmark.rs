use std::{path::PathBuf, sync::Arc};

use clap::{Parser, ValueHint};
use rand::prelude::*;
use subspace_core_primitives::PIECE_SIZE;
use subspace_farmer::Plot;

#[derive(Debug, Parser)]
struct Args {
    /// Number of pieces in a batch
    #[clap(short, long, default_value = "4096")]
    batch_size: u64,
    /// Number of pieces to write
    #[clap(short, long, default_value = "262144")]
    piece_count: u64,

    #[clap(value_hint = ValueHint::DirPath)]
    base_directory: PathBuf,
}

#[tokio::main]
async fn main() {
    let Args {
        batch_size,
        piece_count,
        base_directory,
    } = Args::parse();

    let mut pieces = Vec::with_capacity(batch_size as usize * PIECE_SIZE);
    pieces.resize(batch_size as usize * PIECE_SIZE, 0u8);
    rand::thread_rng().fill(&mut pieces[..]);
    let pieces = Arc::new(pieces.try_into().unwrap());

    let plot = Plot::open_or_create(&base_directory).unwrap();

    let start = std::time::Instant::now();

    for index in (0..piece_count / batch_size).map(|i| i * batch_size) {
        plot.write_many(Arc::clone(&pieces), index as u64).unwrap();
    }
    drop(plot);

    let took = start.elapsed();
    let write_size = piece_count * PIECE_SIZE as u64 / 1024 / 1024;
    eprintln!(
        "Writing {write_size}M to disk took {took:?}. Speed is around {:.2} M/s",
        write_size as f64 / took.as_secs_f64()
    );
}

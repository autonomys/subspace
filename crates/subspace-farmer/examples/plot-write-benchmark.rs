use std::{path::PathBuf, sync::Arc};

use clap::{Parser, ValueHint};
use rand::prelude::*;
use subspace_core_primitives::PIECE_SIZE;
use subspace_farmer::Plot;

#[derive(Debug, Parser)]
struct Args {
    /// In megabytes
    #[clap(short, long, default_value = "8")]
    buffer_size: u64,
    /// In megabytes
    #[clap(short, long, default_value = "1024")]
    write_size: u64,

    #[clap(value_hint = ValueHint::DirPath)]
    base_directory: PathBuf,
}

// $ dd if=/dev/zero of=/home/i1i1/tmp/zeros bs=100M count=80
// 8388608000 bytes (8.4 GB, 7.8 GiB) copied, 25.4853 s, 329 MB/s
//
// Writing 8000M to disk took 5.893584945s. Speed is around 1357.4081097765531 M/s
#[tokio::main]
async fn main() {
    let Args {
        buffer_size,
        write_size,
        base_directory,
    } = Args::parse();

    let npieces = buffer_size * 1024 * 1024 / PIECE_SIZE as u64;
    let mut pieces = Vec::with_capacity(npieces as usize * PIECE_SIZE);
    pieces.resize(npieces as usize * PIECE_SIZE, 0u8);
    rand::thread_rng().fill(&mut pieces[..]);
    let pieces = Arc::new(pieces.try_into().unwrap());

    let plot = Plot::open_or_create(&base_directory).unwrap();

    let start = std::time::Instant::now();

    for index in (0..write_size / buffer_size).map(|i| i * npieces) {
        plot.write_many(Arc::clone(&pieces), index as u64).unwrap();
    }
    drop(plot);

    // Just in case
    std::process::Command::new("sync")
        .spawn()
        .unwrap()
        .wait()
        .unwrap();

    let took = start.elapsed();
    eprintln!(
        "Writing {write_size}M to disk took {took:?}. Speed is around {:.2} M/s",
        write_size as f64 / took.as_secs_f64()
    );
}

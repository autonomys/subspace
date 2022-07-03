use std::sync::Arc;

use rand::prelude::*;
use subspace_core_primitives::PIECE_SIZE;
use subspace_farmer::Plot;
use tempfile::TempDir;

#[tokio::main]
async fn main() {
    let batch_size = 4096; // 16M
    let piece_count = subspace_core_primitives::NPieces::from_bytes(4 * 2u64.pow(20)); // 4G
    let base_directory = TempDir::new_in(std::env::current_dir().unwrap()).unwrap();

    let mut pieces = vec![0u8; batch_size as usize * PIECE_SIZE];
    rand::thread_rng().fill(&mut pieces[..]);
    let pieces = Arc::new(pieces.try_into().unwrap());

    let plot = Plot::open_or_create(
        base_directory.as_ref(),
        base_directory.as_ref(),
        [0; 32].into(),
        piece_count,
    )
    .unwrap();

    let start = std::time::Instant::now();

    for index in (0..*piece_count / batch_size).map(|i| i * batch_size) {
        plot.write_many(Arc::clone(&pieces), (index..index + batch_size).collect())
            .unwrap();
    }
    drop(plot);

    let took = start.elapsed();
    let write_size = *piece_count * PIECE_SIZE as u64 / 1024 / 1024;
    eprintln!(
        "Writing {write_size}M to disk took {took:?}. Speed is around {:.2} M/s",
        write_size as f64 / took.as_secs_f64()
    );
}

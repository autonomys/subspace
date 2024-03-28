use std::path::PathBuf;
use subspace_farmer::single_disk_farm::{SingleDiskFarm, SingleDiskFarmSummary};

pub(crate) fn print_disk_farm_info(directory: PathBuf, farm_index: usize) {
    println!("Single disk farm {farm_index}:");
    match SingleDiskFarm::collect_summary(directory) {
        SingleDiskFarmSummary::Found { info, directory } => {
            println!("  ID: {}", info.id());
            println!("  Genesis hash: 0x{}", hex::encode(info.genesis_hash()));
            println!("  Public key: 0x{}", hex::encode(info.public_key()));
            println!(
                "  Allocated space: {} ({})",
                bytesize::to_string(info.allocated_space(), true),
                bytesize::to_string(info.allocated_space(), false)
            );
            println!("  Directory: {}", directory.display());
        }
        SingleDiskFarmSummary::NotFound { directory } => {
            println!("  Plot directory: {}", directory.display());
            println!("  No farm found here yet");
        }
        SingleDiskFarmSummary::Error { directory, error } => {
            println!("  Directory: {}", directory.display());
            println!("  Failed to open farm info: {error}");
        }
    }
}

use std::path::PathBuf;
use subspace_farmer::single_disk_plot::{SingleDiskPlot, SingleDiskPlotSummary};

pub(crate) fn print_disk_farm_info(directory: PathBuf, disk_farm_index: usize) {
    println!("Single disk farm {disk_farm_index}:");
    match SingleDiskPlot::collect_summary(directory) {
        SingleDiskPlotSummary::Found { info, directory } => {
            println!("  ID: {}", info.id());
            println!("  Genesis hash: 0x{}", hex::encode(info.genesis_hash()));
            println!("  Public key: 0x{}", hex::encode(info.public_key()));
            println!("  First sector index: {}", info.first_sector_index());
            println!(
                "  Allocated space: {} ({})",
                bytesize::to_string(info.allocated_space(), true),
                bytesize::to_string(info.allocated_space(), false)
            );
            println!("  Directory: {}", directory.display());
        }
        SingleDiskPlotSummary::NotFound { directory } => {
            println!("  Plot directory: {}", directory.display());
            println!("  No farm found here yet");
        }
        SingleDiskPlotSummary::Error { directory, error } => {
            println!("  Directory: {}", directory.display());
            println!("  Failed to open farm info: {error}");
        }
    }
}

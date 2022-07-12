use crate::DiskFarm;
use subspace_farmer::single_disk_farm::{SingleDiskFarm, SingleDiskFarmSummary};
use subspace_farmer::single_plot_farm::SinglePlotFarmSummary;

pub(crate) fn info(disk_farms: Vec<DiskFarm>) {
    for (disk_farm_index, disk_farm) in disk_farms.into_iter().enumerate() {
        if disk_farm_index > 0 {
            println!();
        }

        let DiskFarm {
            plot_directory,
            metadata_directory,
            ..
        } = disk_farm;

        println!("Single disk farm {disk_farm_index}:");
        match SingleDiskFarm::collect_summary(plot_directory, metadata_directory) {
            SingleDiskFarmSummary::Found {
                id,
                genesis_hash,
                allocated_plotting_space,
                plot_directory,
                metadata_directory,
                single_plot_farm_summaries,
            } => {
                println!("  ID: {id}");
                println!("  Genesis hash: 0x{}", hex::encode(genesis_hash));
                println!(
                    "  Allocated plotting space: {} ({})",
                    bytesize::to_string(allocated_plotting_space, true),
                    bytesize::to_string(allocated_plotting_space, false)
                );
                println!("  Plot directory (HDD): {}", plot_directory.display());
                println!(
                    "  Metadata directory (SSD): {}",
                    metadata_directory.display()
                );

                for (plot_farm_index, single_plot_farm_summary) in
                    single_plot_farm_summaries.into_iter().enumerate()
                {
                    println!();

                    match single_plot_farm_summary {
                        SinglePlotFarmSummary::Found {
                            id,
                            public_key,
                            allocated_plotting_space,
                            plot_directory,
                            metadata_directory,
                        } => {
                            println!("  Single plot farm {disk_farm_index}.{plot_farm_index}:");
                            println!("    ID: {id}");
                            println!("    Public key: 0x{}", hex::encode(public_key));
                            println!(
                                "    Allocated plotting space: {} ({})",
                                bytesize::to_string(allocated_plotting_space, true),
                                bytesize::to_string(allocated_plotting_space, false)
                            );
                            println!("    Plot directory (HDD): {}", plot_directory.display());
                            println!(
                                "    Metadata directory (SSD): {}",
                                metadata_directory.display()
                            );
                        }
                        SinglePlotFarmSummary::NotFound {
                            plot_directory,
                            metadata_directory,
                        } => {
                            println!("  Single plot farm {}:", plot_farm_index);
                            println!("    Plot directory (HDD): {}", plot_directory.display());
                            println!(
                                "    Metadata directory (SSD): {}",
                                metadata_directory.display()
                            );
                            println!("    No farm found here yet");
                        }
                        SinglePlotFarmSummary::Error {
                            plot_directory,
                            metadata_directory,
                            error,
                        } => {
                            println!("  Single plot farm {}:", plot_farm_index);
                            println!("    Plot directory (HDD): {}", plot_directory.display());
                            println!(
                                "    Metadata directory (SSD): {}",
                                metadata_directory.display()
                            );
                            println!("    Failed to open farm info: {}", error);
                        }
                    }
                }
            }
            SingleDiskFarmSummary::NotFound {
                plot_directory,
                metadata_directory,
            } => {
                println!("  Plot directory (HDD): {}", plot_directory.display());
                println!(
                    "  Metadata directory (SSD): {}",
                    metadata_directory.display()
                );
                println!("  No farm found here yet");
            }
            SingleDiskFarmSummary::Error {
                plot_directory,
                metadata_directory,
                error,
            } => {
                println!("  Plot directory (HDD): {}", plot_directory.display());
                println!(
                    "  Metadata directory (SSD): {}",
                    metadata_directory.display()
                );
                println!("  Failed to open farm info: {}", error);
            }
        }
    }
}

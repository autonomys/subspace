pub(super) mod metrics;
pub(super) mod network;

use bytesize::ByteSize;
use clap::Parser;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use subspace_farmer::single_disk_farm::{SingleDiskFarm, SingleDiskFarmSummary};
use subspace_networking::libp2p::identity::{ed25519, Keypair};
use thread_priority::ThreadPriority;
use zeroize::Zeroizing;

/// Plotting thread priority
#[derive(Debug, Parser, Copy, Clone)]
pub(in super::super) enum PlottingThreadPriority {
    /// Minimum priority
    Min,
    /// Default priority
    Default,
    /// Max priority (not recommended)
    Max,
}

impl FromStr for PlottingThreadPriority {
    type Err = String;

    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        match s {
            "min" => Ok(Self::Min),
            "default" => Ok(Self::Default),
            "max" => Ok(Self::Max),
            s => Err(format!("Thread priority {s} is not valid")),
        }
    }
}

impl fmt::Display for PlottingThreadPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Min => "min",
            Self::Default => "default",
            Self::Max => "max",
        })
    }
}

impl From<PlottingThreadPriority> for Option<ThreadPriority> {
    fn from(value: PlottingThreadPriority) -> Self {
        match value {
            PlottingThreadPriority::Min => Some(ThreadPriority::Min),
            PlottingThreadPriority::Default => None,
            PlottingThreadPriority::Max => Some(ThreadPriority::Max),
        }
    }
}

#[derive(Debug, Clone)]
pub(in super::super) struct DiskFarm {
    /// Path to directory where data is stored.
    pub(in super::super) directory: PathBuf,
    /// How much space in bytes can farm use for plots (metadata space is not included)
    pub(in super::super) allocated_plotting_space: u64,
}

impl FromStr for DiskFarm {
    type Err = String;

    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        let parts = s.split(',').collect::<Vec<_>>();
        if parts.len() != 2 {
            return Err("Must contain 2 coma-separated components".to_string());
        }

        let mut plot_directory = None;
        let mut allocated_plotting_space = None;

        for part in parts {
            let part = part.splitn(2, '=').collect::<Vec<_>>();
            if part.len() != 2 {
                return Err("Each component must contain = separating key from value".to_string());
            }

            let key = *part.first().expect("Length checked above; qed");
            let value = *part.get(1).expect("Length checked above; qed");

            match key {
                "path" => {
                    plot_directory.replace(PathBuf::from(value));
                }
                "size" => {
                    allocated_plotting_space.replace(
                        value
                            .parse::<ByteSize>()
                            .map_err(|error| {
                                format!("Failed to parse `size` \"{value}\": {error}")
                            })?
                            .as_u64(),
                    );
                }
                key => {
                    return Err(format!(
                        "Key \"{key}\" is not supported, only `path` or `size`"
                    ));
                }
            }
        }

        Ok(DiskFarm {
            directory: plot_directory.ok_or({
                "`path` key is required with path to directory where plots will be stored"
            })?,
            allocated_plotting_space: allocated_plotting_space.ok_or({
                "`size` key is required with path to directory where plots will be stored"
            })?,
        })
    }
}

pub(in super::super) fn derive_libp2p_keypair(schnorrkel_sk: &schnorrkel::SecretKey) -> Keypair {
    let mut secret_bytes = Zeroizing::new(schnorrkel_sk.to_ed25519_bytes());

    let keypair = ed25519::Keypair::from(
        ed25519::SecretKey::try_from_bytes(&mut secret_bytes.as_mut()[..32])
            .expect("Secret key is exactly 32 bytes in size; qed"),
    );

    Keypair::from(keypair)
}

pub(super) fn print_disk_farm_info(directory: PathBuf, farm_index: usize) {
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

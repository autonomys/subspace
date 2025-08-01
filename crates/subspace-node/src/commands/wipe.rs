use clap::Parser;
use std::path::PathBuf;
use std::{fs, io};
use subspace_process::init_logger;
use tracing::info;

/// Options for running a node
#[derive(Debug, Parser)]
pub struct WipeOptions {
    /// Base path where to store node files
    base_path: PathBuf,
}

pub fn wipe(WipeOptions { base_path }: WipeOptions) -> Result<(), io::Error> {
    init_logger();
    let paths = [
        base_path.join("db"),
        base_path.join("domains"),
        base_path.join("network"),
    ];

    for path in paths {
        if path.exists() {
            info!("Removing {}", path.display());
            fs::remove_dir_all(path)?;
        }
    }

    info!("Done");

    Ok(())
}

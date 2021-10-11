use crate::utils::{get_path, try_remove};
use anyhow::Result;
use log::info;
use std::fs;
use std::path::PathBuf;

pub(crate) fn erase_plot(custom_path: Option<PathBuf>) -> Result<()> {
    let path = get_path(custom_path);
    info!("Erasing the plot");
    try_remove(path.join("plot.bin"), fs::remove_file)?;
    info!("Erasing plot metadata");
    try_remove(path.join("plot-metadata"), fs::remove_dir_all)?;
    info!("Erasing plot commitments");
    try_remove(path.join("commitments"), fs::remove_dir_all)?;
    info!("Erasing object mappings");
    try_remove(path.join("object-mappings"), fs::remove_dir_all)?;
    info!("Erasing identity");
    try_remove(path.join("identity.bin"), fs::remove_file)?;
    info!("Done");

    Ok(())
}

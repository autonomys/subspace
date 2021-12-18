mod farm;
mod identity;

pub(crate) use farm::farm;
pub(crate) use identity::identity;
use log::info;
use std::path::Path;
use std::{fs, io};

/// Helper function for ignoring the error that given file/directory does not exist.
fn try_remove<P: AsRef<Path>>(
    path: P,
    remove: impl FnOnce(P) -> std::io::Result<()>,
) -> io::Result<()> {
    if path.as_ref().exists() {
        remove(path)?;
    }
    Ok(())
}

pub(crate) fn erase_plot<P: AsRef<Path>>(path: P) -> io::Result<()> {
    info!("Erasing the plot");
    try_remove(path.as_ref().join("plot.bin"), fs::remove_file)?;
    info!("Erasing plot metadata");
    try_remove(path.as_ref().join("plot-metadata"), fs::remove_dir_all)?;
    info!("Erasing plot commitments");
    try_remove(path.as_ref().join("commitments"), fs::remove_dir_all)?;
    info!("Erasing object mappings");
    try_remove(path.as_ref().join("object-mappings"), fs::remove_dir_all)?;

    Ok(())
}

pub(crate) fn wipe<P: AsRef<Path>>(path: P) -> io::Result<()> {
    erase_plot(path.as_ref())?;

    info!("Erasing identity");
    try_remove(path.as_ref().join("identity.bin"), fs::remove_file)?;

    Ok(())
}

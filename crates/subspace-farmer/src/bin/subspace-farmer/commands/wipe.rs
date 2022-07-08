use std::path::Path;
use std::{fs, io};
use tracing::info;

pub(crate) fn wipe<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let _ = std::fs::remove_dir_all(path.as_ref().join("object-mappings"));
    (0..)
        .map(|i| path.as_ref().join(format!("plot{i}")))
        .take_while(|path| path.is_dir())
        .try_for_each(|replica_path| {
            info!(path = ?replica_path, "Erasing plot replica");
            std::fs::remove_dir_all(replica_path)
        })?;

    // TODO: Remove this after next snapshot, this is a compatibility layer to make sure we
    //  wipe old data from disks of our users
    if let Some(base_dir) = dirs::data_local_dir() {
        let _ = std::fs::remove_dir_all(base_dir.join("subspace"));
    }

    // TODO: Remove this after next snapshot, this is a compatibility layer to make sure we
    //  wipe old data from disks of our users
    erase_legacy_plot(path.as_ref())?;

    // TODO: Remove this after next snapshot, this is a compatibility layer to make sure we
    //  wipe old data from disks of our users
    let identity = path.as_ref().join("identity.bin");
    info!(path = ?identity, "Erasing identity");
    if identity.exists() {
        fs::remove_file(identity)?;
    }

    Ok(())
}

/// Helper function for ignoring the error that given file/directory does not exist.
fn try_remove<P: AsRef<Path>>(path: P, remove: impl FnOnce(P) -> io::Result<()>) -> io::Result<()> {
    if path.as_ref().exists() {
        remove(path)?;
    }
    Ok(())
}

// TODO: Remove with the next snapshot (as it is unused by now)
/// Erases plot in specific directory
fn erase_legacy_plot(path: &Path) -> io::Result<()> {
    info!("Erasing the plot");
    try_remove(&path.join("plot.bin"), fs::remove_file)?;
    info!("Erasing the plot offset to index db");
    try_remove(&path.join("plot-offset-to-index.bin"), fs::remove_file)?;
    info!("Erasing the plot index to offset db");
    try_remove(&path.join("plot-index-to-offset"), fs::remove_dir_all)?;
    info!("Erasing plot metadata");
    try_remove(&path.join("plot-metadata"), fs::remove_dir_all)?;
    info!("Erasing plot commitments");
    try_remove(&path.join("commitments"), fs::remove_dir_all)?;
    info!("Erasing object mappings");
    try_remove(&path.join("object-mappings"), fs::remove_dir_all)?;

    Ok(())
}

mod farm;
mod identity;

pub(crate) use farm::farm;
pub(crate) use identity::identity;
use log::info;
use std::path::Path;
use std::{fs, io};

pub(crate) fn erase(path: impl AsRef<Path>) -> io::Result<()> {
    subspace_farmer::Plot::erase(path.as_ref())?;
    (0..)
        .map(|i| path.as_ref().join(format!("plot{i}")))
        .take_while(|path| path.is_dir())
        .try_for_each(|replica_path| {
            info!("Erasing plot replica at path `{replica_path:?}'");
            std::fs::remove_dir_all(replica_path)
        })
}

pub(crate) fn wipe<P: AsRef<Path>>(path: P) -> io::Result<()> {
    erase(path.as_ref())?;

    info!("Erasing identity");
    let identity = path.as_ref().join("identity.bin");
    if identity.exists() {
        fs::remove_file(identity)?;
    }

    Ok(())
}

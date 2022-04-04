mod farm;
mod identity;

pub(crate) use farm::farm;
pub(crate) use identity::identity;
use log::info;
use std::path::Path;
use std::{fs, io};
use subspace_farmer::Plot;

pub(crate) fn wipe<P: AsRef<Path>>(path: P) -> io::Result<()> {
    Plot::erase(path.as_ref())?;

    info!("Erasing identity");
    let identity = path.as_ref().join("identity.bin");
    if identity.exists() {
        fs::remove_file(identity)?;
    }

    Ok(())
}

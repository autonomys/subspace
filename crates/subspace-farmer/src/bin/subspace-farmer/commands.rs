mod farm;

pub(crate) use farm::farm;
use log::info;
use std::path::Path;
use std::{fs, io};

pub(crate) fn wipe<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let _ = std::fs::remove_dir_all(path.as_ref().join("object-mappings"));
    (0..)
        .map(|i| path.as_ref().join(format!("plot{i}")))
        .take_while(|path| path.is_dir())
        .try_for_each(|replica_path| {
            info!("Erasing plot replica at path `{replica_path:?}'");
            std::fs::remove_dir_all(replica_path)
        })?;

    // TODO: Remove this line in one of future releases
    subspace_farmer::Plot::erase(path.as_ref())?;

    // TODO: Remove these lines line in one of future releases
    info!("Erasing identity");
    let identity = path.as_ref().join("identity.bin");
    if identity.exists() {
        fs::remove_file(identity)?;
    }

    Ok(())
}

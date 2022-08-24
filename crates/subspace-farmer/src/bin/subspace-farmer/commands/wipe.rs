use std::path::Path;
use std::{fs, io};
use tracing::info;

pub(crate) fn wipe<P: AsRef<Path>>(path: P) -> io::Result<()> {
    // TODO: Remove this after next snapshot, this is a compatibility layer to make sure we
    //  wipe old data from disks of our users
    let _ = fs::remove_dir_all(path.as_ref().join("object-mappings"));

    (0..)
        .map(|i| path.as_ref().join(format!("plot{i}")))
        .take_while(|path| path.is_dir())
        .try_for_each(|replica_path| {
            info!(path = ?replica_path, "Erasing plot replica");
            fs::remove_dir_all(replica_path)
        })?;

    Ok(())
}

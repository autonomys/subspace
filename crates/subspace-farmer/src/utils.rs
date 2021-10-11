use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn get_path(custom_path: Option<PathBuf>) -> PathBuf {
    // set storage path
    let path = custom_path
        .or_else(|| std::env::var("SUBSPACE_DIR").map(PathBuf::from).ok())
        .unwrap_or_else(|| {
            dirs::data_local_dir()
                .expect("Can't find local data directory, needs to be specified explicitly")
                .join("subspace")
        });

    if !path.exists() {
        fs::create_dir_all(&path).unwrap_or_else(|error| {
            panic!("Failed to create data directory {:?}: {:?}", path, error)
        });
    }

    path
}

/// Helper function for ignoring the error that given file/directory does not exist.
pub(crate) fn try_remove<P: AsRef<Path>>(
    path: P,
    remove: impl FnOnce(P) -> std::io::Result<()>,
) -> Result<()> {
    if path.as_ref().exists() {
        remove(path)?;
    }
    Ok(())
}

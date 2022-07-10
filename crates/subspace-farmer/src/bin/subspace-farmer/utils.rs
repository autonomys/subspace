use std::path::PathBuf;

pub(crate) fn default_base_path() -> PathBuf {
    dirs::data_local_dir()
        .expect("Can't find local data directory, needs to be specified explicitly")
        .join("subspace-farmer")
}

pub(crate) fn raise_fd_limit() {
    match std::panic::catch_unwind(fdlimit::raise_fd_limit) {
        Ok(Some(limit)) => {
            tracing::info!("Increase file limit from soft to hard (limit is {limit})")
        }
        Ok(None) => tracing::debug!("Failed to increase file limit"),
        Err(err) => {
            let err = if let Some(err) = err.downcast_ref::<&str>() {
                *err
            } else if let Some(err) = err.downcast_ref::<String>() {
                err
            } else {
                unreachable!("Should be unreachable as `fdlimit` uses panic macro, which should return either `&str` or `String`.")
            };
            tracing::warn!("Failed to increase file limit: {err}")
        }
    }
}

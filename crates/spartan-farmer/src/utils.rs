use async_std::task;
use std::fs;
use std::path::PathBuf;

pub(crate) fn spawn_blocking<F, T>(f: F) -> task::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    task::spawn(async_global_executor::spawn_blocking(f))
}

pub(crate) fn get_path(custom_path: Option<PathBuf>) -> PathBuf {
    // set storage path
    let path = custom_path
        .or_else(|| std::env::var("SPARTAN_DIR").map(PathBuf::from).ok())
        .unwrap_or_else(|| {
            dirs::data_local_dir()
                .expect("Can't find local data directory, needs to be specified explicitly")
                .join("spartan")
        });

    if !path.exists() {
        fs::create_dir_all(&path).unwrap_or_else(|error| {
            panic!("Failed to create data directory {:?}: {:?}", path, error)
        });
    }

    path
}

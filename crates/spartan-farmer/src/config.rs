use rocksdb::DB;
use schnorrkel::Keypair;
use std::path::PathBuf;
use std::sync::Arc;

const KEYPAIR_KEY: &[u8] = b"keypair";

#[derive(Debug)]
struct Inner {
    base_directory: PathBuf,
    db: Arc<DB>,
}

// Global farmer configuration
#[derive(Debug, Clone)]
pub(crate) struct Config {
    inner: Arc<Inner>,
}

impl Config {
    /// Open existing configuration or create an empty one
    pub(crate) async fn open_or_create(base_directory: PathBuf) -> Result<Self, rocksdb::Error> {
        let path = base_directory.join("config");
        let db = tokio::task::spawn_blocking(move || DB::open_default(path))
            .await
            .unwrap()?;

        Ok(Self {
            inner: Arc::new(Inner {
                base_directory,
                db: Arc::new(db),
            }),
        })
    }

    pub(crate) fn base_directory(&self) -> &PathBuf {
        &self.inner.base_directory
    }

    /// Get stored farmer keypair/identity
    pub(crate) async fn get_keypair(&self) -> Result<Option<Keypair>, rocksdb::Error> {
        let db = Arc::clone(&self.inner.db);
        tokio::task::spawn_blocking(move || {
            db.get(KEYPAIR_KEY).map(|maybe_keypair| {
                maybe_keypair.as_ref().map(|keypair_bytes| {
                    Keypair::from_bytes(keypair_bytes).expect("Database contains incorrect keypair")
                })
            })
        })
        .await
        .unwrap()
    }

    /// Store farmer keypair/identity
    pub(crate) async fn set_keypair(&self, keypair: &Keypair) -> Result<(), rocksdb::Error> {
        let db = Arc::clone(&self.inner.db);
        let keypair_bytes = keypair.to_bytes();
        tokio::task::spawn_blocking(move || db.put(KEYPAIR_KEY, keypair_bytes))
            .await
            .unwrap()
    }
}

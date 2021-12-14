use super::CommitmentError;
use async_lock::Mutex;
use log::error;
use lru::LruCache;
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::Salt;

// TODO: Make this private
pub(super) const COMMITMENTS_CACHE_SIZE: usize = 2;
const COMMITMENTS_KEY: &[u8] = b"commitments";

// TODO: Make this private
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum CommitmentStatus {
    /// In-progress commitment to the part of the plot
    InProgress,
    /// Commitment to the whole plot and not some in-progress partial commitment
    Created,
}

// TODO: Make fields in this data structure private
pub(super) struct DbEntry {
    pub(super) salt: Salt,
    pub(super) db: Mutex<Option<Arc<DB>>>,
}

// TODO: Make fields in this data structure private
#[derive(Debug)]
pub(super) struct CommitmentDatabases {
    pub(super) databases: LruCache<Salt, Arc<DbEntry>>,
    pub(super) metadata_cache: HashMap<Salt, CommitmentStatus>,
    pub(super) metadata_db: Arc<DB>,
}

impl CommitmentDatabases {
    pub(super) fn new(base_directory: PathBuf) -> Result<Self, CommitmentError> {
        let metadata_db = DB::open_default(base_directory.join("metadata"))
            .map_err(CommitmentError::MetadataDb)?;
        let metadata_cache: HashMap<Salt, CommitmentStatus> = metadata_db
            .get(COMMITMENTS_KEY)
            .map_err(CommitmentError::MetadataDb)?
            .map(|bytes| {
                serde_json::from_slice::<HashMap<String, CommitmentStatus>>(&bytes)
                    .unwrap()
                    .into_iter()
                    .map(|(salt, status)| (hex::decode(salt).unwrap().try_into().unwrap(), status))
                    .collect()
            })
            .unwrap_or_default();

        let mut commitment_databases = CommitmentDatabases {
            databases: LruCache::new(COMMITMENTS_CACHE_SIZE),
            metadata_cache,
            metadata_db: Arc::new(metadata_db),
        };

        if commitment_databases
            .metadata_cache
            .drain_filter(|salt, status| match status {
                CommitmentStatus::InProgress => {
                    if let Err(error) =
                        std::fs::remove_dir_all(base_directory.join(hex::encode(salt)))
                    {
                        error!(
                            "Failed to remove old in progress commitment {}: {}",
                            hex::encode(salt),
                            error
                        );
                    }
                    true
                }
                CommitmentStatus::Created => false,
            })
            .next()
            .is_some()
        {
            tokio::runtime::Handle::current()
                .block_on(commitment_databases.persist_metadata_cache())?;
        }

        // Open databases that were fully created during previous run
        for salt in commitment_databases.metadata_cache.keys() {
            let db = DB::open(&Options::default(), base_directory.join(hex::encode(salt)))
                .map_err(CommitmentError::CommitmentDb)?;
            commitment_databases.databases.put(
                *salt,
                Arc::new(DbEntry {
                    salt: *salt,
                    db: Mutex::new(Some(Arc::new(db))),
                }),
            );
        }

        Ok::<_, CommitmentError>(commitment_databases)
    }

    pub(super) async fn mark_in_progress(&mut self, salt: Salt) -> Result<(), CommitmentError> {
        self.update_status(salt, CommitmentStatus::InProgress).await
    }

    pub(super) async fn mark_created(&mut self, salt: Salt) -> Result<(), CommitmentError> {
        self.update_status(salt, CommitmentStatus::Created).await
    }

    async fn update_status(
        &mut self,
        salt: Salt,
        status: CommitmentStatus,
    ) -> Result<(), CommitmentError> {
        self.metadata_cache.insert(salt, status);

        self.persist_metadata_cache().await
    }

    async fn persist_metadata_cache(&self) -> Result<(), CommitmentError> {
        let metadata_db = Arc::clone(&self.metadata_db);
        let prepared_metadata_cache: HashMap<String, CommitmentStatus> = self
            .metadata_cache
            .iter()
            .map(|(salt, status)| (hex::encode(salt), *status))
            .collect();

        tokio::task::spawn_blocking(move || {
            metadata_db
                .put(
                    COMMITMENTS_KEY,
                    &serde_json::to_vec(&prepared_metadata_cache).unwrap(),
                )
                .map_err(CommitmentError::MetadataDb)
        })
        .await
        .unwrap()
    }
}

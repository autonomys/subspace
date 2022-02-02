use super::CommitmentError;
use log::error;
use lru::LruCache;
use parking_lot::Mutex;
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::Salt;

// Cache size is just enough for last 2 salts to be stored
const COMMITMENTS_CACHE_SIZE: usize = 2;
const COMMITMENTS_KEY: &[u8] = b"commitments";

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
enum CommitmentStatus {
    /// In-progress commitment to the part of the plot
    InProgress,
    /// Commitment to the whole plot and not some in-progress partial commitment
    Created,
}

pub(super) struct CreateDbEntryResult {
    pub(super) db_entry: Arc<DbEntry>,
    pub(super) removed_entry_salt: Option<Salt>,
}

pub(super) struct DbEntry {
    salt: Salt,
    db: Mutex<Option<Arc<DB>>>,
}

impl fmt::Debug for DbEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbEntry").field("salt", &self.salt).finish()
    }
}

impl Deref for DbEntry {
    type Target = Mutex<Option<Arc<DB>>>;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl DbEntry {
    pub(super) fn salt(&self) -> &Salt {
        &self.salt
    }
}

#[derive(Debug)]
pub(super) struct CommitmentDatabases {
    base_directory: PathBuf,
    databases: LruCache<Salt, Arc<DbEntry>>,
    metadata_cache: HashMap<Salt, CommitmentStatus>,
    metadata_db: Arc<DB>,
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
            base_directory: base_directory.clone(),
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
            commitment_databases.persist_metadata_cache()?;
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

    /// Get salts for all current database entries
    pub(super) fn get_salts(&self) -> Vec<Salt> {
        self.databases
            .iter()
            .map(|(salt, _db_entry)| *salt)
            .collect()
    }

    /// Returns current and next `db_entry`.
    pub(super) fn get_db_entries(&mut self) -> (Option<Arc<DbEntry>>, Option<Arc<DbEntry>>) {
        let mut databases_iter = self.databases.iter().rev();

        let current = databases_iter
            .next()
            .map(|(_salt, db_entry)| Arc::clone(db_entry));
        let next = databases_iter
            .next()
            .map(|(_salt, db_entry)| Arc::clone(db_entry));

        (current, next)
    }
    pub(super) fn get_db_entry(&self, salt: &Salt) -> Option<&Arc<DbEntry>> {
        self.databases.peek(salt)
    }

    /// Returns `Ok(None)` if entry for this salt already exists.
    pub(super) fn create_db_entry(
        &mut self,
        salt: Salt,
    ) -> Result<Option<CreateDbEntryResult>, CommitmentError> {
        if self.databases.contains(&salt) {
            return Ok(None);
        }

        let db_entry = Arc::new(DbEntry {
            salt,
            db: Mutex::new(None),
        });
        let mut removed_entry_salt = None;

        let old_db_entry = if self.databases.len() >= COMMITMENTS_CACHE_SIZE {
            self.databases.pop_lru().map(|(_salt, db_entry)| db_entry)
        } else {
            None
        };
        self.databases.put(salt, Arc::clone(&db_entry));

        if let Some(old_db_entry) = old_db_entry {
            let old_salt = old_db_entry.salt;
            removed_entry_salt.replace(old_salt);
            let old_db_path = self.base_directory.join(hex::encode(old_salt));

            // Remove old commitments for `old_salt`
            self.metadata_cache.remove(&old_salt);

            tokio::task::spawn_blocking(move || {
                // Take a lock to make sure database was released by whatever user there was and we
                // have an exclusive access to it, then drop it
                old_db_entry.db.lock().take();

                if let Err(error) = std::fs::remove_dir_all(old_db_path) {
                    error!(
                        "Failed to remove old commitment for salt {}: {}",
                        hex::encode(old_salt),
                        error
                    );
                }
            });
        }

        self.mark_in_progress(salt)?;

        Ok(Some(CreateDbEntryResult {
            db_entry,
            removed_entry_salt,
        }))
    }

    pub(super) fn mark_in_progress(&mut self, salt: Salt) -> Result<(), CommitmentError> {
        self.update_status(salt, CommitmentStatus::InProgress)
    }

    pub(super) fn mark_created(&mut self, salt: Salt) -> Result<(), CommitmentError> {
        self.update_status(salt, CommitmentStatus::Created)
    }

    fn update_status(
        &mut self,
        salt: Salt,
        status: CommitmentStatus,
    ) -> Result<(), CommitmentError> {
        self.metadata_cache.insert(salt, status);

        self.persist_metadata_cache()
    }

    fn persist_metadata_cache(&self) -> Result<(), CommitmentError> {
        let prepared_metadata_cache: HashMap<String, CommitmentStatus> = self
            .metadata_cache
            .iter()
            .map(|(salt, status)| (hex::encode(salt), *status))
            .collect();

        self.metadata_db
            .put(
                COMMITMENTS_KEY,
                &serde_json::to_vec(&prepared_metadata_cache).unwrap(),
            )
            .map_err(CommitmentError::MetadataDb)
    }
}

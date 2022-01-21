use super::CommitmentError;
use log::error;
use parking_lot::{Mutex, RwLock};
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::Salt;

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

impl Deref for DbEntry {
    type Target = Mutex<Option<Arc<DB>>>;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

pub(super) struct CommitmentDatabases {
    base_directory: PathBuf,
    first_db: RwLock<Option<Arc<DbEntry>>>,
    second_db: RwLock<Option<Arc<DbEntry>>>,
    metadata: RwLock<CommitmentMetadata>,
}

pub(super) struct CommitmentMetadata {
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

        let commitment_metadata = CommitmentMetadata {
            metadata_cache,
            metadata_db: Arc::new(metadata_db),
        };

        let commitment_databases = CommitmentDatabases {
            base_directory: base_directory.clone(),
            first_db: RwLock::new(None),
            second_db: RwLock::new(None),
            metadata: RwLock::new(commitment_metadata),
        };

        if commitment_databases
            .metadata
            .write()
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
        let read_lock = commitment_databases.metadata.read();
        let first_salt = read_lock.metadata_cache.keys().next();
        let second_salt = read_lock.metadata_cache.keys().next();

        // Open the first one
        if let Some(first_salt) = first_salt {
            let db = DB::open(
                &Options::default(),
                base_directory.join(hex::encode(first_salt)),
            )
            .map_err(CommitmentError::CommitmentDb)?;
            commitment_databases
                .first_db
                .write()
                .replace(Arc::new(DbEntry {
                    salt: *first_salt,
                    db: Mutex::new(Some(Arc::new(db))),
                }));
        }
        // Open the second one
        if let Some(second_salt) = second_salt {
            let db = DB::open(
                &Options::default(),
                base_directory.join(hex::encode(second_salt)),
            )
            .map_err(CommitmentError::CommitmentDb)?;
            commitment_databases
                .second_db
                .write()
                .replace(Arc::new(DbEntry {
                    salt: *second_salt,
                    db: Mutex::new(Some(Arc::new(db))),
                }));
        }
        drop(read_lock);

        Ok::<_, CommitmentError>(commitment_databases)
    }

    /// Get salts for all current database entries
    pub(super) fn get_salts(&self) -> Vec<Salt> {
        self.metadata
            .read()
            .metadata_cache
            .iter()
            .map(|(salt, _commitment_status)| *salt)
            .collect()
    }

    pub(super) fn get_db_entry(&self, salt: &Salt) -> Option<Arc<DbEntry>> {
        return match salt {
            _ if &self.first_db.read().as_ref().unwrap().salt == salt => {
                self.first_db.read().clone()
            }
            _ if &self.second_db.read().as_ref().unwrap().salt == salt => {
                self.second_db.read().clone()
            }
            _ => None,
        };
    }

    /// Returns `Ok(None)` if entry for this salt already exists.
    pub(super) fn create_db_entry(
        &self,
        salt: Salt,
        current_salt: Salt,
    ) -> Result<Option<CreateDbEntryResult>, CommitmentError> {
        match salt {
            _ if self.first_db.read().as_ref().is_some()
                && self.first_db.read().as_ref().unwrap().salt == salt =>
            {
                return Ok(None)
            }
            _ if self.second_db.read().as_ref().is_some()
                && self.second_db.read().as_ref().unwrap().salt == salt =>
            {
                return Ok(None)
            }
            _ => {} // don't do anything yet if salt does not exist
        };

        // create the new db_entry
        let db_entry = Arc::new(DbEntry {
            salt,
            db: Mutex::new(None),
        });
        let mut removed_entry_salt = None;
        let old_db_entry;

        // delete the old database only, and don't touch the other to prevent data races
        match current_salt {
            // if the `first` DB is not the current one, replace it
            _ if self.first_db.read().as_ref().is_none() => {
                old_db_entry = self.first_db.write().replace(Arc::clone(&db_entry));
            }
            _ if self.second_db.read().as_ref().is_none() => {
                old_db_entry = self.second_db.write().replace(Arc::clone(&db_entry));
            }
            _ if self.first_db.read().as_ref().is_some()
                && self.first_db.read().as_ref().unwrap().salt != current_salt =>
            {
                old_db_entry = self.first_db.write().replace(Arc::clone(&db_entry));
            }
            // if the `second` DB is not the current one, replace it
            _ if self.second_db.read().as_ref().is_some()
                && self.second_db.read().as_ref().unwrap().salt != current_salt =>
            {
                old_db_entry = self.second_db.write().replace(Arc::clone(&db_entry));
            }
            _ => unreachable!(),
        };

        if let Some(old_db_entry) = old_db_entry {
            let old_salt = old_db_entry.salt;
            removed_entry_salt.replace(old_salt);
            let old_db_path = self.base_directory.join(hex::encode(old_salt));

            // Remove old commitments for `old_salt` from the metadata_cache
            self.metadata.write().metadata_cache.remove(&old_salt);

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

    pub(super) fn mark_in_progress(&self, salt: Salt) -> Result<(), CommitmentError> {
        self.update_status(salt, CommitmentStatus::InProgress)
    }

    pub(super) fn mark_created(&self, salt: Salt) -> Result<(), CommitmentError> {
        self.update_status(salt, CommitmentStatus::Created)
    }

    fn update_status(&self, salt: Salt, status: CommitmentStatus) -> Result<(), CommitmentError> {
        self.metadata.write().metadata_cache.insert(salt, status);
        self.persist_metadata_cache()
    }

    fn persist_metadata_cache(&self) -> Result<(), CommitmentError> {
        let prepared_metadata_cache: HashMap<String, CommitmentStatus> = self
            .metadata
            .read()
            .metadata_cache
            .iter()
            .map(|(salt, status)| (hex::encode(salt), *status))
            .collect();

        self.metadata
            .write()
            .metadata_db
            .put(
                COMMITMENTS_KEY,
                &serde_json::to_vec(&prepared_metadata_cache).unwrap(),
            )
            .map_err(CommitmentError::MetadataDb)
    }
}

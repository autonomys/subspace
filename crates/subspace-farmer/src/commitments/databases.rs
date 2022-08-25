use crate::commitments::metadata::{CommitmentMetadata, CommitmentStatus};
use crate::commitments::CommitmentError;
use lru::LruCache;
use parity_db::{ColumnOptions, CompressionType, Db, Options};
use parking_lot::Mutex;
use std::fmt;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::Salt;
use tracing::error;

// Cache size is just enough for last 2 salts to be stored
const COMMITMENTS_CACHE_SIZE: usize = 2;

pub(super) struct CreateDbEntryResult {
    pub(super) db_entry: Arc<DbEntry>,
    pub(super) removed_entry_salt: Option<Salt>,
}

pub(super) struct DbEntry {
    salt: Salt,
    db: Mutex<Option<Arc<Db>>>,
}

impl fmt::Debug for DbEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbEntry").field("salt", &self.salt).finish()
    }
}

impl Deref for DbEntry {
    type Target = Mutex<Option<Arc<Db>>>;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl DbEntry {
    pub(super) fn salt(&self) -> Salt {
        self.salt
    }
}

#[derive(Debug)]
pub(super) struct CommitmentDatabases {
    base_directory: PathBuf,
    databases: LruCache<Salt, Arc<DbEntry>>,
    metadata: Mutex<CommitmentMetadata>,
}

impl CommitmentDatabases {
    pub(super) fn options(path: PathBuf) -> Options {
        Options {
            path,
            columns: vec![ColumnOptions {
                preimage: false,
                btree_index: true,
                uniform: true,
                ref_counted: false,
                compression: CompressionType::NoCompression,
                compression_threshold: 4096,
            }],
            sync_wal: true,
            sync_data: true,
            stats: false,
            salt: None,
        }
    }

    pub(super) fn new(base_directory: PathBuf) -> Result<Self, CommitmentError> {
        if rocksdb::DB::open_default(base_directory.join("metadata")).is_ok() {
            std::fs::remove_dir_all(&base_directory).map_err(CommitmentError::Migrate)?;
            std::fs::create_dir(&base_directory).map_err(CommitmentError::Migrate)?;
        }

        let mut metadata = CommitmentMetadata::new(base_directory.join("metadata"))?;
        let mut databases = LruCache::new(COMMITMENTS_CACHE_SIZE);

        metadata.mutate(|metadata| {
            metadata.drain_filter(|salt, status| match status {
                CommitmentStatus::InProgress => {
                    if let Err(error) =
                        std::fs::remove_dir_all(base_directory.join(hex::encode(salt)))
                    {
                        error!(
                            salt = %hex::encode(salt),
                            %error,
                            "Failed to remove old in progress commitment",
                        );
                    }
                    true
                }
                CommitmentStatus::Created => false,
            });

            // Open databases that were fully created during previous run
            for salt in metadata.keys() {
                let db = Db::open_or_create(&Self::options(base_directory.join(hex::encode(salt))))
                    .map_err(CommitmentError::CommitmentDb)?;
                databases.put(
                    *salt,
                    Arc::new(DbEntry {
                        salt: *salt,
                        db: Mutex::new(Some(Arc::new(db))),
                    }),
                );
            }

            Ok(())
        })?;

        Ok(CommitmentDatabases {
            base_directory: base_directory.clone(),
            databases,
            metadata: Mutex::new(metadata),
        })
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
            self.metadata.lock().mutate(|metadata| {
                metadata.remove(&old_salt);

                Ok(())
            })?;

            std::thread::spawn(move || {
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
        self.metadata.lock().mutate(|metadata| {
            metadata.insert(salt, CommitmentStatus::InProgress);
            Ok(())
        })
    }

    pub(super) fn mark_created(&mut self, salt: Salt) -> Result<(), CommitmentError> {
        self.metadata.lock().mutate(|metadata| {
            metadata.insert(salt, CommitmentStatus::Created);
            Ok(())
        })
    }
}

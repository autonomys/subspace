#[cfg(test)]
mod tests;

use crate::plot::Plot;
use crate::{crypto, Salt, Tag, BATCH_SIZE};
use async_lock::Mutex;
use async_std::io;
use async_std::path::PathBuf;
use log::{error, trace};
use lru::LruCache;
use rayon::prelude::*;
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Arc;
use subspace_core_primitives::{Piece, PIECE_SIZE};
use thiserror::Error;

const COMMITMENTS_CACHE_SIZE: usize = 2;
const COMMITMENTS_KEY: &[u8] = b"commitments";

#[derive(Debug, Error)]
pub(crate) enum CommitmentError {
    #[error("Metadata DB error: {0}")]
    MetadataDb(rocksdb::Error),
    #[error("Commitment DB error: {0}")]
    CommitmentDb(rocksdb::Error),
    #[error("Plot error: {0}")]
    Plot(io::Error),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
enum CommitmentStatus {
    /// In-progress commitment to the part of the plot
    InProgress,
    /// Commitment to the whole plot and not some in-progress partial commitment
    Created,
}

struct DbEntry {
    salt: Salt,
    db: Mutex<Option<Arc<DB>>>,
}

#[derive(Debug)]
struct CommitmentDatabases {
    databases: LruCache<Salt, Arc<DbEntry>>,
    metadata_cache: HashMap<Salt, CommitmentStatus>,
    metadata_db: Arc<DB>,
}

impl CommitmentDatabases {
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

#[derive(Debug)]
struct Inner {
    base_directory: PathBuf,
    commitment_databases: Mutex<CommitmentDatabases>,
}

#[derive(Debug, Clone)]
pub(super) struct Commitments {
    inner: Arc<Inner>,
}

impl Commitments {
    /// Creates new commitments database
    pub(super) async fn new(base_directory: PathBuf) -> Result<Self, CommitmentError> {
        // Cache size is just enough for last 2 salts to be stored
        let commitment_databases_fut = tokio::task::spawn_blocking({
            let base_directory = base_directory.clone();

            move || {
                let metadata_db = DB::open_default(base_directory.join("metadata"))
                    .map_err(CommitmentError::MetadataDb)?;
                let metadata_cache: HashMap<Salt, CommitmentStatus> = metadata_db
                    .get(COMMITMENTS_KEY)
                    .map_err(CommitmentError::MetadataDb)?
                    .map(|bytes| {
                        serde_json::from_slice::<HashMap<String, CommitmentStatus>>(&bytes)
                            .unwrap()
                            .into_iter()
                            .map(|(salt, status)| {
                                (hex::decode(salt).unwrap().try_into().unwrap(), status)
                            })
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
        });

        let inner = Inner {
            base_directory,
            commitment_databases: Mutex::new(commitment_databases_fut.await.unwrap()?),
        };

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Create commitments for all pieces for a given salt
    pub(crate) async fn create(&self, salt: Salt, plot: Plot) -> Result<(), CommitmentError> {
        let mut commitment_databases = self.inner.commitment_databases.lock().await;
        if commitment_databases.databases.contains(&salt) {
            return Ok(());
        }

        let db_entry = Arc::new(DbEntry {
            salt,
            db: Mutex::new(None),
        });

        let old_db_entry = if commitment_databases.databases.len() >= COMMITMENTS_CACHE_SIZE {
            commitment_databases
                .databases
                .pop_lru()
                .map(|(_salt, db_entry)| db_entry)
        } else {
            None
        };
        commitment_databases
            .databases
            .put(salt, Arc::clone(&db_entry));

        if let Some(old_db_entry) = old_db_entry {
            let old_salt = old_db_entry.salt;
            let old_db_path = self.inner.base_directory.join(hex::encode(old_salt));

            // Remove old commitments for `old_salt`
            commitment_databases.metadata_cache.remove(&old_salt);

            tokio::task::spawn_blocking(move || {
                // Take a lock to make sure database was released by whatever user there was and we
                // have an exclusive access to it, then drop it
                tokio::runtime::Handle::current()
                    .block_on(old_db_entry.db.lock())
                    .take();

                if let Err(error) = std::fs::remove_dir_all(old_db_path) {
                    error!(
                        "Failed to remove old commitment for salt {}: {}",
                        hex::encode(old_salt),
                        error
                    );
                }
            });
        }

        commitment_databases
            .update_status(salt, CommitmentStatus::InProgress)
            .await?;

        // Release lock to allow working with other databases, but hold lock for `db_entry.db` such
        // that nothing else can modify it
        let mut db_guard = db_entry.db.lock().await;
        drop(commitment_databases);

        let db_path = self.inner.base_directory.join(hex::encode(salt));

        let db_fut = tokio::task::spawn_blocking(move || {
            let runtime_handle = tokio::runtime::Handle::current();

            let db = DB::open_default(db_path).map_err(CommitmentError::CommitmentDb)?;
            let piece_count = plot.piece_count();
            for batch_start in (0..piece_count).step_by(BATCH_SIZE as usize) {
                let pieces_to_process = (batch_start + BATCH_SIZE).min(piece_count) - batch_start;
                let pieces = runtime_handle
                    .block_on(plot.read_pieces(batch_start, pieces_to_process))
                    .map_err(CommitmentError::Plot)?;

                let tags: Vec<Tag> = pieces
                    .par_chunks_exact(PIECE_SIZE)
                    .map(|piece| crypto::create_tag(piece, &salt))
                    .collect();

                for (tag, index) in tags.iter().zip(batch_start..) {
                    db.put(tag, index.to_le_bytes())
                        .map_err(CommitmentError::CommitmentDb)?;
                }
            }

            Ok::<_, CommitmentError>(db)
        });

        db_guard.replace(Arc::new(db_fut.await.unwrap()?));
        // Drop guard because locks need to be taken in a specific order or else will result in a
        // deadlock
        drop(db_guard);

        let mut commitment_databases = self.inner.commitment_databases.lock().await;

        // Check if database was already been removed
        if let Some(db_entry) = commitment_databases.databases.get(&salt) {
            if db_entry.db.lock().await.is_some() {
                commitment_databases
                    .update_status(salt, CommitmentStatus::Created)
                    .await?;
            }
        }

        Ok(())
    }

    /// Create commitments for all salts for specified pieces
    pub(crate) async fn create_for_pieces(
        &self,
        pieces: &Arc<Vec<Piece>>,
        start_offset: u64,
    ) -> Result<(), CommitmentError> {
        let salts = self
            .inner
            .commitment_databases
            .lock()
            .await
            .databases
            .iter()
            .map(|(salt, _db_entry)| *salt)
            .collect::<Vec<Salt>>();

        for salt in salts {
            let commitment_databases = self.inner.commitment_databases.lock().await;
            let db_entry = match commitment_databases.databases.peek(&salt).cloned() {
                Some(db_entry) => db_entry,
                None => {
                    continue;
                }
            };

            // Release lock to allow working with other databases, but hold lock for `db_entry.db` such
            // that nothing else can modify it
            let db_guard = db_entry.db.lock().await;
            drop(commitment_databases);

            let db = match db_guard.clone() {
                Some(db) => db,
                None => {
                    continue;
                }
            };
            let create_commitment_fut = tokio::task::spawn_blocking({
                let pieces = Arc::clone(pieces);

                move || {
                    let tags: Vec<Tag> = pieces
                        .par_iter()
                        .map(|piece| crypto::create_tag(piece, &salt))
                        .collect();

                    for (tag, offset) in tags.iter().zip(start_offset..) {
                        db.put(tag, offset.to_le_bytes())
                            .map_err(CommitmentError::CommitmentDb)?;
                    }

                    Ok::<_, CommitmentError>(db)
                }
            });

            create_commitment_fut.await.unwrap()?;
        }

        Ok(())
    }

    pub(crate) async fn find_by_range(
        &self,
        target: Tag,
        range: u64,
        salt: Salt,
    ) -> Option<(Tag, u64)> {
        let mut commitment_databases = self.inner.commitment_databases.try_lock()?;
        let db_entry = Arc::clone(commitment_databases.databases.get(&salt)?);

        let db_guard = db_entry.db.try_lock()?;
        let db = db_guard.clone()?;

        let solutions_fut = tokio::task::spawn_blocking(move || {
            let mut iter = db.raw_iterator();

            let mut solutions: Vec<(Tag, u64)> = Vec::new();

            let (lower, is_lower_overflowed) =
                u64::from_be_bytes(target).overflowing_sub(range / 2);
            let (upper, is_upper_overflowed) =
                u64::from_be_bytes(target).overflowing_add(range / 2);

            trace!(
                "{} Lower overflow: {} -- Upper overflow: {}",
                u64::from_be_bytes(target),
                is_lower_overflowed,
                is_upper_overflowed
            );

            if is_lower_overflowed || is_upper_overflowed {
                iter.seek_to_first();
                while let Some(tag) = iter.key() {
                    let tag = tag.try_into().unwrap();
                    let index = iter.value().unwrap();
                    if u64::from_be_bytes(tag) <= upper {
                        solutions.push((tag, u64::from_le_bytes(index.try_into().unwrap())));
                        iter.next();
                    } else {
                        break;
                    }
                }
                iter.seek(lower.to_be_bytes());
                while let Some(tag) = iter.key() {
                    let tag = tag.try_into().unwrap();
                    let index = iter.value().unwrap();

                    solutions.push((tag, u64::from_le_bytes(index.try_into().unwrap())));
                    iter.next();
                }
            } else {
                iter.seek(lower.to_be_bytes());
                while let Some(tag) = iter.key() {
                    let tag = tag.try_into().unwrap();
                    let index = iter.value().unwrap();
                    if u64::from_be_bytes(tag) <= upper {
                        solutions.push((tag, u64::from_le_bytes(index.try_into().unwrap())));
                        iter.next();
                    } else {
                        break;
                    }
                }
            }

            solutions
        });

        solutions_fut.await.unwrap().into_iter().next()
    }
}

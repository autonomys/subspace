mod databases;
mod metadata;
#[cfg(test)]
mod tests;

use crate::plot::{PieceOffset, Plot};
use arc_swap::ArcSwapOption;
use databases::{CommitmentDatabases, CreateDbEntryResult, DbEntry};
use event_listener_primitives::{Bag, HandlerId};
use parking_lot::Mutex;
use rayon::prelude::*;
use rocksdb::{WriteBatch, DB};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{io, mem};
use subspace_core_primitives::{Piece, Salt, Tag, PIECE_SIZE, TAG_SIZE};
use subspace_solving::create_tag;
use thiserror::Error;
use tracing::trace;

/// Number of pieces to read at once during commitments creation (16MiB)
const PLOT_READ_BATCH_SIZE: u64 = (16 * 1024 * 1024 / PIECE_SIZE) as u64;
const PIECE_OFFSET_SIZE: usize = mem::size_of::<PieceOffset>();
/// Number of commitments to store in memory before writing as a batch to disk (16MiB)
const TAGS_WRITE_BATCH_SIZE: usize = 16 * 1024 * 1024 / (TAG_SIZE + PIECE_OFFSET_SIZE);

#[derive(Debug, Error)]
pub enum CommitmentError {
    #[error("Metadata DB error: {0}")]
    MetadataDb(rocksdb::Error),
    #[error("Commitment DB error: {0}")]
    CommitmentDb(rocksdb::Error),
    #[error("Plot error: {0}")]
    Plot(io::Error),
}

#[derive(Debug, Copy, Clone)]
pub enum CommitmentStatusChange {
    /// Commitment creation has started
    Creating { salt: Salt },
    /// Commitment creation has finished
    Created { salt: Salt },
    /// Commitment creation was cancelled
    Cancelled { salt: Salt },
    /// Commitment was removed
    Removed { salt: Salt },
}

#[derive(Default, Debug)]
struct Handlers {
    #[allow(clippy::type_complexity)]
    status_change:
        Bag<Arc<dyn Fn(&CommitmentStatusChange) + Send + Sync + 'static>, CommitmentStatusChange>,
}

#[derive(Debug)]
struct Inner {
    base_directory: PathBuf,
    handlers: Handlers,
    current: ArcSwapOption<DbEntry>,
    next: ArcSwapOption<DbEntry>,
    commitment_databases: Mutex<CommitmentDatabases>,
}

/// `Commitments` is a database for commitments.
///
/// You can think of it as 2 mappings from *piece tags* to *plot offsets*.
///
/// Overall it is just wrapper around 2 databases (as we know just 2 salts -
/// current and the next one). Second one is filled in the background in the
/// `Plotting` process.
#[derive(Debug, Clone)]
pub struct Commitments {
    inner: Arc<Inner>,
}

impl Commitments {
    /// Creates new commitments database
    pub fn new(base_directory: PathBuf) -> Result<Self, CommitmentError> {
        let mut commitment_databases = CommitmentDatabases::new(base_directory.clone())?;

        let (current, next) = commitment_databases.get_db_entries();

        let inner = Inner {
            base_directory,
            handlers: Handlers::default(),
            current: ArcSwapOption::new(current),
            next: ArcSwapOption::new(next),
            commitment_databases: Mutex::new(commitment_databases),
        };

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Create commitments for all pieces for a given salt
    pub fn create(
        &self,
        salt: Salt,
        plot: Plot,
        must_stop: &AtomicBool,
    ) -> Result<(), CommitmentError> {
        {
            let mut commitment_databases = self.inner.commitment_databases.lock();

            let db_entry = match commitment_databases.create_db_entry(salt)? {
                Some(CreateDbEntryResult {
                    db_entry,
                    removed_entry_salt,
                }) => {
                    if let Some(salt) = removed_entry_salt {
                        self.inner
                            .handlers
                            .status_change
                            .call_simple(&CommitmentStatusChange::Removed { salt });
                    }
                    self.inner
                        .handlers
                        .status_change
                        .call_simple(&CommitmentStatusChange::Creating { salt });
                    db_entry
                }
                None => {
                    return Ok(());
                }
            };
            let (current, next) = commitment_databases.get_db_entries();
            self.inner.current.swap(current);
            self.inner.next.swap(next);

            let db_path = self.inner.base_directory.join(hex::encode(salt));
            db_entry.lock().replace(Arc::new(
                DB::open_default(db_path).map_err(CommitmentError::CommitmentDb)?,
            ));
        }

        let piece_count = plot.piece_count();
        let mut tags_with_offset = Vec::with_capacity(TAGS_WRITE_BATCH_SIZE);
        for batch_start in (0..piece_count).step_by(PLOT_READ_BATCH_SIZE as usize) {
            if must_stop.load(Ordering::SeqCst) {
                return Ok(());
            }
            let pieces_to_process =
                (batch_start + PLOT_READ_BATCH_SIZE).min(piece_count) - batch_start;
            // TODO: Read next batch while creating tags for the previous one for faster
            //  recommitment.
            let pieces = plot
                .read_pieces(batch_start, pieces_to_process)
                .map_err(CommitmentError::Plot)?;

            let tags: Vec<Tag> = pieces
                .par_chunks_exact(PIECE_SIZE)
                .map(|piece| create_tag(piece, salt))
                .collect();

            let db_entry = match self.get_db_entry(salt) {
                Some(db_entry) => db_entry,
                None => {
                    // Database was already removed, no need to continue
                    break;
                }
            };

            let db_guard = db_entry.lock();

            if let Some(db) = db_guard.as_ref() {
                for (tag, offset) in tags.into_iter().zip(batch_start..) {
                    tags_with_offset.push((tag, offset.to_le_bytes()));
                }

                if tags_with_offset.len() == tags_with_offset.capacity() {
                    tags_with_offset.sort_by(|(tag_a, _), (tag_b, _)| tag_a.cmp(tag_b));

                    let mut batch = WriteBatch::default();
                    for (tag, offset) in &tags_with_offset {
                        batch.put(tag, offset);
                    }
                    db.write(batch).map_err(CommitmentError::CommitmentDb)?;

                    tags_with_offset.clear();
                }
            } else {
                // Database was already removed, no need to continue
                break;
            }
        }

        // Write any remaining commitments in the buffer
        if !tags_with_offset.is_empty() {
            if let Some(db_entry) = self.get_db_entry(salt) {
                let db_guard = db_entry.lock();

                if let Some(db) = db_guard.as_ref() {
                    tags_with_offset.sort_by(|(tag_a, _), (tag_b, _)| tag_a.cmp(tag_b));

                    let mut batch = WriteBatch::default();
                    for (tag, offset) in &tags_with_offset {
                        batch.put(tag, offset);
                    }
                    db.write(batch).map_err(CommitmentError::CommitmentDb)?;
                }
            }

            drop(tags_with_offset);
        }

        let mut commitment_databases = self.inner.commitment_databases.lock();

        // Check if database was already removed
        if commitment_databases
            .get_db_entry(&salt)
            .map(|db_entry| db_entry.lock().is_some())
            .unwrap_or_default()
        {
            commitment_databases.mark_created(salt)?;

            self.inner
                .handlers
                .status_change
                .call_simple(&CommitmentStatusChange::Created { salt });
        } else {
            self.inner
                .handlers
                .status_change
                .call_simple(&CommitmentStatusChange::Cancelled { salt });
        }

        Ok(())
    }

    pub(crate) fn remove_pieces(&self, pieces: &[Piece]) -> Result<(), CommitmentError> {
        if pieces.is_empty() {
            return Ok(());
        }

        for db_entry in self.get_db_entries() {
            let salt = db_entry.salt();
            let db_guard = db_entry.lock();

            if let Some(db) = db_guard.as_ref() {
                let mut batch = WriteBatch::default();
                for piece in pieces {
                    let tag = create_tag(piece, salt);
                    batch.delete(tag);
                }
                db.write(batch).map_err(CommitmentError::CommitmentDb)?;
            }
        }

        Ok(())
    }

    /// Create commitments for all salts for specified pieces
    pub(crate) fn create_for_pieces<'a, 'iter, F, Iter>(
        &'a self,
        pieces_with_offsets: F,
    ) -> Result<(), CommitmentError>
    where
        F: Fn() -> Iter,
        Iter: Iterator<Item = (PieceOffset, &'iter [u8])>,
    {
        if pieces_with_offsets().next().is_none() {
            return Ok(());
        }

        for db_entry in self.get_db_entries() {
            let salt = db_entry.salt();
            let db_guard = db_entry.lock();

            if let Some(db) = db_guard.as_ref() {
                let mut tags_with_offset: Vec<(Tag, PieceOffset)> = pieces_with_offsets()
                    .map(|(piece_offset, piece)| (create_tag(piece, salt), piece_offset))
                    .collect();

                tags_with_offset.sort_by(|(tag_a, _), (tag_b, _)| tag_a.cmp(tag_b));

                let mut batch = WriteBatch::default();
                for (tag, piece_offset) in tags_with_offset {
                    batch.put(tag, piece_offset.to_le_bytes());
                }
                db.write(batch).map_err(CommitmentError::CommitmentDb)?;
            };
        }

        Ok(())
    }

    /// Finds the commitment falling in the range of the challenge, the first one in the list is the
    /// closest one to the target
    pub(crate) fn find_by_range(
        &self,
        target: Tag,
        range: u64,
        salt: Salt,
        limit: usize,
    ) -> Vec<(Tag, PieceOffset)> {
        let db_entry = match self.get_db_entry(salt) {
            Some(db_entry) => db_entry,
            None => {
                return Vec::new();
            }
        };

        let db_guard = match db_entry.try_lock() {
            Some(db_guard) => db_guard,
            None => {
                return Vec::new();
            }
        };
        let db = match db_guard.as_ref() {
            Some(db) => db,
            None => {
                return Vec::new();
            }
        };
        let iter = db.raw_iterator();

        // Take the best out of 10 solutions
        let mut solutions = SolutionIterator::new(iter, target, range)
            .take(limit)
            .collect::<Vec<_>>();
        let target = u64::from_be_bytes(target);
        solutions.sort_by_key(|(tag, _)| {
            let tag = u64::from_be_bytes(*tag);
            subspace_core_primitives::bidirectional_distance(&target, &tag)
        });
        solutions
    }

    pub fn on_status_change(
        &self,
        callback: Arc<dyn Fn(&CommitmentStatusChange) + Send + Sync + 'static>,
    ) -> HandlerId {
        self.inner.handlers.status_change.add(callback)
    }

    fn get_db_entry(&self, salt: Salt) -> Option<Arc<DbEntry>> {
        if let Some(current) = self.inner.current.load_full() {
            if current.salt() == salt {
                return Some(current);
            }
        }

        if let Some(next) = self.inner.next.load_full() {
            if next.salt() == salt {
                return Some(next);
            }
        }

        None
    }

    fn get_db_entries(&self) -> impl Iterator<Item = Arc<DbEntry>> {
        self.inner
            .current
            .load_full()
            .into_iter()
            .chain(self.inner.next.load_full())
    }
}

enum SolutionIteratorState {
    /// We don't have overflow of solution range.
    /// Scanning solutions from `lower..=upper`
    NoOverflow,
    /// We have overflow of solution range and we are trying to scan all solutions within
    /// `0..=upper` and switch to `Self::OverflowEnd` state.
    OverflowStart,
    /// We have overflow of solution range and we scanned all solutions from `0..=upper`. Scanning
    /// solutions in `lower..` range
    OverflowEnd,
}

pub(crate) struct SolutionIterator<'a> {
    iter: rocksdb::DBRawIterator<'a>,
    state: SolutionIteratorState,
    /// Lower bound of solution range
    lower: u64,
    /// Upper bound of solution range
    upper: u64,
}

impl<'a> SolutionIterator<'a> {
    pub fn new(mut iter: rocksdb::DBRawIterator<'a>, target: Tag, range: u64) -> Self {
        let (lower, is_lower_overflowed) = u64::from_be_bytes(target).overflowing_sub(range / 2);
        let (upper, is_upper_overflowed) = u64::from_be_bytes(target).overflowing_add(range / 2);

        trace!(
            target = u64::from_be_bytes(target),
            is_lower_overflowed,
            is_upper_overflowed
        );

        let state = if is_lower_overflowed || is_upper_overflowed {
            iter.seek_to_first();
            SolutionIteratorState::OverflowStart
        } else {
            iter.seek(lower.to_be_bytes());
            SolutionIteratorState::NoOverflow
        };
        Self {
            iter,
            state,
            lower,
            upper,
        }
    }

    fn next_entry(&mut self) -> Option<(Tag, PieceOffset)> {
        self.iter
            .key()
            .map(|tag| tag.try_into().unwrap())
            .map(|tag| {
                let offset = u64::from_le_bytes(self.iter.value().unwrap().try_into().unwrap());
                self.iter.next();
                (tag, offset)
            })
    }
}

impl<'a> Iterator for SolutionIterator<'a> {
    type Item = (Tag, PieceOffset);

    fn next(&mut self) -> Option<Self::Item> {
        match self.state {
            SolutionIteratorState::NoOverflow => self
                .next_entry()
                .filter(|(tag, _)| u64::from_be_bytes(*tag) <= self.upper),
            SolutionIteratorState::OverflowStart => self
                .next_entry()
                .filter(|(tag, _)| u64::from_be_bytes(*tag) <= self.upper)
                .or_else(|| {
                    self.state = SolutionIteratorState::OverflowEnd;
                    self.iter.seek(self.lower.to_be_bytes());
                    self.next()
                }),
            SolutionIteratorState::OverflowEnd => self.next_entry(),
        }
    }
}

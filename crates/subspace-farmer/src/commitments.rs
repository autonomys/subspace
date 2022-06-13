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
use rocksdb::DB;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use subspace_core_primitives::{Piece, Salt, Tag, PIECE_SIZE};
use subspace_solving::create_tag;
use thiserror::Error;
use tracing::trace;

const BATCH_SIZE: u64 = (16 * 1024 * 1024 / PIECE_SIZE) as u64;

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
    pub fn create(&self, salt: Salt, plot: Plot) -> Result<(), CommitmentError> {
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
        for batch_start in (0..piece_count).step_by(BATCH_SIZE as usize) {
            let pieces_to_process = (batch_start + BATCH_SIZE).min(piece_count) - batch_start;
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
                for (tag, offset) in tags.iter().zip(batch_start..) {
                    db.put(tag, offset.to_le_bytes())
                        .map_err(CommitmentError::CommitmentDb)?;
                }
            } else {
                // Database was already removed, no need to continue
                break;
            }
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
                for piece in pieces {
                    let tag = create_tag(piece, salt);
                    db.delete(tag).map_err(CommitmentError::CommitmentDb)?;
                }
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
                let tags_with_offset: Vec<(PieceOffset, Tag)> = pieces_with_offsets()
                    .map(|(piece_offset, piece)| (piece_offset, create_tag(piece, salt)))
                    .collect();

                for (piece_offset, tag) in tags_with_offset {
                    db.put(tag, piece_offset.to_le_bytes())
                        .map_err(CommitmentError::CommitmentDb)?;
                }
            };
        }

        Ok(())
    }

    /// Finds the commitment falling in the range of the challenge
    pub(crate) fn find_by_range(
        &self,
        target: Tag,
        range: u64,
        salt: Salt,
    ) -> Option<(Tag, PieceOffset)> {
        let db_entry = self.get_db_entry(salt)?;

        let db_guard = db_entry.try_lock()?;
        let db = db_guard.clone()?;
        let iter = db.raw_iterator();

        // Take the best out of 10 solutions
        let mut solutions = SolutionIterator::new(iter, target, range)
            .take(10)
            .collect::<Vec<_>>();
        let target = u64::from_be_bytes(target);
        solutions.sort_by_key(|(tag, _)| {
            let tag = u64::from_be_bytes(*tag);
            subspace_core_primitives::bidirectional_distance(&target, &tag)
        });
        solutions.into_iter().next()
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

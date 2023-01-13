//use crate::behavior::record_binary_heap::RecordBinaryHeap;
use crate::commands::farm::dsn::PieceStorage;
use parity_db::{ColumnOptions, Db, Options};
use std::borrow::Borrow;
use std::error::Error;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::vec;
use subspace_core_primitives::Piece;
use subspace_networking::libp2p::kad::record::Key;
use subspace_networking::libp2p::PeerId;
use subspace_networking::RecordBinaryHeap;
use tracing::{debug, info, trace, warn};

const PARITY_DB_COLUMN_NAME: u8 = 0;

/// Defines record storage with DB persistence
#[derive(Clone)]
pub struct ParityDbPieceStorage {
    // Parity DB instance
    db: Arc<Db>,
}

impl ParityDbPieceStorage {
    pub fn new(path: &Path) -> Result<Self, parity_db::Error> {
        let mut options = Options::with_columns(path, 1);
        options.columns = vec![ColumnOptions {
            btree_index: true,
            ..Default::default()
        }];
        // We don't use stats
        options.stats = false;

        let db = Db::open_or_create(&options)?;

        Ok(Self { db: Arc::new(db) })
    }

    fn save_data(&mut self, key: &Key, data: Option<Vec<u8>>) -> bool {
        trace!(?key, "Saving a new record to DB");

        let key: &[u8] = key.borrow();

        let tx = [(PARITY_DB_COLUMN_NAME, key, data)];

        let result = self.db.commit(tx);
        if let Err(ref err) = result {
            debug!(?key, ?err, "DB saving error.");
        }

        result.is_ok()
    }

    pub(crate) fn get(&self, key: &Key) -> Option<Piece> {
        let result = self.db.get(PARITY_DB_COLUMN_NAME, key.borrow());

        match result {
            Ok(Some(data)) => {
                trace!(?key, "Record loaded successfully from DB");

                match data.try_into() {
                    Ok(piece) => Some(piece),
                    Err(err) => {
                        debug!(?key, ?err, "Parity DB record conversion error");

                        None
                    }
                }
            }
            Ok(None) => {
                trace!(?key, "No Parity DB record for given key");

                None
            }
            Err(err) => {
                debug!(?key, ?err, "Parity DB record storage error");

                None
            }
        }
    }

    fn pieces(&self) -> Result<impl Iterator<Item = (Key, Piece)> + '_, Box<dyn Error>> {
        let btree_iter = self.db.iter(PARITY_DB_COLUMN_NAME)?;

        Ok(ParityDbRecordIterator::new(btree_iter)?)
    }
}

/// Parity DB BTree iterator wrapper.
pub struct ParityDbRecordIterator<'a> {
    iter: parity_db::BTreeIterator<'a>,
}

impl<'a> ParityDbRecordIterator<'a> {
    /// Fallible iterator constructor. It requires inner DB BTreeIterator as a parameter.
    pub fn new(mut iter: parity_db::BTreeIterator<'a>) -> parity_db::Result<Self> {
        iter.seek_to_first()?;

        Ok(Self { iter })
    }

    fn next_entry(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        match self.iter.next() {
            Ok(value) => {
                trace!("Parity DB provider iterator succeeded");

                value
            }
            Err(err) => {
                warn!(?err, "Parity DB provider iterator error");

                None
            }
        }
    }
}

impl<'a> Iterator for ParityDbRecordIterator<'a> {
    type Item = (Key, Piece);

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry().and_then(|(k, v)| match v.try_into() {
            Ok(piece) => match k.clone().try_into() {
                Ok(key) => Some((key, piece)),
                Err(err) => {
                    debug!(?k, ?err, "Parity DB key conversion error");

                    None
                }
            },
            Err(err) => {
                warn!(?k, ?err, "Parity DB storage piece conversion error");

                None
            }
        })
    }
}

/// Piece storage with limited size.
pub struct LimitedSizePieceStorageWrapper {
    // Wrapped record storage implementation.
    piece_store: ParityDbPieceStorage,
    // Maintains a heap to limit total item number.
    heap: RecordBinaryHeap,
}

impl LimitedSizePieceStorageWrapper {
    pub fn new(
        piece_store: ParityDbPieceStorage,
        max_items_limit: NonZeroUsize,
        peer_id: PeerId,
    ) -> Self {
        let mut heap = RecordBinaryHeap::new(peer_id, max_items_limit.get());

        match piece_store.pieces() {
            Ok(pieces_iter) => {
                for (key, _) in pieces_iter {
                    let _ = heap.insert(key);
                }

                if heap.size() > 0 {
                    info!(size = heap.size(), "Local piece cache loaded.");
                } else {
                    info!("New local piece cache initialized.");
                }
            }
            Err(err) => {
                warn!(?err, "Local pieces from Parity DB iterator failed.");
            }
        }

        Self { piece_store, heap }
    }
}

impl PieceStorage for LimitedSizePieceStorageWrapper {
    fn should_include_in_storage(&self, key: &Key) -> bool {
        self.heap.should_include_key(key)
    }

    fn add_piece(&mut self, key: Key, piece: Piece) {
        self.piece_store.save_data(&key, Some(piece.into()));

        let evicted_key = self.heap.insert(key);

        if let Some(key) = evicted_key {
            trace!(?key, "Record evicted from cache.");

            self.piece_store.save_data(&key, None);
        }
    }

    fn get_piece(&self, key: &Key) -> Option<Piece> {
        self.piece_store.get(key)
    }
}

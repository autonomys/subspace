use cuckoofilter::CuckooFilter;
use event_listener_primitives::{Bag, HandlerId};
use parking_lot::Mutex;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::fmt::Debug;
use std::sync::Arc;
use subspace_core_primitives::PieceIndex;
use subspace_networking::{
    CuckooFilterDTO, CuckooFilterProvider, Notification, NotificationHandler,
};
use tracing::warn;

type NotificationEventHandler = Bag<NotificationHandler, Notification>;

// TODO: Consider renaming this type.
#[derive(Clone)]
pub struct ArchivalStoragePieces {
    cuckoo_filter: Arc<Mutex<CuckooFilter<DefaultHasher>>>,
    listeners: NotificationEventHandler,
}

impl Debug for ArchivalStoragePieces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchivalStoragePieces")
            .field("cuckoo_filter (len)", &self.cuckoo_filter.lock().len())
            .finish()
    }
}

impl ArchivalStoragePieces {
    pub fn new(capacity: usize) -> Self {
        Self {
            cuckoo_filter: Arc::new(Mutex::new(CuckooFilter::with_capacity(capacity))),
            listeners: Bag::default(),
        }
    }

    pub fn add_pieces(&self, piece_indexes: &[PieceIndex]) {
        let mut cuckoo_filter = self.cuckoo_filter.lock();
        let mut last_error = None;

        for piece_index in piece_indexes {
            if let Err(err) = cuckoo_filter.add(piece_index) {
                last_error.replace(err);
            }
        }
        drop(cuckoo_filter);

        self.listeners.call_simple(&Notification);

        if let Some(err) = last_error {
            warn!(
                ?err,
                "Cuckoo-filter returned an error during piece insertion."
            );
        }
    }

    pub fn delete_pieces(&self, piece_indexes: &[PieceIndex]) {
        let mut cuckoo_filter = self.cuckoo_filter.lock();

        for piece_index in piece_indexes {
            cuckoo_filter.delete(piece_index);
        }
        drop(cuckoo_filter);

        self.listeners.call_simple(&Notification);
    }
}

impl CuckooFilterProvider for ArchivalStoragePieces {
    fn cuckoo_filter(&self) -> CuckooFilterDTO {
        let exported_filter = self.cuckoo_filter.lock().export();

        CuckooFilterDTO {
            values: exported_filter.values,
            length: exported_filter.length as u64,
        }
    }

    fn on_notification(&self, handler: NotificationHandler) -> Option<HandlerId> {
        let handler_id = self.listeners.add(handler);

        Some(handler_id)
    }
}

use cuckoofilter::CuckooFilter;
use event_listener_primitives::{Bag, HandlerId};
use parking_lot::Mutex;
use std::collections::hash_map::DefaultHasher;
use std::sync::Arc;
use subspace_core_primitives::PieceIndex;
use subspace_networking::{
    Notification, NotificationHandler, PeerInfo, PeerInfoProvider, PeerRole,
};

type NotificationEventHandler = Bag<NotificationHandler, Notification>;

pub const DEFAULT_CAPACITY: usize = (1 << 20) - 1;

// TODO: Consider renaming this type.
#[derive(Clone)]
pub struct ArchivalStoragePieces {
    cuckoo_filter: Arc<Mutex<CuckooFilter<DefaultHasher>>>,
    listeners: NotificationEventHandler,
}

impl Default for ArchivalStoragePieces {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl ArchivalStoragePieces {
    pub fn new(capacity: usize) -> Self {
        Self {
            cuckoo_filter: Arc::new(Mutex::new(CuckooFilter::with_capacity(capacity))),
            listeners: Bag::default(),
        }
    }

    pub fn add_pieces(&self, piece_indexes: &[PieceIndex]) -> Result<(), anyhow::Error> {
        let mut cuckoo_filter = self.cuckoo_filter.lock();
        for piece_index in piece_indexes {
            cuckoo_filter
                .add(piece_index)
                .map_err(|err| anyhow::anyhow!("Cuckoo filter error: {}", err,))?;
        }
        drop(cuckoo_filter);

        self.listeners.call_simple(&Notification);

        Ok(())
    }
}

impl PeerInfoProvider for ArchivalStoragePieces {
    fn peer_info(&self) -> PeerInfo {
        let exported_filter = self.cuckoo_filter.lock().export();
        let data = serde_scale::to_vec(&exported_filter).expect("Serialization always works.");

        PeerInfo {
            role: PeerRole::Farmer,
            data: Some(data),
        }
    }

    fn on_notification(&self, handler: NotificationHandler) -> Option<HandlerId> {
        let handler_id = self.listeners.add(handler);

        Some(handler_id)
    }
}

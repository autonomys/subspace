pub mod farmer_piece_cache;
pub mod farmer_piece_getter;
pub mod farmer_provider_record_processor;
pub mod farmer_provider_storage;
pub mod node_piece_getter;
pub mod parity_db_store;
pub mod piece_cache;
pub mod piece_validator;
pub mod readers_and_pieces;
pub mod records_root;

use std::ops::Deref;

/// Joins synchronous join handle on drop
pub(crate) struct JoinOnDrop(Option<std::thread::JoinHandle<()>>);

impl Drop for JoinOnDrop {
    fn drop(&mut self) {
        self.0
            .take()
            .expect("Always called exactly once; qed")
            .join()
            .expect("DSN archiving must not panic");
    }
}

impl JoinOnDrop {
    pub(crate) fn new(handle: std::thread::JoinHandle<()>) -> Self {
        Self(Some(handle))
    }
}

impl Deref for JoinOnDrop {
    type Target = std::thread::JoinHandle<()>;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("Only dropped in Drop impl; qed")
    }
}

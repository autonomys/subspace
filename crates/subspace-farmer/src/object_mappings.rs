#[cfg(test)]
mod tests;

use parity_scale_codec::{Decode, Encode};
use rocksdb::{Options, WriteBatch, DB};
use std::path::Path;
use std::sync::Arc;
use subspace_core_primitives::objects::GlobalObject;
use subspace_core_primitives::Sha256Hash;
use thiserror::Error;

// TODO: Remove once global object mappings are gone
#[derive(Debug, Error)]
pub enum LegacyObjectMappingError {
    #[error("DB error: {0}")]
    Db(rocksdb::Error),
}

/// `ObjectMappings` is a mapping from arbitrary object hash to its location in archived history.
// TODO: Remove once global object mappings are gone
#[derive(Debug, Clone)]
pub struct LegacyObjectMappings {
    db: Arc<DB>,
}

impl LegacyObjectMappings {
    /// Opens or creates a new object mappings database
    pub fn open_or_create<P>(path: P) -> Result<Self, LegacyObjectMappingError>
    where
        P: AsRef<Path>,
    {
        let mut options = Options::default();
        options.create_if_missing(true);
        options.set_unordered_write(true);
        let db = DB::open(&options, path).map_err(LegacyObjectMappingError::Db)?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Retrieve mapping for object
    pub fn retrieve(
        &self,
        object_id: &Sha256Hash,
    ) -> Result<Option<GlobalObject>, LegacyObjectMappingError> {
        Ok(self
            .db
            .get(object_id)
            .map_err(LegacyObjectMappingError::Db)?
            .and_then(|global_object| GlobalObject::decode(&mut global_object.as_ref()).ok()))
    }

    /// Store object mappings in database
    pub fn store(
        &self,
        object_mapping: &[(Sha256Hash, GlobalObject)],
    ) -> Result<(), LegacyObjectMappingError> {
        let mut tmp = Vec::new();

        let mut batch = WriteBatch::default();
        for (object_id, global_object) in object_mapping {
            global_object.encode_to(&mut tmp);
            batch.put(object_id, &tmp);

            tmp.clear();
        }
        self.db.write(batch).map_err(LegacyObjectMappingError::Db)?;

        Ok(())
    }
}

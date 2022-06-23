#[cfg(test)]
mod tests;

use parity_scale_codec::{Decode, Encode};
use rocksdb::DB;
use std::path::Path;
use std::sync::Arc;
use subspace_core_primitives::objects::GlobalObject;
use subspace_core_primitives::Sha256Hash;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ObjectMappingError {
    #[error("DB error: {0}")]
    Db(rocksdb::Error),
}

/// `ObjectMappings` is a mapping from arbitrary object hash to its location in archived history.
#[derive(Debug, Clone)]
pub struct ObjectMappings {
    db: Arc<DB>,
}

impl ObjectMappings {
    /// Opens or creates a new object mappings database
    pub fn open_or_create<P>(path: P) -> Result<Self, ObjectMappingError>
    where
        P: AsRef<Path>,
    {
        let db = DB::open_default(path).map_err(ObjectMappingError::Db)?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Retrieve mapping for object
    pub fn retrieve(
        &self,
        object_id: &Sha256Hash,
    ) -> Result<Option<GlobalObject>, ObjectMappingError> {
        Ok(self
            .db
            .get(object_id)
            .map_err(ObjectMappingError::Db)?
            .and_then(|global_object| GlobalObject::decode(&mut global_object.as_ref()).ok()))
    }

    /// Store object mappings in database
    pub fn store(
        &self,
        object_mapping: &[(Sha256Hash, GlobalObject)],
    ) -> Result<(), ObjectMappingError> {
        let mut tmp = Vec::new();

        for (object_id, global_object) in object_mapping {
            global_object.encode_to(&mut tmp);
            self.db
                .put(object_id, &tmp)
                .map_err(ObjectMappingError::Db)?;

            tmp.clear();
        }

        Ok(())
    }
}

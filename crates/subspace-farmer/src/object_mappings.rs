#[cfg(test)]
mod tests;

use crate::db::MapDb;
use parity_scale_codec::{Decode, Encode};
use std::path::Path;
use std::sync::Arc;
use subspace_core_primitives::objects::GlobalObject;
use subspace_core_primitives::Sha256Hash;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ObjectMappingError {
    #[error("DB error: {0}")]
    Db(parity_db::Error),
}

/// `ObjectMappings` is a mapping from arbitrary object hash to its location in archived history.
#[derive(Debug, Clone)]
pub struct ObjectMappings {
    db: Arc<MapDb>,
}

impl ObjectMappings {
    /// Opens or creates a new object mappings database
    pub fn open_or_create<B: AsRef<Path>>(base_directory: B) -> Result<Self, ObjectMappingError> {
        let db = MapDb::object_mappings_open(base_directory.as_ref().join("object-mappings"))
            .map_err(ObjectMappingError::Db)?;

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
        let tx = object_mapping
            .iter()
            .map(|(object_id, global_object)| (object_id, Some(global_object.encode())));

        self.db.commit(tx).map_err(ObjectMappingError::Db)
    }
}

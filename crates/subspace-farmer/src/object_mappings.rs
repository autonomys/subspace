#[cfg(test)]
mod tests;

use log::error;
use parity_scale_codec::{Decode, Encode};
use rocksdb::DB;
use std::path::Path;
use std::sync::Arc;
use subspace_archiving::archiver::ArchivedSegment;
use subspace_core_primitives::objects::{GlobalObject, PieceObject, PieceObjectMapping};
use subspace_core_primitives::Sha256Hash;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ObjectMappingError {
    #[error("DB error: {0}")]
    Db(rocksdb::Error),
}

#[derive(Debug, Clone)]
pub struct ObjectMappings {
    db: Arc<DB>,
}

impl ObjectMappings {
    /// Opens or creates a new object mappings database
    pub fn open_or_create<B: AsRef<Path>>(base_directory: B) -> Result<Self, ObjectMappingError> {
        let db = DB::open_default(base_directory.as_ref().join("object-mappings"))
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

    // TODO: This assumes fixed size segments, which might not be the case
    pub fn update_with_info_from_archiver(
        &self,
        mut archived_segments_receiver: tokio::sync::broadcast::Receiver<Vec<ArchivedSegment>>,
        merkle_num_leaves: u64,
    ) {
        let runtime_handle = tokio::runtime::Handle::current();
        while let Ok(archived_segments) = runtime_handle.block_on(archived_segments_receiver.recv())
        {
            for archived_segment in archived_segments {
                let ArchivedSegment {
                    root_block,
                    object_mapping,
                    ..
                } = archived_segment;
                let piece_index_offset = merkle_num_leaves * root_block.segment_index();
                let object_mapping =
                    create_global_object_mapping(piece_index_offset, object_mapping);
                if let Err(error) = self.store(&object_mapping) {
                    error!("Failed to store object mappings for pieces: {}", error);
                }
            }
        }
    }
}

fn create_global_object_mapping(
    piece_index_offset: u64,
    object_mapping: Vec<PieceObjectMapping>,
) -> Vec<(Sha256Hash, GlobalObject)> {
    object_mapping
        .iter()
        .enumerate()
        .flat_map(move |(position, object_mapping)| {
            object_mapping.objects.iter().map(move |piece_object| {
                let PieceObject::V0 { hash, offset } = piece_object;
                (
                    *hash,
                    GlobalObject::V0 {
                        piece_index: piece_index_offset + position as u64,
                        offset: *offset,
                    },
                )
            })
        })
        .collect()
}

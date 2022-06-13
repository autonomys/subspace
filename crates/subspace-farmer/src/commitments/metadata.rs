use crate::commitments::CommitmentError;
use rocksdb::DB;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use subspace_core_primitives::Salt;

const COMMITMENTS_KEY: &[u8] = b"commitments";

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum CommitmentStatus {
    /// In-progress commitment to the part of the plot
    InProgress,
    /// Commitment to the whole plot and not some in-progress partial commitment
    Created,
}

#[derive(Debug)]
pub(super) struct CommitmentMetadata {
    db: DB,
}

impl CommitmentMetadata {
    pub(super) fn new(path: PathBuf) -> Result<Self, CommitmentError> {
        let db = DB::open_default(path).map_err(CommitmentError::MetadataDb)?;

        Ok(Self { db })
    }

    pub(super) fn mutate<F>(&mut self, mut callback: F) -> Result<(), CommitmentError>
    where
        F: FnMut(&mut HashMap<Salt, CommitmentStatus>) -> Result<(), CommitmentError>,
    {
        let mut metadata = self
            .db
            .get(COMMITMENTS_KEY)
            .map_err(CommitmentError::MetadataDb)?
            .map(|bytes| {
                serde_json::from_slice::<HashMap<String, CommitmentStatus>>(&bytes)
                    .unwrap()
                    .into_iter()
                    .map(|(salt, status)| (hex::decode(salt).unwrap().try_into().unwrap(), status))
                    .collect()
            })
            .unwrap_or_default();

        callback(&mut metadata)?;

        let metadata: HashMap<String, CommitmentStatus> = metadata
            .iter()
            .map(|(salt, status)| (hex::encode(salt), *status))
            .collect();

        self.db
            .put(COMMITMENTS_KEY, &serde_json::to_vec(&metadata).unwrap())
            .map_err(CommitmentError::MetadataDb)
    }
}

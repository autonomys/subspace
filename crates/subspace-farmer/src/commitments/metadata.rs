use crate::commitments::CommitmentError;
use parity_db::Db;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use subspace_core_primitives::Salt;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum CommitmentStatus {
    /// In-progress commitment to the part of the plot
    InProgress,
    /// Commitment to the whole plot and not some in-progress partial commitment
    Created,
}

pub(super) struct CommitmentMetadata {
    db: Db,
}

impl std::fmt::Debug for CommitmentMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitmentMetadata").finish_non_exhaustive()
    }
}

impl CommitmentMetadata {
    const COMMITMENTS_KEY: &[u8] = b"commitments";

    pub(super) fn new(path: PathBuf) -> Result<Self, CommitmentError> {
        let db = Db::with_columns(&path, 1).map_err(CommitmentError::MetadataDb)?;
        Ok(Self { db })
    }

    pub(super) fn mutate<F>(&mut self, mut callback: F) -> Result<(), CommitmentError>
    where
        F: FnMut(&mut HashMap<Salt, CommitmentStatus>) -> Result<(), CommitmentError>,
    {
        let mut metadata = self
            .db
            .get(0, Self::COMMITMENTS_KEY)
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
            .commit(std::iter::once((
                0,
                Self::COMMITMENTS_KEY,
                Some(serde_json::to_vec(&metadata).unwrap()),
            )))
            .map_err(CommitmentError::MetadataDb)
    }
}

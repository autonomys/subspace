use crate::Salt;
use async_std::io;
use async_std::path::PathBuf;
use log::warn;
use rocksdb::{DBWithThreadMode, SingleThreaded, DB};
use serde::ser::SerializeStruct;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub(super) enum DbError {
    #[error("RocksDB database opening error: {0}")]
    RocksDb(rocksdb::Error),
    #[error("Metadata file error: {0}")]
    Metadata(io::Error),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum CommitmentStatus {
    /// In-progress commitment to the part of the plot
    InProgress,
    /// Commitment to the whole plot and not some in-progress partial commitment
    Created,
}

#[derive(Debug, Default, Clone)]
struct Metadata {
    pub(super) commitments: HashMap<Salt, CommitmentStatus>,
}

impl Serialize for Metadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut metadata = serializer.serialize_struct("Metadata", 1)?;
        metadata.serialize_field(
            "commitments",
            &self
                .commitments
                .iter()
                .map(|(salt, commitment_status)| (hex::encode(salt), *commitment_status))
                .collect::<HashMap<_, _>>(),
        )?;
        metadata.end()
    }
}

impl<'de> Deserialize<'de> for Metadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct S {
            commitments: HashMap<String, CommitmentStatus>,
        }

        S::deserialize(deserializer).and_then(|s| {
            Ok(Metadata {
                commitments: s
                    .commitments
                    .into_iter()
                    .map(|(salt, commitment_status)| {
                        let salt_bytes = hex::decode(salt)?;
                        Ok((salt_bytes[..].try_into()?, commitment_status))
                    })
                    .collect::<Result<HashMap<_, _>, Box<dyn std::error::Error>>>()
                    .map_err(|error| {
                        de::Error::custom(format!("Failed to decode salt: {}", error))
                    })?,
            })
        })
    }
}

#[derive(Debug)]
pub(super) struct Commitments {
    path: PathBuf,
    databases: HashMap<Salt, Arc<DBWithThreadMode<SingleThreaded>>>,
    metadata: Metadata,
}

impl Commitments {
    pub(super) async fn new(path: PathBuf) -> io::Result<Self> {
        let mut metadata: Metadata = async_std::fs::read_to_string(path.join("metadata.json"))
            .await
            .ok()
            .and_then(|metadata| serde_json::from_str(&metadata).ok())
            .unwrap_or_default();

        // Remove unfinished commitments from the previous run
        for (salt, _status) in metadata
            .commitments
            .drain_filter(|_salt, status| *status != CommitmentStatus::Created)
        {
            let commitment_path = path.join(hex::encode(salt));
            if let Err(error) = async_std::fs::remove_dir_all(&commitment_path).await {
                warn!(
                    "Failed to remove commitment at {:?}: {}",
                    commitment_path, error
                );
            }
        }

        Ok(Self {
            path,
            databases: HashMap::new(),
            metadata,
        })
    }

    pub(super) fn get_existing_commitments(&self) -> impl Iterator<Item = &Salt> {
        self.metadata.commitments.keys()
    }

    /// Get existing database or create an empty one with [`CommitmentStatus::InProgress`] status
    pub(super) async fn get_or_create_db(
        &mut self,
        salt: Salt,
    ) -> Result<Arc<DBWithThreadMode<SingleThreaded>>, DbError> {
        match self.databases.entry(salt) {
            Entry::Occupied(entry) => Ok(Arc::clone(entry.get())),
            Entry::Vacant(entry) => {
                let db_path = self.path.join(hex::encode(salt));
                let db = Arc::new(
                    tokio::task::spawn_blocking(move || DB::open_default(db_path))
                        .await
                        .unwrap()
                        .map_err(DbError::RocksDb)?,
                );

                entry.insert(Arc::clone(&db));
                self.metadata
                    .commitments
                    .entry(salt)
                    .or_insert(CommitmentStatus::InProgress);
                async_std::fs::write(
                    self.path.join("metadata.json"),
                    serde_json::to_string(&self.metadata).unwrap(),
                )
                .await
                .map_err(DbError::Metadata)?;

                Ok(db)
            }
        }
    }

    /// Transition database associated with `salt` to created status, meaning that it represents the
    /// whole plot and not some in-progress partial commitment
    pub(super) async fn finish_commitment_creation(&mut self, salt: Salt) -> io::Result<()> {
        self.metadata
            .commitments
            .insert(salt, CommitmentStatus::Created);
        async_std::fs::write(
            self.path.join("metadata.json"),
            serde_json::to_string(&self.metadata).unwrap(),
        )
        .await
    }

    /// Removes commitment from disk
    pub(super) async fn remove_commitment(&mut self, salt: Salt) -> io::Result<()> {
        self.metadata.commitments.remove(&salt);
        let db_path = self.path.join(hex::encode(salt));
        let database = self.databases.remove(&salt);
        tokio::task::spawn_blocking(move || {
            drop(database);
            std::fs::remove_dir_all(db_path)
        })
        .await
        .unwrap()?;

        Ok(())
    }
}

use crate::single_plot_farm::{SinglePlotFarmId, SinglePlotPieceGetter};
use crate::ws_rpc_server::PieceGetter;
use derive_more::From;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::{fmt, fs, io};
use std_semaphore::{Semaphore, SemaphoreGuard};
use subspace_core_primitives::{Piece, PieceIndex, PieceIndexHash};
use ulid::Ulid;

/// Abstraction that can get pieces out of internal plots
#[derive(Debug, Clone)]
pub struct SingleDiskFarmPieceGetter {
    single_plot_piece_getters: Vec<SinglePlotPieceGetter>,
}

impl SingleDiskFarmPieceGetter {
    /// Create new piece getter for many single plot farms
    pub fn new(single_plot_piece_getters: Vec<SinglePlotPieceGetter>) -> Self {
        Self {
            single_plot_piece_getters,
        }
    }
}

impl PieceGetter for SingleDiskFarmPieceGetter {
    fn get_piece(
        &self,
        piece_index: PieceIndex,
        piece_index_hash: PieceIndexHash,
    ) -> Option<Piece> {
        self.single_plot_piece_getters
            .iter()
            .find_map(|single_plot_piece_getter| {
                single_plot_piece_getter.get_piece(piece_index, piece_index_hash)
            })
    }
}

/// Semaphore that limits disk access concurrency in strategic places to the number specified during
/// initialization
#[derive(Clone)]
pub struct SingleDiskSemaphore {
    inner: Arc<Semaphore>,
}

impl fmt::Debug for SingleDiskSemaphore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingleDiskSemaphore").finish()
    }
}

impl SingleDiskSemaphore {
    /// Create new semaphore for limiting concurrency of the major processes working with the same
    /// disk
    pub fn new(concurrency: u16) -> Self {
        Self {
            inner: Arc::new(Semaphore::new(concurrency as isize)),
        }
    }

    /// Acquire access, will block current thread until previously acquired guards are dropped and
    /// access is released
    pub fn acquire(&self) -> SemaphoreGuard<'_> {
        self.inner.access()
    }
}

/// An identifier for single plot farm, can be used for in logs, thread names, etc.
#[derive(
    Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, From,
)]
pub struct SingleDiskFarmId(Ulid);

impl fmt::Display for SingleDiskFarmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Metadata for `SingleDiskFarm`, stores important information about the contents of the farm
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SingleDiskFarmMetadata {
    /// V0 of the metadata
    #[serde(rename_all = "camelCase")]
    V0 {
        /// ID of the farm
        id: SingleDiskFarmId,
        /// Genesis hash of the chain used for farm creation
        #[serde(with = "hex::serde")]
        genesis_hash: [u8; 32],
        /// Allocated space in bytes used during latest start
        allocated_space: u64,
        /// IDs of single plot farms contained within
        single_plot_farms: Vec<SinglePlotFarmId>,
    },
}

impl SingleDiskFarmMetadata {
    const FILE_NAME: &'static str = "single_disk_farm.json";

    /// Load `SingleDiskFarm` metadata from path where metadata is supposed to be stored, `None`
    /// means no metadata was found, happens during first start.
    pub fn load_from(metadata_path: &Path) -> io::Result<Option<Self>> {
        let bytes = match fs::read(metadata_path.join(Self::FILE_NAME)) {
            Ok(bytes) => bytes,
            Err(error) => {
                return if error.kind() == io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(error)
                };
            }
        };

        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    /// Store `SingleDiskFarm` metadata to path where metadata is supposed to be stored so it can be
    /// loaded again upon restart.
    pub fn store_to(&self, metadata_path: &Path) -> io::Result<()> {
        fs::write(
            metadata_path.join(Self::FILE_NAME),
            serde_json::to_vec(self).expect("Metadata serialization never fails; qed"),
        )
    }
}

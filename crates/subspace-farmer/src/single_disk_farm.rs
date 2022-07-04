use crate::single_plot_farm::SinglePlotPieceGetter;
use crate::ws_rpc_server::PieceGetter;
use std::fmt;
use std::sync::Arc;
use std_semaphore::{Semaphore, SemaphoreGuard};
use subspace_core_primitives::{Piece, PieceIndex, PieceIndexHash};

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

//! CUDA GPU records encoder

use crate::plotter::gpu::GpuRecordsEncoder;
use async_lock::Mutex as AsyncMutex;
use parking_lot::Mutex;
use rayon::{ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use subspace_core_primitives::pieces::{PieceOffset, Record};
use subspace_core_primitives::sectors::SectorId;
use subspace_farmer_components::plotting::RecordsEncoder;
use subspace_farmer_components::sector::SectorContentsMap;
use subspace_proof_of_space_gpu::cuda::CudaDevice;

/// CUDA implementation of [`GpuRecordsEncoder`]
#[derive(Debug)]
pub struct CudaRecordsEncoder {
    cuda_device: CudaDevice,
    thread_pool: ThreadPool,
    global_mutex: Arc<AsyncMutex<()>>,
}

impl GpuRecordsEncoder for CudaRecordsEncoder {
    const TYPE: &'static str = "cuda";
}

impl RecordsEncoder for CudaRecordsEncoder {
    fn encode_records(
        &mut self,
        sector_id: &SectorId,
        records: &mut [Record],
        abort_early: &AtomicBool,
    ) -> anyhow::Result<SectorContentsMap> {
        let pieces_in_sector = records
            .len()
            .try_into()
            .map_err(|error| anyhow::anyhow!("Failed to convert pieces in sector: {error}"))?;
        let mut sector_contents_map = SectorContentsMap::new(pieces_in_sector);

        self.thread_pool.install(|| {
            let iter = Mutex::new(
                (PieceOffset::ZERO..)
                    .zip(records.iter_mut())
                    .zip(sector_contents_map.iter_record_bitfields_mut()),
            );
            let plotting_error = Mutex::new(None::<String>);

            rayon::scope(|scope| {
                scope.spawn_broadcast(|_scope, _ctx| loop {
                    // Take mutex briefly to make sure encoding is allowed right now
                    self.global_mutex.lock_blocking();

                    // This instead of `while` above because otherwise mutex will be held for the
                    // duration of the loop and will limit concurrency to 1 record
                    let Some(((piece_offset, record), mut encoded_chunks_used)) =
                        iter.lock().next()
                    else {
                        return;
                    };
                    let pos_seed = sector_id.derive_evaluation_seed(piece_offset);

                    if let Err(error) = self.cuda_device.generate_and_encode_pospace(
                        &pos_seed,
                        record,
                        encoded_chunks_used.iter_mut(),
                    ) {
                        plotting_error.lock().replace(error);
                        return;
                    }

                    if abort_early.load(Ordering::Relaxed) {
                        return;
                    }
                });
            });

            let plotting_error = plotting_error.lock().take();
            if let Some(error) = plotting_error {
                return Err(anyhow::Error::msg(error));
            }

            Ok(())
        })?;

        Ok(sector_contents_map)
    }
}

impl CudaRecordsEncoder {
    /// Create new instance
    pub fn new(
        cuda_device: CudaDevice,
        global_mutex: Arc<AsyncMutex<()>>,
    ) -> Result<Self, ThreadPoolBuildError> {
        let id = cuda_device.id();
        let thread_pool = ThreadPoolBuilder::new()
            .thread_name(move |thread_index| format!("cuda-{id}.{thread_index}"))
            // Make sure there is overlap between records, so GPU is almost always busy
            .num_threads(2)
            .build()?;

        Ok(Self {
            cuda_device,
            thread_pool,
            global_mutex,
        })
    }
}

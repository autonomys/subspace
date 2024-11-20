//! CUDA GPU records encoder

use crate::plotter::gpu::GpuRecordsEncoder;
use async_lock::Mutex as AsyncMutex;
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

        for ((piece_offset, record), mut encoded_chunks_used) in (PieceOffset::ZERO..)
            .zip(records.iter_mut())
            .zip(sector_contents_map.iter_record_bitfields_mut())
        {
            // Take mutex briefly to make sure encoding is allowed right now
            self.global_mutex.lock_blocking();

            let pos_seed = sector_id.derive_evaluation_seed(piece_offset);

            self.cuda_device
                .generate_and_encode_pospace(&pos_seed, record, encoded_chunks_used.iter_mut())
                .map_err(anyhow::Error::msg)?;

            if abort_early.load(Ordering::Relaxed) {
                break;
            }
        }

        Ok(sector_contents_map)
    }
}

impl CudaRecordsEncoder {
    /// Create new instance
    pub fn new(cuda_device: CudaDevice, global_mutex: Arc<AsyncMutex<()>>) -> Self {
        Self {
            cuda_device,
            global_mutex,
        }
    }
}

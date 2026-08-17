//! wgpu GPU records encoder

use crate::plotter::gpu::GpuRecordsEncoder;
use async_lock::Mutex as AsyncMutex;
use parking_lot::Mutex;
use rayon::{ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder, current_thread_index};
use std::fmt;
use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use subspace_core_primitives::pieces::{PieceOffset, Record};
use subspace_core_primitives::sectors::SectorId;
use subspace_farmer_components::plotting::RecordsEncoder;
use subspace_farmer_components::sector::SectorContentsMap;
use subspace_proof_of_space_wgpu::WgpuDevice;

/// wgpu implementation of [`GpuRecordsEncoder`]
pub struct WgpuRecordsEncoder {
    devices: Vec<Mutex<WgpuDevice>>,
    thread_pool: ThreadPool,
    global_mutex: Arc<AsyncMutex<()>>,
}

impl fmt::Debug for WgpuRecordsEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgpuRecordsEncoder").finish_non_exhaustive()
    }
}

impl GpuRecordsEncoder for WgpuRecordsEncoder {
    const TYPE: &'static str = "wgpu";
}

impl RecordsEncoder for WgpuRecordsEncoder {
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

        {
            let iter = Mutex::new(
                (PieceOffset::ZERO..)
                    .zip(records.iter_mut())
                    .zip(sector_contents_map.iter_record_bitfields_mut()),
            );
            let plotting_error = Mutex::new(None::<String>);

            self.thread_pool.scope(|scope| {
                scope.spawn_broadcast(|_scope, _ctx| {
                    // One device (GPU queue) per pool thread, so this lock is always uncontended
                    let thread_index = current_thread_index().unwrap_or_default();
                    let Some(device) = self.devices.get(thread_index) else {
                        return;
                    };
                    let mut device = device
                        .try_lock()
                        .expect("1:1 mapping between threads and devices; qed");

                    loop {
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

                        if let Err(error) = device.generate_and_encode_pospace(
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
                    }
                });
            });

            let plotting_error = plotting_error.lock().take();
            if let Some(error) = plotting_error {
                return Err(anyhow::Error::msg(error));
            }
        }

        Ok(sector_contents_map)
    }
}

impl WgpuRecordsEncoder {
    /// Create new instance.
    ///
    /// One thread is spawned per device (GPU queue), so records encode concurrently across queues.
    pub fn new(
        id: u32,
        devices: Vec<WgpuDevice>,
        global_mutex: Arc<AsyncMutex<()>>,
    ) -> Result<Self, ThreadPoolBuildError> {
        let thread_name = move |thread_index| format!("wgpu-{id:02}.{thread_index:02}");
        // TODO: remove this panic handler when rayon logs panic_info
        // https://github.com/rayon-rs/rayon/issues/1208
        let panic_handler = move |panic_info| {
            if let Some(index) = current_thread_index() {
                eprintln!("panic on thread {}: {:?}", thread_name(index), panic_info);
            } else {
                // We want to guarantee exit, rather than panicking in a panic handler.
                eprintln!("rayon panic handler called on non-rayon thread: {panic_info:?}");
            }
            exit(1);
        };

        let thread_pool = ThreadPoolBuilder::new()
            .thread_name(thread_name)
            .panic_handler(panic_handler)
            .num_threads(devices.len())
            .build()?;

        Ok(Self {
            devices: devices.into_iter().map(Mutex::new).collect(),
            thread_pool,
            global_mutex,
        })
    }
}

//! CPU plotter

pub mod metrics;

use crate::plotter::cpu::metrics::CpuPlotterMetrics;
use crate::plotter::{Plotter, SectorPlottingProgress};
use crate::thread_pool_manager::PlottingThreadPoolManager;
use async_lock::{Mutex as AsyncMutex, Semaphore, SemaphoreGuardArc};
use async_trait::async_trait;
use bytes::Bytes;
use event_listener_primitives::{Bag, HandlerId};
use futures::channel::mpsc;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, Sink, SinkExt, StreamExt, select, stream};
use prometheus_client::registry::Registry;
use std::any::type_name;
use std::error::Error;
use std::fmt;
use std::future::pending;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Instant;
use subspace_core_primitives::PublicKey;
use subspace_core_primitives::sectors::SectorIndex;
use subspace_data_retrieval::piece_getter::PieceGetter;
use subspace_erasure_coding::ErasureCoding;
use subspace_farmer_components::FarmerProtocolInfo;
use subspace_farmer_components::plotting::{
    CpuRecordsEncoder, DownloadSectorOptions, EncodeSectorOptions, PlottingError, download_sector,
    encode_sector, write_sector,
};
use subspace_kzg::Kzg;
use subspace_process::AsyncJoinOnDrop;
use subspace_proof_of_space::Table;
use tokio::task::yield_now;
use tracing::{Instrument, warn};

/// Type alias used for event handlers
pub type HandlerFn3<A, B, C> = Arc<dyn Fn(&A, &B, &C) + Send + Sync + 'static>;
type Handler3<A, B, C> = Bag<HandlerFn3<A, B, C>, A, B, C>;

#[derive(Default, Debug)]
struct Handlers {
    plotting_progress: Handler3<PublicKey, SectorIndex, SectorPlottingProgress>,
}

/// CPU plotter
pub struct CpuPlotter<PG, PosTable> {
    piece_getter: PG,
    downloading_semaphore: Arc<Semaphore>,
    plotting_thread_pool_manager: PlottingThreadPoolManager,
    record_encoding_concurrency: NonZeroUsize,
    global_mutex: Arc<AsyncMutex<()>>,
    kzg: Kzg,
    erasure_coding: ErasureCoding,
    handlers: Arc<Handlers>,
    tasks_sender: mpsc::Sender<AsyncJoinOnDrop<()>>,
    _background_tasks: AsyncJoinOnDrop<()>,
    abort_early: Arc<AtomicBool>,
    metrics: Option<Arc<CpuPlotterMetrics>>,
    _phantom: PhantomData<PosTable>,
}

impl<PG, PosTable> fmt::Debug for CpuPlotter<PG, PosTable> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpuPlotter").finish_non_exhaustive()
    }
}

impl<PG, PosTable> Drop for CpuPlotter<PG, PosTable> {
    #[inline]
    fn drop(&mut self) {
        self.abort_early.store(true, Ordering::Release);
        self.tasks_sender.close_channel();
    }
}

#[async_trait]
impl<PG, PosTable> Plotter for CpuPlotter<PG, PosTable>
where
    PG: PieceGetter + Clone + Send + Sync + 'static,
    PosTable: Table,
{
    async fn has_free_capacity(&self) -> Result<bool, String> {
        Ok(self.downloading_semaphore.try_acquire().is_some())
    }

    async fn plot_sector(
        &self,
        public_key: PublicKey,
        sector_index: SectorIndex,
        farmer_protocol_info: FarmerProtocolInfo,
        pieces_in_sector: u16,
        replotting: bool,
        progress_sender: mpsc::Sender<SectorPlottingProgress>,
    ) {
        let start = Instant::now();

        // Done outside the future below as a backpressure, ensuring that it is not possible to
        // schedule unbounded number of plotting tasks
        let downloading_permit = self.downloading_semaphore.acquire_arc().await;

        self.plot_sector_internal(
            start,
            downloading_permit,
            public_key,
            sector_index,
            farmer_protocol_info,
            pieces_in_sector,
            replotting,
            progress_sender,
        )
        .await
    }

    async fn try_plot_sector(
        &self,
        public_key: PublicKey,
        sector_index: SectorIndex,
        farmer_protocol_info: FarmerProtocolInfo,
        pieces_in_sector: u16,
        replotting: bool,
        progress_sender: mpsc::Sender<SectorPlottingProgress>,
    ) -> bool {
        let start = Instant::now();

        let Some(downloading_permit) = self.downloading_semaphore.try_acquire_arc() else {
            return false;
        };

        self.plot_sector_internal(
            start,
            downloading_permit,
            public_key,
            sector_index,
            farmer_protocol_info,
            pieces_in_sector,
            replotting,
            progress_sender,
        )
        .await;

        true
    }
}

impl<PG, PosTable> CpuPlotter<PG, PosTable>
where
    PG: PieceGetter + Clone + Send + Sync + 'static,
    PosTable: Table,
{
    /// Create new instance
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        piece_getter: PG,
        downloading_semaphore: Arc<Semaphore>,
        plotting_thread_pool_manager: PlottingThreadPoolManager,
        record_encoding_concurrency: NonZeroUsize,
        global_mutex: Arc<AsyncMutex<()>>,
        kzg: Kzg,
        erasure_coding: ErasureCoding,
        registry: Option<&mut Registry>,
    ) -> Self {
        let (tasks_sender, mut tasks_receiver) = mpsc::channel(1);

        // Basically runs plotting tasks in the background and allows to abort on drop
        let background_tasks = AsyncJoinOnDrop::new(
            tokio::spawn(async move {
                let background_tasks = FuturesUnordered::new();
                let mut background_tasks = pin!(background_tasks);
                // Just so that `FuturesUnordered` will never end
                background_tasks.push(AsyncJoinOnDrop::new(tokio::spawn(pending::<()>()), true));

                loop {
                    select! {
                        maybe_background_task = tasks_receiver.next().fuse() => {
                            let Some(background_task) = maybe_background_task else {
                                break;
                            };

                            background_tasks.push(background_task);
                        },
                        _ = background_tasks.select_next_some() => {
                            // Nothing to do
                        }
                    }
                }
            }),
            true,
        );

        let abort_early = Arc::new(AtomicBool::new(false));
        let metrics = registry.map(|registry| {
            Arc::new(CpuPlotterMetrics::new(
                registry,
                type_name::<PosTable>(),
                plotting_thread_pool_manager.thread_pool_pairs(),
            ))
        });

        Self {
            piece_getter,
            downloading_semaphore,
            plotting_thread_pool_manager,
            record_encoding_concurrency,
            global_mutex,
            kzg,
            erasure_coding,
            handlers: Arc::default(),
            tasks_sender,
            _background_tasks: background_tasks,
            abort_early,
            metrics,
            _phantom: PhantomData,
        }
    }

    /// Subscribe to plotting progress notifications
    pub fn on_plotting_progress(
        &self,
        callback: HandlerFn3<PublicKey, SectorIndex, SectorPlottingProgress>,
    ) -> HandlerId {
        self.handlers.plotting_progress.add(callback)
    }

    #[allow(clippy::too_many_arguments)]
    async fn plot_sector_internal<PS>(
        &self,
        start: Instant,
        downloading_permit: SemaphoreGuardArc,
        public_key: PublicKey,
        sector_index: SectorIndex,
        farmer_protocol_info: FarmerProtocolInfo,
        pieces_in_sector: u16,
        replotting: bool,
        mut progress_sender: PS,
    ) where
        PS: Sink<SectorPlottingProgress> + Unpin + Send + 'static,
        PS::Error: Error,
    {
        if let Some(metrics) = &self.metrics {
            metrics.sector_plotting.inc();
        }

        let progress_updater = ProgressUpdater {
            public_key,
            sector_index,
            handlers: Arc::clone(&self.handlers),
            metrics: self.metrics.clone(),
        };

        let plotting_fut = {
            let piece_getter = self.piece_getter.clone();
            let plotting_thread_pool_manager = self.plotting_thread_pool_manager.clone();
            let record_encoding_concurrency = self.record_encoding_concurrency;
            let global_mutex = Arc::clone(&self.global_mutex);
            let kzg = self.kzg.clone();
            let erasure_coding = self.erasure_coding.clone();
            let abort_early = Arc::clone(&self.abort_early);
            let metrics = self.metrics.clone();

            async move {
                // Downloading
                let downloaded_sector = {
                    if !progress_updater
                        .update_progress_and_events(
                            &mut progress_sender,
                            SectorPlottingProgress::Downloading,
                        )
                        .await
                    {
                        return;
                    }

                    // Take mutex briefly to make sure plotting is allowed right now
                    global_mutex.lock().await;

                    let downloading_start = Instant::now();

                    let downloaded_sector_fut = download_sector(DownloadSectorOptions {
                        public_key: &public_key,
                        sector_index,
                        piece_getter: &piece_getter,
                        farmer_protocol_info,
                        kzg: &kzg,
                        erasure_coding: &erasure_coding,
                        pieces_in_sector,
                    });

                    let downloaded_sector = match downloaded_sector_fut.await {
                        Ok(downloaded_sector) => downloaded_sector,
                        Err(error) => {
                            warn!(%error, "Failed to download sector");

                            progress_updater
                                .update_progress_and_events(
                                    &mut progress_sender,
                                    SectorPlottingProgress::Error {
                                        error: format!("Failed to download sector: {error}"),
                                    },
                                )
                                .await;

                            return;
                        }
                    };

                    if !progress_updater
                        .update_progress_and_events(
                            &mut progress_sender,
                            SectorPlottingProgress::Downloaded(downloading_start.elapsed()),
                        )
                        .await
                    {
                        return;
                    }

                    downloaded_sector
                };

                // Plotting
                let (sector, plotted_sector) = {
                    let thread_pools = plotting_thread_pool_manager.get_thread_pools().await;
                    if let Some(metrics) = &metrics {
                        metrics.plotting_capacity_used.inc();
                    }

                    // Give a chance to interrupt plotting if necessary
                    yield_now().await;

                    if !progress_updater
                        .update_progress_and_events(
                            &mut progress_sender,
                            SectorPlottingProgress::Encoding,
                        )
                        .await
                    {
                        if let Some(metrics) = &metrics {
                            metrics.plotting_capacity_used.dec();
                        }
                        return;
                    }

                    let encoding_start = Instant::now();

                    let plotting_result = tokio::task::block_in_place(move || {
                        let thread_pool = if replotting {
                            &thread_pools.replotting
                        } else {
                            &thread_pools.plotting
                        };

                        let encoded_sector = thread_pool.install(|| {
                            let mut generators = (0..record_encoding_concurrency.get())
                                .map(|_| PosTable::generator())
                                .collect::<Vec<_>>();
                            let mut records_encoder = CpuRecordsEncoder::<PosTable>::new(
                                &mut generators,
                                &erasure_coding,
                                &global_mutex,
                            );

                            encode_sector(
                                downloaded_sector,
                                EncodeSectorOptions {
                                    sector_index,
                                    records_encoder: &mut records_encoder,
                                    abort_early: &abort_early,
                                },
                            )
                        })?;

                        if abort_early.load(Ordering::Acquire) {
                            return Err(PlottingError::AbortEarly);
                        }

                        drop(thread_pools);

                        let mut sector = Vec::new();

                        write_sector(&encoded_sector, &mut sector)?;

                        Ok((sector, encoded_sector.plotted_sector))
                    });

                    if let Some(metrics) = &metrics {
                        metrics.plotting_capacity_used.dec();
                    }

                    match plotting_result {
                        Ok(plotting_result) => {
                            if !progress_updater
                                .update_progress_and_events(
                                    &mut progress_sender,
                                    SectorPlottingProgress::Encoded(encoding_start.elapsed()),
                                )
                                .await
                            {
                                return;
                            }

                            plotting_result
                        }
                        Err(PlottingError::AbortEarly) => {
                            return;
                        }
                        Err(error) => {
                            progress_updater
                                .update_progress_and_events(
                                    &mut progress_sender,
                                    SectorPlottingProgress::Error {
                                        error: format!("Failed to encode sector: {error}"),
                                    },
                                )
                                .await;

                            return;
                        }
                    }
                };

                progress_updater
                    .update_progress_and_events(
                        &mut progress_sender,
                        SectorPlottingProgress::Finished {
                            plotted_sector,
                            time: start.elapsed(),
                            sector: Box::pin({
                                let mut sector = Some(Ok(Bytes::from(sector)));

                                stream::poll_fn(move |_cx| {
                                    // Just so that permit is dropped with stream itself
                                    let _downloading_permit = &downloading_permit;

                                    Poll::Ready(sector.take())
                                })
                            }),
                        },
                    )
                    .await;
            }
        };

        // Spawn a separate task such that `block_in_place` inside will not affect anything else
        let plotting_task =
            AsyncJoinOnDrop::new(tokio::spawn(plotting_fut.in_current_span()), true);
        if let Err(error) = self.tasks_sender.clone().send(plotting_task).await {
            warn!(%error, "Failed to send plotting task");

            let progress = SectorPlottingProgress::Error {
                error: format!("Failed to send plotting task: {error}"),
            };

            self.handlers
                .plotting_progress
                .call_simple(&public_key, &sector_index, &progress);
        }
    }
}

struct ProgressUpdater {
    public_key: PublicKey,
    sector_index: SectorIndex,
    handlers: Arc<Handlers>,
    metrics: Option<Arc<CpuPlotterMetrics>>,
}

impl ProgressUpdater {
    /// Returns `true` on success and `false` if progress receiver channel is gone
    async fn update_progress_and_events<PS>(
        &self,
        progress_sender: &mut PS,
        progress: SectorPlottingProgress,
    ) -> bool
    where
        PS: Sink<SectorPlottingProgress> + Unpin,
        PS::Error: Error,
    {
        if let Some(metrics) = &self.metrics {
            match &progress {
                SectorPlottingProgress::Downloading => {
                    metrics.sector_downloading.inc();
                }
                SectorPlottingProgress::Downloaded(time) => {
                    metrics.sector_downloading_time.observe(time.as_secs_f64());
                    metrics.sector_downloaded.inc();
                }
                SectorPlottingProgress::Encoding => {
                    metrics.sector_encoding.inc();
                }
                SectorPlottingProgress::Encoded(time) => {
                    metrics.sector_encoding_time.observe(time.as_secs_f64());
                    metrics.sector_encoded.inc();
                }
                SectorPlottingProgress::Finished { time, .. } => {
                    metrics.sector_plotting_time.observe(time.as_secs_f64());
                    metrics.sector_plotted.inc();
                }
                SectorPlottingProgress::Error { .. } => {
                    metrics.sector_plotting_error.inc();
                }
            }
        }
        self.handlers.plotting_progress.call_simple(
            &self.public_key,
            &self.sector_index,
            &progress,
        );

        if let Err(error) = progress_sender.send(progress).await {
            warn!(%error, "Failed to send progress update");

            false
        } else {
            true
        }
    }
}

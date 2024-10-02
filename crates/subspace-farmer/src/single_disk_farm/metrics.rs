//! Metrics for single disk farm

use crate::farm::{FarmId, FarmingError, ProvingResult};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::{Registry, Unit};
use std::fmt;
use std::sync::atomic::{AtomicI64, AtomicU64};
use std::time::Duration;
use subspace_core_primitives::sectors::SectorIndex;

#[derive(Debug, Copy, Clone)]
pub(super) enum SectorState {
    NotPlotted,
    Plotted,
    AboutToExpire,
    Expired,
}

impl fmt::Display for SectorState {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotPlotted => "NotPlotted",
            Self::Plotted => "Plotted",
            Self::AboutToExpire => "AboutToExpire",
            Self::Expired => "Expired",
        })
    }
}

/// Metrics for single disk farm
#[derive(Debug)]
pub(super) struct SingleDiskFarmMetrics {
    pub(super) auditing_time: Histogram,
    pub(super) skipped_slots: Counter<u64, AtomicU64>,
    proving_time: Family<Vec<(&'static str, String)>, Histogram>,
    farming_errors: Family<Vec<(&'static str, String)>, Counter<u64, AtomicU64>>,
    pub(super) sector_downloading_time: Histogram,
    pub(super) sector_encoding_time: Histogram,
    pub(super) sector_writing_time: Histogram,
    pub(super) sector_plotting_time: Histogram,
    sectors_total: Family<Vec<(&'static str, String)>, Gauge<i64, AtomicI64>>,
    pub(super) sector_downloading: Counter<u64, AtomicU64>,
    pub(super) sector_downloaded: Counter<u64, AtomicU64>,
    pub(super) sector_encoding: Counter<u64, AtomicU64>,
    pub(super) sector_encoded: Counter<u64, AtomicU64>,
    pub(super) sector_writing: Counter<u64, AtomicU64>,
    pub(super) sector_written: Counter<u64, AtomicU64>,
    pub(super) sector_plotting: Counter<u64, AtomicU64>,
    pub(super) sector_plotted: Counter<u64, AtomicU64>,
    pub(super) sector_plotting_error: Counter<u64, AtomicU64>,
}

impl SingleDiskFarmMetrics {
    /// Create new instance for specified farm
    pub(super) fn new(
        registry: &mut Registry,
        farm_id: &FarmId,
        total_sectors_count: SectorIndex,
        plotted_sectors_count: SectorIndex,
    ) -> Self {
        let sub_registry = registry
            .sub_registry_with_prefix("farm")
            .sub_registry_with_label(("farm_id".into(), farm_id.to_string().into()));

        let auditing_time = Histogram::new(exponential_buckets(0.0002, 2.0, 15));
        sub_registry.register_with_unit(
            "auditing_time",
            "Auditing time",
            Unit::Seconds,
            auditing_time.clone(),
        );

        let skipped_slots = Counter::default();
        sub_registry.register(
            "skipped_slots",
            "Completely skipped slots (not even auditing)",
            skipped_slots.clone(),
        );

        let proving_time = Family::<_, _>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(0.0002, 2.0, 15))
        });
        sub_registry.register_with_unit(
            "proving_time",
            "Proving time",
            Unit::Seconds,
            proving_time.clone(),
        );

        let farming_errors = Family::default();
        sub_registry.register(
            "farming_errors",
            "Non-fatal farming errors",
            farming_errors.clone(),
        );

        let sector_downloading_time = Histogram::new(exponential_buckets(0.1, 2.0, 15));
        sub_registry.register_with_unit(
            "sector_downloading_time",
            "Sector downloading time",
            Unit::Seconds,
            sector_downloading_time.clone(),
        );

        let sector_encoding_time = Histogram::new(exponential_buckets(0.1, 2.0, 15));
        sub_registry.register_with_unit(
            "sector_encoding_time",
            "Sector encoding time",
            Unit::Seconds,
            sector_encoding_time.clone(),
        );

        let sector_writing_time = Histogram::new(exponential_buckets(0.0002, 2.0, 15));
        sub_registry.register_with_unit(
            "sector_writing_time",
            "Sector writing time",
            Unit::Seconds,
            sector_writing_time.clone(),
        );

        let sector_plotting_time = Histogram::new(exponential_buckets(0.1, 2.0, 15));
        sub_registry.register_with_unit(
            "sector_plotting_time",
            "Sector plotting time",
            Unit::Seconds,
            sector_plotting_time.clone(),
        );

        let sectors_total = Family::default();
        sub_registry.register_with_unit(
            "sectors_total",
            "Total number of sectors with corresponding state",
            Unit::Other("Sectors".to_string()),
            sectors_total.clone(),
        );

        let sector_downloading = Counter::default();
        sub_registry.register_with_unit(
            "sector_downloading_counter",
            "Number of sectors being downloaded",
            Unit::Other("Sectors".to_string()),
            sector_downloading.clone(),
        );

        let sector_downloaded = Counter::default();
        sub_registry.register_with_unit(
            "sector_downloaded_counter",
            "Number of downloaded sectors",
            Unit::Other("Sectors".to_string()),
            sector_downloaded.clone(),
        );

        let sector_encoding = Counter::default();
        sub_registry.register_with_unit(
            "sector_encoding_counter",
            "Number of sectors being encoded",
            Unit::Other("Sectors".to_string()),
            sector_encoding.clone(),
        );

        let sector_encoded = Counter::default();
        sub_registry.register_with_unit(
            "sector_encoded_counter",
            "Number of encoded sectors",
            Unit::Other("Sectors".to_string()),
            sector_encoded.clone(),
        );

        let sector_writing = Counter::default();
        sub_registry.register_with_unit(
            "sector_writing_counter",
            "Number of sectors being written",
            Unit::Other("Sectors".to_string()),
            sector_writing.clone(),
        );

        let sector_written = Counter::default();
        sub_registry.register_with_unit(
            "sector_written_counter",
            "Number of written sectors",
            Unit::Other("Sectors".to_string()),
            sector_written.clone(),
        );

        let sector_plotting = Counter::default();
        sub_registry.register_with_unit(
            "sector_plotting_counter",
            "Number of sectors being plotted",
            Unit::Other("Sectors".to_string()),
            sector_plotting.clone(),
        );

        let sector_plotted = Counter::default();
        sub_registry.register_with_unit(
            "sector_plotted_counter",
            "Number of plotted sectors",
            Unit::Other("Sectors".to_string()),
            sector_plotted.clone(),
        );

        let sector_plotting_error = Counter::default();
        sub_registry.register_with_unit(
            "sector_plotting_error_counter",
            "Number of sector plotting failures",
            Unit::Other("Sectors".to_string()),
            sector_plotting_error.clone(),
        );

        let metrics = Self {
            auditing_time,
            skipped_slots,
            proving_time,
            farming_errors,
            sector_downloading_time,
            sector_encoding_time,
            sector_writing_time,
            sector_plotting_time,
            sectors_total,
            sector_downloading,
            sector_downloaded,
            sector_encoding,
            sector_encoded,
            sector_writing,
            sector_written,
            sector_plotting,
            sector_plotted,
            sector_plotting_error,
        };

        metrics.update_sectors_total(
            total_sectors_count - plotted_sectors_count,
            SectorState::NotPlotted,
        );
        metrics.update_sectors_total(plotted_sectors_count, SectorState::Plotted);

        metrics
    }

    pub(super) fn observe_proving_time(&self, time: &Duration, result: ProvingResult) {
        self.proving_time
            .get_or_create(&vec![("result", result.to_string())])
            .observe(time.as_secs_f64());
    }

    pub(super) fn note_farming_error(&self, error: &FarmingError) {
        self.farming_errors
            .get_or_create(&vec![("error", error.str_variant().to_string())])
            .inc();
    }

    pub(super) fn update_sectors_total(&self, sectors: SectorIndex, state: SectorState) {
        self.sectors_total
            .get_or_create(&vec![("state", state.to_string())])
            .set(i64::from(sectors));
    }

    pub(super) fn update_sector_state(&self, state: SectorState) {
        self.sectors_total
            .get_or_create(&vec![("state", state.to_string())])
            .inc();
        match state {
            SectorState::NotPlotted => {
                // Never called, doesn't make sense
            }
            SectorState::Plotted => {
                // Separate blocks in because of mutex guard returned by `get_or_create` resulting
                // in deadlock otherwise
                {
                    let not_plotted_sectors = self
                        .sectors_total
                        .get_or_create(&vec![("state", SectorState::NotPlotted.to_string())]);
                    if not_plotted_sectors.get() > 0 {
                        // Initial plotting
                        not_plotted_sectors.dec();
                        return;
                    }
                }
                {
                    let expired_sectors = self
                        .sectors_total
                        .get_or_create(&vec![("state", SectorState::Expired.to_string())]);
                    if expired_sectors.get() > 0 {
                        // Replaced expired sector
                        expired_sectors.dec();
                        return;
                    }
                }
                // Replaced about to expire sector
                self.sectors_total
                    .get_or_create(&vec![("state", SectorState::AboutToExpire.to_string())])
                    .dec();
            }
            SectorState::AboutToExpire | SectorState::Expired => {
                self.sectors_total
                    .get_or_create(&vec![("state", SectorState::Plotted.to_string())])
                    .dec();
            }
        }
    }
}

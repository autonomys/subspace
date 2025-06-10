//! Metrics for GPU plotter

use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::{Registry, Unit};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicI64, AtomicU64};

/// Metrics for GPU plotter
#[derive(Debug)]
pub(super) struct GpuPlotterMetrics {
    pub(super) sector_downloading_time: Histogram,
    pub(super) sector_encoding_time: Histogram,
    pub(super) sector_plotting_time: Histogram,
    pub(super) sector_downloading: Counter<u64, AtomicU64>,
    pub(super) sector_downloaded: Counter<u64, AtomicU64>,
    pub(super) sector_encoding: Counter<u64, AtomicU64>,
    pub(super) sector_encoded: Counter<u64, AtomicU64>,
    pub(super) sector_plotting: Counter<u64, AtomicU64>,
    pub(super) sector_plotted: Counter<u64, AtomicU64>,
    pub(super) sector_plotting_error: Counter<u64, AtomicU64>,
    pub(super) plotting_capacity_used: Gauge<i64, AtomicI64>,
}

impl GpuPlotterMetrics {
    /// Create new instance
    pub(super) fn new(
        registry: &mut Registry,
        subtype: &str,
        total_capacity: NonZeroUsize,
    ) -> Self {
        let registry = registry
            .sub_registry_with_prefix("plotter")
            .sub_registry_with_label(("kind".into(), format!("gpu-{subtype}").into()));

        let sector_downloading_time = Histogram::new(exponential_buckets(0.1, 2.0, 15));
        registry.register_with_unit(
            "sector_downloading_time",
            "Sector downloading time",
            Unit::Seconds,
            sector_downloading_time.clone(),
        );

        let sector_encoding_time = Histogram::new(exponential_buckets(0.1, 2.0, 15));
        registry.register_with_unit(
            "sector_encoding_time",
            "Sector encoding time",
            Unit::Seconds,
            sector_encoding_time.clone(),
        );

        let sector_plotting_time = Histogram::new(exponential_buckets(0.1, 2.0, 15));
        registry.register_with_unit(
            "sector_plotting_time",
            "Sector plotting time",
            Unit::Seconds,
            sector_plotting_time.clone(),
        );

        let sector_downloading = Counter::default();
        registry.register_with_unit(
            "sector_downloading_counter",
            "Number of sectors being downloaded",
            Unit::Other("Sectors".to_string()),
            sector_downloading.clone(),
        );

        let sector_downloaded = Counter::default();
        registry.register_with_unit(
            "sector_downloaded_counter",
            "Number of downloaded sectors",
            Unit::Other("Sectors".to_string()),
            sector_downloaded.clone(),
        );

        let sector_encoding = Counter::default();
        registry.register_with_unit(
            "sector_encoding_counter",
            "Number of sectors being encoded",
            Unit::Other("Sectors".to_string()),
            sector_encoding.clone(),
        );

        let sector_encoded = Counter::default();
        registry.register_with_unit(
            "sector_encoded_counter",
            "Number of encoded sectors",
            Unit::Other("Sectors".to_string()),
            sector_encoded.clone(),
        );

        let sector_plotting = Counter::default();
        registry.register_with_unit(
            "sector_plotting_counter",
            "Number of sectors being plotted",
            Unit::Other("Sectors".to_string()),
            sector_plotting.clone(),
        );

        let sector_plotted = Counter::default();
        registry.register_with_unit(
            "sector_plotted_counter",
            "Number of plotted sectors",
            Unit::Other("Sectors".to_string()),
            sector_plotted.clone(),
        );

        let sector_plotting_error = Counter::default();
        registry.register_with_unit(
            "sector_plotting_error_counter",
            "Number of sector plotting failures",
            Unit::Other("Sectors".to_string()),
            sector_plotting_error.clone(),
        );

        let plotting_capacity_total = Gauge::<i64, AtomicI64>::default();
        plotting_capacity_total.set(total_capacity.get() as i64);
        registry.register_with_unit(
            "plotting_capacity_total",
            "Plotting capacity total",
            Unit::Other("Sectors".to_string()),
            plotting_capacity_total,
        );

        let plotting_capacity_used = Gauge::default();
        registry.register_with_unit(
            "plotting_capacity_used",
            "Plotting capacity used",
            Unit::Other("Sectors".to_string()),
            plotting_capacity_used.clone(),
        );

        Self {
            sector_downloading_time,
            sector_encoding_time,
            sector_plotting_time,
            sector_downloading,
            sector_downloaded,
            sector_encoding,
            sector_encoded,
            sector_plotting,
            sector_plotted,
            sector_plotting_error,
            plotting_capacity_used,
        }
    }
}

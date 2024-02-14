use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::{Registry, Unit};
use std::sync::atomic::{AtomicI64, AtomicU64};
use std::time::Duration;
use subspace_core_primitives::SectorIndex;
use subspace_farmer::single_disk_farm::farming::ProvingResult;
use subspace_farmer::single_disk_farm::{FarmingError, SingleDiskFarmId};

#[derive(Debug, Clone)]
pub(super) struct FarmerMetrics {
    auditing_time: Family<Vec<(String, String)>, Histogram>,
    proving_time: Family<Vec<(String, String)>, Histogram>,
    farming_errors: Family<Vec<(String, String)>, Counter<u64, AtomicU64>>,
    sector_downloading_time: Family<Vec<(String, String)>, Histogram>,
    sector_encoding_time: Family<Vec<(String, String)>, Histogram>,
    sector_writing_time: Family<Vec<(String, String)>, Histogram>,
    sector_plotting_time: Family<Vec<(String, String)>, Histogram>,
    farm_size: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    farm_plotted: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    farm_expired: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    farm_about_to_expire: Family<Vec<(String, String)>, Gauge<i64, AtomicI64>>,
    pub(super) sector_downloading: Counter<u64, AtomicU64>,
    pub(super) sector_downloaded: Counter<u64, AtomicU64>,
    pub(super) sector_encoding: Counter<u64, AtomicU64>,
    pub(super) sector_encoded: Counter<u64, AtomicU64>,
    pub(super) sector_writing: Counter<u64, AtomicU64>,
    pub(super) sector_written: Counter<u64, AtomicU64>,
    pub(super) sector_plotting: Counter<u64, AtomicU64>,
    pub(super) sector_plotted: Counter<u64, AtomicU64>,
}

impl FarmerMetrics {
    pub(super) fn new(registry: &mut Registry) -> Self {
        let sub_registry = registry.sub_registry_with_prefix("subspace_farmer");

        let auditing_time = Family::<_, _>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(0.0001, 2.0, 15))
        });

        sub_registry.register_with_unit(
            "auditing_time",
            "Auditing time",
            Unit::Seconds,
            auditing_time.clone(),
        );

        let proving_time = Family::<_, _>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(0.0001, 2.0, 15))
        });

        sub_registry.register_with_unit(
            "proving_time",
            "Proving time",
            Unit::Seconds,
            proving_time.clone(),
        );

        let farming_errors = Family::<_, _>::new_with_constructor(Counter::<_, _>::default);

        sub_registry.register(
            "farming_errors",
            "Non-fatal farming errors",
            farming_errors.clone(),
        );

        let sector_downloading_time = Family::<_, _>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(0.0001, 2.0, 15))
        });

        sub_registry.register_with_unit(
            "sector_downloading_time",
            "Sector downloading time",
            Unit::Seconds,
            sector_downloading_time.clone(),
        );

        let sector_encoding_time = Family::<_, _>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(0.0001, 2.0, 15))
        });

        sub_registry.register_with_unit(
            "sector_encoding_time",
            "Sector encoding time",
            Unit::Seconds,
            sector_encoding_time.clone(),
        );

        let sector_writing_time = Family::<_, _>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(0.0001, 2.0, 15))
        });

        sub_registry.register_with_unit(
            "sector_writing_time",
            "Sector writing time",
            Unit::Seconds,
            sector_writing_time.clone(),
        );

        let sector_plotting_time = Family::<_, _>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(0.0001, 2.0, 15))
        });

        sub_registry.register_with_unit(
            "sector_plotting_time",
            "Sector plotting time",
            Unit::Seconds,
            sector_plotting_time.clone(),
        );

        let farm_size = Family::<_, _>::new_with_constructor(Gauge::<_, _>::default);

        sub_registry.register_with_unit(
            "farm_size",
            "Farm size",
            Unit::Other("sectors".to_string()),
            farm_size.clone(),
        );

        let farm_plotted = Family::<_, _>::new_with_constructor(Gauge::<_, _>::default);

        sub_registry.register_with_unit(
            "farm_plotted",
            "Number of plotted farm sectors",
            Unit::Other("sectors".to_string()),
            farm_plotted.clone(),
        );

        let farm_expired = Family::<_, _>::new_with_constructor(Gauge::<_, _>::default);

        sub_registry.register_with_unit(
            "farm_expired",
            "Number of expired farm sectors",
            Unit::Other("sectors".to_string()),
            farm_expired.clone(),
        );

        let farm_about_to_expire = Family::<_, _>::new_with_constructor(Gauge::<_, _>::default);

        sub_registry.register_with_unit(
            "farm_about_to_expire",
            "Number of farm sectors about to expire",
            Unit::Other("sectors".to_string()),
            farm_about_to_expire.clone(),
        );

        let sector_downloading = Counter::<_, _>::default();

        sub_registry.register_with_unit(
            "sector_downloading_counter",
            "Number of sectors being downloaded",
            Unit::Other("sectors".to_string()),
            sector_downloading.clone(),
        );

        let sector_downloaded = Counter::<_, _>::default();

        sub_registry.register_with_unit(
            "sector_downloaded_counter",
            "Number of sectors being downloaded",
            Unit::Other("sectors".to_string()),
            sector_downloaded.clone(),
        );

        let sector_encoding = Counter::<_, _>::default();

        sub_registry.register_with_unit(
            "sector_encoding_counter",
            "Number of sectors being downloaded",
            Unit::Other("sectors".to_string()),
            sector_encoding.clone(),
        );

        let sector_encoded = Counter::<_, _>::default();

        sub_registry.register_with_unit(
            "sector_encoded_counter",
            "Number of sectors being downloaded",
            Unit::Other("sectors".to_string()),
            sector_encoded.clone(),
        );

        let sector_writing = Counter::<_, _>::default();

        sub_registry.register_with_unit(
            "sector_writing_counter",
            "Number of sectors being downloaded",
            Unit::Other("sectors".to_string()),
            sector_writing.clone(),
        );

        let sector_written = Counter::<_, _>::default();

        sub_registry.register_with_unit(
            "sector_written_counter",
            "Number of sectors being downloaded",
            Unit::Other("sectors".to_string()),
            sector_written.clone(),
        );

        let sector_plotting = Counter::<_, _>::default();

        sub_registry.register_with_unit(
            "sector_plotting_counter",
            "Number of sectors being downloaded",
            Unit::Other("sectors".to_string()),
            sector_plotting.clone(),
        );

        let sector_plotted = Counter::<_, _>::default();

        sub_registry.register_with_unit(
            "sector_plotted_counter",
            "Number of sectors being downloaded",
            Unit::Other("sectors".to_string()),
            sector_plotted.clone(),
        );

        Self {
            auditing_time,
            proving_time,
            farming_errors,
            sector_downloading_time,
            sector_encoding_time,
            sector_writing_time,
            sector_plotting_time,
            farm_size,
            farm_plotted,
            farm_expired,
            farm_about_to_expire,
            sector_downloading,
            sector_downloaded,
            sector_encoding,
            sector_encoded,
            sector_writing,
            sector_written,
            sector_plotting,
            sector_plotted,
        }
    }

    pub(super) fn observe_auditing_time(
        &self,
        single_disk_farm_id: &SingleDiskFarmId,
        time: &Duration,
    ) {
        self.auditing_time
            .get_or_create(&vec![(
                "farm_id".to_string(),
                single_disk_farm_id.to_string(),
            )])
            .observe(time.as_secs_f64());
    }

    pub(super) fn observe_proving_time(
        &self,
        single_disk_farm_id: &SingleDiskFarmId,
        time: &Duration,
        result: ProvingResult,
    ) {
        self.proving_time
            .get_or_create(&vec![
                ("farm_id".to_string(), single_disk_farm_id.to_string()),
                ("result".to_string(), result.to_string()),
            ])
            .observe(time.as_secs_f64());
    }

    pub(super) fn note_farming_error(
        &self,
        single_disk_farm_id: &SingleDiskFarmId,
        error: &FarmingError,
    ) {
        self.farming_errors
            .get_or_create(&vec![
                ("farm_id".to_string(), single_disk_farm_id.to_string()),
                ("error".to_string(), error.str_variant().to_string()),
            ])
            .inc();
    }

    pub(super) fn observe_sector_downloading_time(
        &self,
        single_disk_farm_id: &SingleDiskFarmId,
        time: &Duration,
    ) {
        self.sector_downloading_time
            .get_or_create(&vec![(
                "farm_id".to_string(),
                single_disk_farm_id.to_string(),
            )])
            .observe(time.as_secs_f64());
    }

    pub(super) fn observe_sector_encoding_time(
        &self,
        single_disk_farm_id: &SingleDiskFarmId,
        time: &Duration,
    ) {
        self.sector_encoding_time
            .get_or_create(&vec![(
                "farm_id".to_string(),
                single_disk_farm_id.to_string(),
            )])
            .observe(time.as_secs_f64());
    }

    pub(super) fn observe_sector_writing_time(
        &self,
        single_disk_farm_id: &SingleDiskFarmId,
        time: &Duration,
    ) {
        self.sector_writing_time
            .get_or_create(&vec![(
                "farm_id".to_string(),
                single_disk_farm_id.to_string(),
            )])
            .observe(time.as_secs_f64());
    }

    pub(super) fn observe_sector_plotting_time(
        &self,
        single_disk_farm_id: &SingleDiskFarmId,
        time: &Duration,
    ) {
        self.sector_plotting_time
            .get_or_create(&vec![(
                "farm_id".to_string(),
                single_disk_farm_id.to_string(),
            )])
            .observe(time.as_secs_f64());
    }

    pub(super) fn update_farm_size(
        &self,
        single_disk_farm_id: &SingleDiskFarmId,
        sectors: SectorIndex,
    ) {
        self.farm_size
            .get_or_create(&vec![(
                "farm_id".to_string(),
                single_disk_farm_id.to_string(),
            )])
            .set(i64::from(sectors));
    }

    pub(super) fn inc_farm_plotted(
        &self,
        single_disk_farm_id: &SingleDiskFarmId,
        sectors: SectorIndex,
    ) {
        self.farm_plotted
            .get_or_create(&vec![(
                "farm_id".to_string(),
                single_disk_farm_id.to_string(),
            )])
            .inc_by(i64::from(sectors));
    }

    pub(super) fn inc_farm_expired(
        &self,
        single_disk_farm_id: &SingleDiskFarmId,
        sectors: SectorIndex,
    ) {
        self.farm_expired
            .get_or_create(&vec![(
                "farm_id".to_string(),
                single_disk_farm_id.to_string(),
            )])
            .inc_by(i64::from(sectors));
        self.farm_plotted
            .get_or_create(&vec![(
                "farm_id".to_string(),
                single_disk_farm_id.to_string(),
            )])
            .dec_by(i64::from(sectors));
    }

    pub(super) fn inc_farm_about_to_expire(
        &self,
        single_disk_farm_id: &SingleDiskFarmId,
        sectors: SectorIndex,
    ) {
        self.farm_about_to_expire
            .get_or_create(&vec![(
                "farm_id".to_string(),
                single_disk_farm_id.to_string(),
            )])
            .inc_by(i64::from(sectors));
        self.farm_plotted
            .get_or_create(&vec![(
                "farm_id".to_string(),
                single_disk_farm_id.to_string(),
            )])
            .dec_by(i64::from(sectors));
    }

    pub(super) fn inc_farm_replotted(&self, single_disk_farm_id: &SingleDiskFarmId) {
        self.farm_plotted
            .get_or_create(&vec![(
                "farm_id".to_string(),
                single_disk_farm_id.to_string(),
            )])
            .inc();
        if self
            .farm_expired
            .get_or_create(&vec![(
                "farm_id".to_string(),
                single_disk_farm_id.to_string(),
            )])
            .get()
            > 0
        {
            self.farm_expired
                .get_or_create(&vec![(
                    "farm_id".to_string(),
                    single_disk_farm_id.to_string(),
                )])
                .dec();
        } else {
            self.farm_about_to_expire
                .get_or_create(&vec![(
                    "farm_id".to_string(),
                    single_disk_farm_id.to_string(),
                )])
                .dec();
        }
    }
}

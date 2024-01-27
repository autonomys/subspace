use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::{Registry, Unit};
use std::time::Duration;
use subspace_farmer::single_disk_farm::farming::ProvingResult;
use subspace_farmer::single_disk_farm::SingleDiskFarmId;
use tokio::signal;

#[derive(Debug, Clone)]
pub(crate) struct FarmerMetrics {
    auditing_time: Family<Vec<(String, String)>, Histogram>,
    proving_time: Family<Vec<(String, String)>, Histogram>,
    sector_downloading_time: Family<Vec<(String, String)>, Histogram>,
    sector_encoding_time: Family<Vec<(String, String)>, Histogram>,
    sector_writing_time: Family<Vec<(String, String)>, Histogram>,
    sector_plotting_time: Family<Vec<(String, String)>, Histogram>,
}

impl FarmerMetrics {
    pub(crate) fn new(registry: &mut Registry) -> Self {
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

        Self {
            auditing_time,
            proving_time,
            sector_downloading_time,
            sector_encoding_time,
            sector_writing_time,
            sector_plotting_time,
        }
    }

    pub(crate) fn observe_auditing_time(
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

    pub(crate) fn observe_proving_time(
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

    pub(crate) fn observe_sector_downloading_time(
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

    pub(crate) fn observe_sector_encoding_time(
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

    pub(crate) fn observe_sector_writing_time(
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

    pub(crate) fn observe_sector_plotting_time(
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
}

pub(crate) fn raise_fd_limit() {
    match fdlimit::raise_fd_limit() {
        Ok(fdlimit::Outcome::LimitRaised { from, to }) => {
            tracing::debug!(
                "Increased file descriptor limit from previous (most likely soft) limit {} to \
                new (most likely hard) limit {}",
                from,
                to
            );
        }
        Ok(fdlimit::Outcome::Unsupported) => {
            // Unsupported platform (non-Linux)
        }
        Err(error) => {
            tracing::warn!(
                "Failed to increase file descriptor limit for the process due to an error: {}.",
                error
            );
        }
    }
}

#[cfg(unix)]
pub(crate) async fn shutdown_signal() {
    use futures::FutureExt;
    use std::pin::pin;

    futures::future::select(
        pin!(signal::unix::signal(signal::unix::SignalKind::interrupt())
            .expect("Setting signal handlers must never fail")
            .recv()
            .map(|_| {
                tracing::info!("Received SIGINT, shutting down farmer...");
            }),),
        pin!(signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Setting signal handlers must never fail")
            .recv()
            .map(|_| {
                tracing::info!("Received SIGTERM, shutting down farmer...");
            }),),
    )
    .await;
}

#[cfg(not(unix))]
pub(crate) async fn shutdown_signal() {
    signal::ctrl_c()
        .await
        .expect("Setting signal handlers must never fail");

    tracing::info!("Received Ctrl+C, shutting down farmer...");
}

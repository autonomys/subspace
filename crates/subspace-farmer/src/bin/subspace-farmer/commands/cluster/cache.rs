use anyhow::anyhow;
use bytesize::ByteSize;
use clap::Parser;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use prometheus_client::registry::Registry;
use std::fs;
use std::future::Future;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::time::Duration;
use subspace_farmer::cluster::cache::cache_service;
use subspace_farmer::cluster::nats_client::NatsClient;
use subspace_farmer::disk_piece_cache::DiskPieceCache;
use subspace_networking::utils::AsyncJoinOnDrop;

/// Interval between cache self-identification broadcast messages
pub(super) const CACHE_IDENTIFICATION_BROADCAST_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct DiskCache {
    /// Path to directory where cache is stored
    directory: PathBuf,
    /// How much space in bytes can cache use
    allocated_space: u64,
}

impl FromStr for DiskCache {
    type Err = String;

    #[inline]
    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        let parts = s.split(',').collect::<Vec<_>>();
        if parts.len() != 2 {
            return Err("Must contain 2 coma-separated components".to_string());
        }

        let mut plot_directory = None;
        let mut allocated_space = None;

        for part in parts {
            let part = part.splitn(2, '=').collect::<Vec<_>>();
            if part.len() != 2 {
                return Err("Each component must contain = separating key from value".to_string());
            }

            let key = *part.first().expect("Length checked above; qed");
            let value = *part.get(1).expect("Length checked above; qed");

            match key {
                "path" => {
                    plot_directory.replace(PathBuf::from(value));
                }
                "size" => {
                    allocated_space.replace(
                        value
                            .parse::<ByteSize>()
                            .map_err(|error| {
                                format!("Failed to parse `size` \"{value}\": {error}")
                            })?
                            .as_u64(),
                    );
                }
                key => {
                    return Err(format!(
                        "Key \"{key}\" is not supported, only `path` or `size`"
                    ));
                }
            }
        }

        Ok(DiskCache {
            directory: plot_directory.ok_or(
                "`path` key is required with path to directory where cache will be stored",
            )?,
            allocated_space: allocated_space
                .ok_or("`size` key is required with allocated amount of disk space")?,
        })
    }
}

/// Arguments for cache
#[derive(Debug, Parser)]
pub(super) struct CacheArgs {
    /// One or more caches located at specified path, each with its own allocated space.
    ///
    /// Format for each cache is coma-separated list of strings like this:
    ///
    ///   path=/path/to/directory,size=5T
    ///
    /// `size` is max allocated size in human-readable format (e.g. 10GB, 2TiB) or just bytes that
    /// cache will make sure to not exceed (and will pre-allocated all the space on startup to
    /// ensure it will not run out of space in runtime).
    disk_caches: Vec<DiskCache>,
    /// Run temporary cache with specified farm size in human-readable format (e.g. 10GB, 2TiB) or
    /// just bytes (e.g. 4096), this will create a temporary directory that will be deleted at the
    /// end of the process.
    #[arg(long, conflicts_with = "disk_caches")]
    tmp: Option<ByteSize>,
    /// Cache group to use, the same cache group must be also specified on corresponding controller
    #[arg(long, default_value = "default")]
    cache_group: String,
    /// Number of service instances.
    ///
    /// Increasing number of services allows to process more concurrent requests, but increasing
    /// beyond number of CPU cores doesn't make sense and will likely hurt performance instead.
    #[arg(long, default_value = "32")]
    service_instances: NonZeroUsize,
    /// Additional cluster components
    #[clap(raw = true)]
    pub(super) additional_components: Vec<String>,
}

pub(super) async fn cache(
    nats_client: NatsClient,
    registry: &mut Registry,
    cache_args: CacheArgs,
) -> anyhow::Result<Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>> {
    let CacheArgs {
        mut disk_caches,
        tmp,
        cache_group,
        service_instances,
        additional_components: _,
    } = cache_args;

    let tmp_directory = if let Some(plot_size) = tmp {
        let tmp_directory = tempfile::Builder::new()
            .prefix("subspace-cache-")
            .tempdir()
            .map_err(|error| anyhow!("Failed to create temporary directory: {error}"))?;

        disk_caches = vec![DiskCache {
            directory: tmp_directory.as_ref().to_path_buf(),
            allocated_space: plot_size.as_u64(),
        }];

        Some(tmp_directory)
    } else {
        if disk_caches.is_empty() {
            return Err(anyhow!("There must be at least one disk cache provided"));
        }

        for cache in &disk_caches {
            if !cache.directory.exists()
                && let Err(error) = fs::create_dir(&cache.directory)
            {
                return Err(anyhow!(
                    "Directory {} doesn't exist and can't be created: {}",
                    cache.directory.display(),
                    error
                ));
            }
        }
        None
    };

    let caches = disk_caches
        .iter()
        .map(|disk_cache| {
            let capacity =
                u32::try_from(disk_cache.allocated_space / DiskPieceCache::element_size() as u64)
                    .map_err(|error| {
                    anyhow!(
                        "Unsupported cache #1 size {} at {}: {error}",
                        disk_cache.allocated_space,
                        disk_cache.directory.display()
                    )
                })?;
            let capacity = NonZeroU32::try_from(capacity).map_err(|error| {
                anyhow!(
                    "Unsupported cache #2 size {} at {}: {error}",
                    disk_cache.allocated_space,
                    disk_cache.directory.display()
                )
            })?;
            DiskPieceCache::open(&disk_cache.directory, capacity, None, Some(registry)).map_err(
                |error| {
                    anyhow!(
                        "Failed to open piece cache at {}: {error}",
                        disk_cache.directory.display()
                    )
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut cache_services = (0..service_instances.get())
        .map(|index| {
            let nats_client = nats_client.clone();
            let caches = caches.clone();
            let cache_group = cache_group.clone();

            AsyncJoinOnDrop::new(
                tokio::spawn(async move {
                    cache_service(
                        nats_client,
                        &caches,
                        &cache_group,
                        CACHE_IDENTIFICATION_BROADCAST_INTERVAL,
                        index == 0,
                    )
                    .await
                }),
                true,
            )
        })
        .collect::<FuturesUnordered<_>>();

    Ok(Box::pin(async move {
        cache_services
            .next()
            .await
            .expect("Not empty; qed")
            .map_err(|error| anyhow!("Cache service failed: {error}"))?
            .map_err(|error| anyhow!("Cache service failed: {error}"))?;

        drop(tmp_directory);

        Ok(())
    }))
}

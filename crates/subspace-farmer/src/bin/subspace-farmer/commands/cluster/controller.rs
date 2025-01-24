use crate::commands::cluster::cache::CACHE_IDENTIFICATION_BROADCAST_INTERVAL;
use crate::commands::cluster::farmer::FARMER_IDENTIFICATION_BROADCAST_INTERVAL;
use crate::commands::shared::derive_libp2p_keypair;
use crate::commands::shared::network::{configure_network, NetworkArgs};
use anyhow::anyhow;
use async_lock::{RwLock as AsyncRwLock, Semaphore};
use backoff::ExponentialBackoff;
use clap::{Parser, ValueHint};
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, StreamExt};
use prometheus_client::registry::Registry;
use std::future::Future;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::time::Duration;
use subspace_farmer::cluster::controller::caches::maintain_caches;
use subspace_farmer::cluster::controller::controller_service;
use subspace_farmer::cluster::controller::farms::{maintain_farms, FarmIndex};
use subspace_farmer::cluster::nats_client::NatsClient;
use subspace_farmer::farm::plotted_pieces::PlottedPieces;
use subspace_farmer::farmer_cache::{FarmerCache, FarmerCaches};
use subspace_farmer::farmer_piece_getter::piece_validator::SegmentCommitmentPieceValidator;
use subspace_farmer::farmer_piece_getter::{DsnCacheRetryPolicy, FarmerPieceGetter};
use subspace_farmer::node_client::caching_proxy_node_client::CachingProxyNodeClient;
use subspace_farmer::node_client::rpc_node_client::RpcNodeClient;
use subspace_farmer::node_client::NodeClient;
use subspace_farmer::single_disk_farm::identity::Identity;
use subspace_farmer::utils::{run_future_in_dedicated_thread, AsyncJoinOnDrop};
use subspace_kzg::Kzg;
use subspace_networking::utils::piece_provider::PieceProvider;
use tracing::{info, info_span, Instrument};

/// Get piece retry attempts number.
const PIECE_GETTER_MAX_RETRIES: u16 = 7;
/// Defines initial duration between get_piece calls.
const GET_PIECE_INITIAL_INTERVAL: Duration = Duration::from_secs(5);
/// Defines max duration between get_piece calls.
const GET_PIECE_MAX_INTERVAL: Duration = Duration::from_secs(40);
/// Multiplier on top of outgoing connections number for piece downloading purposes
const PIECE_PROVIDER_MULTIPLIER: usize = 10;

/// Arguments for controller
#[derive(Debug, Parser)]
pub(super) struct ControllerArgs {
    /// Base path where to store P2P network identity
    #[arg(long, value_hint = ValueHint::DirPath)]
    base_path: Option<PathBuf>,
    /// WebSocket RPC URL of the Subspace node to connect to
    #[arg(long, value_hint = ValueHint::Url, default_value = "ws://127.0.0.1:9944")]
    node_rpc_url: String,
    /// Cache group managed by this controller, each controller must have its dedicated cache group
    /// and there should be just a single controller per cache group or else they may conflict with
    /// each other and cause unnecessary cache writes.
    ///
    /// It is strongly recommended to use alphanumeric values for cache group, the same cache group
    /// must be also specified on corresponding caches.
    #[arg(long = "cache-group", default_value = "default")]
    cache_groups: Vec<String>,
    /// Number of service instances.
    ///
    /// Increasing number of services allows to process more concurrent requests, but increasing
    /// beyond number of CPU cores doesn't make sense and will likely hurt performance instead.
    #[arg(long, default_value = "32")]
    service_instances: NonZeroUsize,
    /// Network parameters
    #[clap(flatten)]
    network_args: NetworkArgs,
    /// Sets some flags that are convenient during development, currently `--allow-private-ips`
    #[arg(long)]
    dev: bool,
    /// Run temporary controller identity
    #[arg(long, conflicts_with = "base_path")]
    tmp: bool,
    /// Additional cluster components
    #[clap(raw = true)]
    pub(super) additional_components: Vec<String>,
}

pub(super) async fn controller(
    nats_client: NatsClient,
    registry: &mut Registry,
    controller_args: ControllerArgs,
) -> anyhow::Result<Pin<Box<dyn Future<Output = anyhow::Result<()>>>>> {
    let ControllerArgs {
        base_path,
        node_rpc_url,
        cache_groups,
        service_instances,
        mut network_args,
        dev,
        tmp,
        additional_components: _,
    } = controller_args;

    // Override flags with `--dev`
    network_args.allow_private_ips = network_args.allow_private_ips || dev;

    let (base_path, tmp_directory) = if tmp {
        let tmp_directory = tempfile::Builder::new()
            .prefix("subspace-cluster-controller-")
            .tempdir()
            .map_err(|error| anyhow!("Failed to create temporary directory: {error}"))?;

        (tmp_directory.as_ref().to_path_buf(), Some(tmp_directory))
    } else {
        let Some(base_path) = base_path else {
            return Err(anyhow!("--base-path must be specified explicitly"));
        };

        (base_path, None)
    };

    let plotted_pieces = Arc::new(AsyncRwLock::new(PlottedPieces::<FarmIndex>::default()));

    info!(url = %node_rpc_url, "Connecting to node RPC");
    let node_client = RpcNodeClient::new(&node_rpc_url)
        .await
        .map_err(|error| anyhow!("Failed to connect to node RPC: {error}"))?;

    let farmer_app_info = node_client
        .farmer_app_info()
        .await
        .map_err(|error| anyhow!("Failed to get farmer app info: {error}"))?;

    let identity = Identity::open_or_create(&base_path)
        .map_err(|error| anyhow!("Failed to open or create identity: {error}"))?;
    let keypair = derive_libp2p_keypair(identity.secret_key());
    let peer_id = keypair.public().to_peer_id();
    let instance = peer_id.to_string();

    let (farmer_caches, farmer_cache_workers) = cache_groups
        .iter()
        .map(|_cache_group| FarmerCache::new(node_client.clone(), peer_id, Some(registry)))
        .unzip::<_, _, Vec<_>, Vec<_>>();
    let farmer_caches = Arc::from(farmer_caches.into_boxed_slice());

    // TODO: Metrics

    let node_client = CachingProxyNodeClient::new(node_client)
        .await
        .map_err(|error| anyhow!("Failed to create caching proxy node client: {error}"))?;

    let out_connections = network_args.out_connections;
    let (node, mut node_runner) = {
        if network_args.bootstrap_nodes.is_empty() {
            network_args
                .bootstrap_nodes
                .clone_from(&farmer_app_info.dsn_bootstrap_nodes);
        }

        configure_network(
            hex::encode(farmer_app_info.genesis_hash),
            &base_path,
            keypair,
            network_args,
            Arc::downgrade(&plotted_pieces),
            node_client.clone(),
            FarmerCaches::from(Arc::clone(&farmer_caches)),
            Some(registry),
        )
        .map_err(|error| anyhow!("Failed to configure networking: {error}"))?
    };

    let kzg = Kzg::new();
    let piece_provider = PieceProvider::new(
        node.clone(),
        SegmentCommitmentPieceValidator::new(node.clone(), node_client.clone(), kzg.clone()),
        Arc::new(Semaphore::new(
            out_connections as usize * PIECE_PROVIDER_MULTIPLIER,
        )),
    );

    let farmer_cache_workers_fut = farmer_cache_workers
        .into_iter()
        .zip(&cache_groups)
        .enumerate()
        .map(|(index, (farmer_cache_worker, cache_group))| {
            // Each farmer cache worker gets a customized piece getter that can leverage other
            // caches than itself for sync purposes
            let piece_getter = FarmerPieceGetter::new(
                piece_provider.clone(),
                FarmerCaches::from(Arc::from(
                    farmer_caches
                        .iter()
                        .enumerate()
                        .filter(|&(filter_index, _farmer_cache)| filter_index != index)
                        .map(|(_filter_index, farmer_cache)| farmer_cache.clone())
                        .collect::<Box<_>>(),
                )),
                node_client.clone(),
                Arc::clone(&plotted_pieces),
                DsnCacheRetryPolicy {
                    max_retries: PIECE_GETTER_MAX_RETRIES,
                    backoff: ExponentialBackoff {
                        initial_interval: GET_PIECE_INITIAL_INTERVAL,
                        max_interval: GET_PIECE_MAX_INTERVAL,
                        // Try until we get a valid piece
                        max_elapsed_time: None,
                        multiplier: 1.75,
                        ..ExponentialBackoff::default()
                    },
                },
            );

            let fut = farmer_cache_worker
                .run(piece_getter)
                .instrument(info_span!("", %cache_group));

            async move {
                let fut =
                    run_future_in_dedicated_thread(move || fut, format!("cache-worker-{index}"));
                anyhow::Ok(fut?.await?)
            }
        })
        .collect::<FuturesUnordered<_>>();

    let piece_getter = FarmerPieceGetter::new(
        piece_provider,
        FarmerCaches::from(Arc::clone(&farmer_caches)),
        node_client.clone(),
        Arc::clone(&plotted_pieces),
        DsnCacheRetryPolicy {
            max_retries: PIECE_GETTER_MAX_RETRIES,
            backoff: ExponentialBackoff {
                initial_interval: GET_PIECE_INITIAL_INTERVAL,
                max_interval: GET_PIECE_MAX_INTERVAL,
                // Try until we get a valid piece
                max_elapsed_time: None,
                multiplier: 1.75,
                ..ExponentialBackoff::default()
            },
        },
    );

    let mut controller_services = (0..service_instances.get())
        .map(|index| {
            let nats_client = nats_client.clone();
            let node_client = node_client.clone();
            let piece_getter = piece_getter.clone();
            let farmer_caches = Arc::clone(&farmer_caches);
            let cache_groups = cache_groups.clone();
            let instance = instance.clone();

            AsyncJoinOnDrop::new(
                tokio::spawn(async move {
                    let farmer_caches = cache_groups
                        .iter()
                        .zip(farmer_caches.as_ref())
                        .map(|(cache_group, farmer_cache)| (cache_group.as_str(), farmer_cache))
                        .collect::<Vec<_>>();

                    controller_service(
                        &nats_client,
                        &node_client,
                        &piece_getter,
                        &farmer_caches,
                        &instance,
                        index == 0,
                    )
                    .await
                }),
                true,
            )
        })
        .collect::<FuturesUnordered<_>>();

    let controller_service_fut = async move {
        controller_services
            .next()
            .await
            .expect("Not empty; qed")
            .map_err(|error| anyhow!("Controller service failed: {error}"))?
            .map_err(|error| anyhow!("Controller service failed: {error}"))
    };

    let farms_fut = run_future_in_dedicated_thread(
        {
            let nats_client = nats_client.clone();

            move || async move {
                maintain_farms(
                    &instance,
                    &nats_client,
                    &plotted_pieces,
                    FARMER_IDENTIFICATION_BROADCAST_INTERVAL,
                )
                .await
            }
        },
        "farms".to_string(),
    )?;

    let caches_fut = farmer_caches
        .iter()
        .cloned()
        .zip(cache_groups)
        .enumerate()
        .map(|(index, (farmer_cache, cache_group))| {
            let nats_client = nats_client.clone();

            async move {
                let fut = run_future_in_dedicated_thread(
                    move || async move {
                        maintain_caches(
                            &cache_group,
                            &nats_client,
                            &farmer_cache,
                            CACHE_IDENTIFICATION_BROADCAST_INTERVAL,
                        )
                        .await
                    },
                    format!("caches-{index}"),
                );
                anyhow::Ok(fut?.await?)
            }
        })
        .collect::<FuturesUnordered<_>>();

    let networking_fut = run_future_in_dedicated_thread(
        move || async move { node_runner.run().await },
        "networking".to_string(),
    )?;

    Ok(Box::pin(async move {
        // This defines order in which things are dropped
        let networking_fut = networking_fut;
        let farms_fut = farms_fut;
        let mut caches_fut = caches_fut;
        let caches_fut = caches_fut.next().map(|result| result.unwrap_or(Ok(Ok(()))));
        let mut farmer_cache_workers_fut = farmer_cache_workers_fut;
        let farmer_cache_workers_fut = farmer_cache_workers_fut
            .next()
            .map(|result| result.unwrap_or(Ok(())));
        let controller_service_fut = controller_service_fut;

        let networking_fut = pin!(networking_fut);
        let farms_fut = pin!(farms_fut);
        let caches_fut = pin!(caches_fut);
        let farmer_cache_workers_fut = pin!(farmer_cache_workers_fut);
        let controller_service_fut = pin!(controller_service_fut);

        select! {
            // Networking future
            _ = networking_fut.fuse() => {
                info!("Node runner exited.")
            },

            // Farms future
            result = farms_fut.fuse() => {
                result??;
            },

            // Caches future
            result = caches_fut.fuse() => {
                result??;
            },

            // Piece cache worker future
            _ = farmer_cache_workers_fut.fuse() => {
                info!("Farmer cache worker exited.")
            },

            // Controller service future
            result = controller_service_fut.fuse() => {
                result?;
            },
        }

        drop(tmp_directory);

        Ok(())
    }))
}

use crate::utils::shutdown_signal;
use crate::{DiskFarm, FarmingArgs, Multiaddr};
use anyhow::{anyhow, Result};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::str::FromStr;
use subspace_farmer::single_disk_plot::{SingleDiskPlot, SingleDiskPlotOptions};
use subspace_farmer::NodeRpcClient;
use subspace_networking::{
    create, BootstrappedNetworkingParameters, Config, CustomRecordStore,
    LimitedSizeRecordStorageWrapper, MemoryProviderStorage, Node, NodeRunner,
    ParityDbRecordStorage, PieceByHashRequestHandler, PieceByHashResponse, PieceKey,
};
use tracing::{debug, error, info};

const MAX_KADEMLIA_RECORDS_NUMBER: usize = 32768;

// Type alias for currently configured Kademlia's custom record store.
type ConfiguredRecordStore = CustomRecordStore<
    LimitedSizeRecordStorageWrapper<ParityDbRecordStorage>,
    MemoryProviderStorage,
>;

/// Start farming by using multiple replica plot in specified path and connecting to WebSocket
/// server at specified address.
pub(crate) async fn farm_multi_disk(
    disk_farms: Vec<DiskFarm>,
    farming_args: FarmingArgs,
) -> Result<(), anyhow::Error> {
    if disk_farms.is_empty() {
        return Err(anyhow!("There must be at least one disk farm provided"));
    }

    let signal = shutdown_signal();

    // TODO: Use variables and remove this suppression
    #[allow(unused_variables)]
    let FarmingArgs {
        bootstrap_nodes,
        listen_on,
        node_rpc_url,
        reward_address,
        plot_size: _,
        disk_concurrency,
        disable_farming,
        enable_dsn,
        record_cache_size,
        record_cache_db_path,
    } = farming_args;

    let (node, node_runner) = configure_dsn(
        enable_dsn,
        listen_on,
        bootstrap_nodes,
        record_cache_size,
        record_cache_db_path,
    )
    .await?;
    let mut single_disk_plots = Vec::with_capacity(disk_farms.len());

    // TODO: Check plot and metadata sizes to ensure there is enough space for farmer to not
    //  fail later
    for disk_farm in disk_farms {
        if disk_farm.allocated_plotting_space < 1024 * 1024 {
            return Err(anyhow::anyhow!(
                "Plot size is too low ({0} bytes). Did you mean {0}G or {0}T?",
                disk_farm.allocated_plotting_space
            ));
        }

        info!("Connecting to node at {}", node_rpc_url);
        let rpc_client = NodeRpcClient::new(&node_rpc_url).await?;

        let single_disk_plot = SingleDiskPlot::new(SingleDiskPlotOptions {
            directory: disk_farm.directory,
            allocated_space: disk_farm.allocated_plotting_space,
            rpc_client,
            reward_address,
            dsn_node: node.clone(),
        })?;

        single_disk_plots.push(single_disk_plot);
    }

    let mut single_disk_plots_stream = single_disk_plots
        .into_iter()
        .map(|single_disk_plot| single_disk_plot.wait())
        .collect::<FuturesUnordered<_>>();

    futures::select!(
        // Signal future
        _ = Box::pin(async move {
            signal.await;
        }).fuse() => {},

        // Plotting future
        _ = Box::pin(async move {
            while let Some(result) = single_disk_plots_stream.next().await {
                result?;

                info!("Farm exited successfully");
            }
            anyhow::Ok(())
        }).fuse() => {},

        // Node runner future
        _ = Box::pin(async move {
            if let Some(mut node_runner) = node_runner{
                node_runner.run().await;

                info!("Node runner exited.")
            } else {
                futures::future::pending().await
            }
        }).fuse() => {},
    );

    anyhow::Ok(())
}

async fn configure_dsn(
    enable_dsn: bool,
    listen_on: Vec<Multiaddr>,
    bootstrap_nodes: Vec<Multiaddr>,
    record_cache_size: usize,
    record_cache_db_path: Option<String>,
) -> Result<(Option<Node>, Option<NodeRunner<ConfiguredRecordStore>>), anyhow::Error> {
    if !enable_dsn {
        info!("No DSN configured.");
        return Ok((None, None));
    }

    let record_cache_size = NonZeroUsize::new(record_cache_size).unwrap_or(
        NonZeroUsize::new(MAX_KADEMLIA_RECORDS_NUMBER)
            .expect("We don't expect an error on manually set value."),
    );

    let record_cache_db_path = record_cache_db_path
        .and_then(|path| {
            let path_result = PathBuf::from_str(&path);

            if let Err(ref err) = path_result {
                error!(
                    ?err,
                    "Invalid record cache DB path. Temp directory used instead."
                );
            }

            path_result.ok()
        })
        .unwrap_or_else(std::env::temp_dir)
        .join("subspace_records_cache_db")
        .into_boxed_path();

    info!(
        ?record_cache_db_path,
        ?record_cache_size,
        "Record cache DB configured."
    );

    let config = Config::<ConfiguredRecordStore> {
        listen_on,
        allow_non_globals_in_dht: true,
        networking_parameters_registry: BootstrappedNetworkingParameters::new(bootstrap_nodes)
            .boxed(),
        request_response_protocols: vec![PieceByHashRequestHandler::create(move |req| {
            let result = if let PieceKey::Sector(_piece_index_hash) = req.key {
                // TODO: Implement actual handler
                None
            } else {
                debug!(key=?req.key, "Incorrect piece request - unsupported key type.");

                None
            };

            Some(PieceByHashResponse { piece: result })
        })],
        record_store: CustomRecordStore::new(
            LimitedSizeRecordStorageWrapper::new(
                ParityDbRecordStorage::new(&record_cache_db_path)
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?,
                record_cache_size,
            ),
            MemoryProviderStorage::default(),
        ),
        ..Config::with_generated_keypair()
    };

    create::<ConfiguredRecordStore>(config)
        .await
        .map(|(node, node_runner)| (Some(node), Some(node_runner)))
        .map_err(Into::into)
}

use crate::utils::shutdown_signal;
use crate::{DiskFarm, FarmingArgs};
use anyhow::{anyhow, Result};
use futures::future::select;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use subspace_farmer::single_disk_plot::{SingleDiskPlot, SingleDiskPlotOptions};
use subspace_farmer::NodeRpcClient;
use tracing::info;

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
    } = farming_args;

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
        })?;

        single_disk_plots.push(single_disk_plot);
    }

    let mut single_disk_plots_stream = single_disk_plots
        .into_iter()
        .map(|single_disk_plot| single_disk_plot.wait())
        .collect::<FuturesUnordered<_>>();

    select(
        Box::pin(async move {
            signal.await;

            Ok(())
        }),
        Box::pin(async move {
            while let Some(result) = single_disk_plots_stream.next().await {
                result?;

                info!("Farm exited successfully");
            }

            anyhow::Ok(())
        }),
    )
    .await
    .factor_first()
    .0
}

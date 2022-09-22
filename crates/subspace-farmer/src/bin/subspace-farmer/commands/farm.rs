use crate::utils::shutdown_signal;
use crate::{ArchivingFrom, DiskFarm, FarmingArgs};
use anyhow::{anyhow, Result};
use futures::future::select;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use jsonrpsee::ws_server::WsServerBuilder;
use std::sync::Arc;
use subspace_farmer::single_disk_farm::{SingleDiskFarm, SingleDiskFarmOptions};
use subspace_farmer::single_plot_farm::PlotFactoryOptions;
use subspace_farmer::ws_rpc_server::{RpcServer, RpcServerImpl};
use subspace_farmer::{NodeRpcClient, Plot, RpcClient};
use tracing::{info, warn};

const GEMINI_2A_GENESIS_HASH: [u8; 32] = [
    0x43, 0xd1, 0x0f, 0xfd, 0x50, 0x99, 0x03, 0x80, 0xff, 0xe6, 0xc9, 0x39, 0x21, 0x45, 0x43, 0x1d,
    0x63, 0x0a, 0xe6, 0x7e, 0x89, 0xdb, 0xc9, 0xc0, 0x14, 0xca, 0xc2, 0xa4, 0x17, 0x75, 0x91, 0x01,
];
// 100GiB
const GEMINI_2A_MAX_ALLOCATED_SIZE: u64 = 100 * 1024 * 1024 * 1024;

struct CallOnDrop<F>(Option<F>)
where
    F: FnOnce() + Send + 'static;

impl<F> Drop for CallOnDrop<F>
where
    F: FnOnce() + Send + 'static,
{
    fn drop(&mut self) {
        let callback = self.0.take().expect("Only removed on drop; qed");
        callback();
    }
}

impl<F> CallOnDrop<F>
where
    F: FnOnce() + Send + 'static,
{
    fn new(callback: F) -> Self {
        Self(Some(callback))
    }
}

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

    let FarmingArgs {
        bootstrap_nodes,
        listen_on: _,
        node_rpc_url,
        mut ws_server_listen_addr,
        reward_address,
        plot_size: _,
        max_plot_size,
        disk_concurrency,
        dsn_sync,
        archiving,
        disable_farming,
    } = farming_args;

    let mut single_disk_farms = Vec::with_capacity(disk_farms.len());
    let mut record_size = None;
    let mut recorded_history_segment_size = None;

    // TODO: Check plot and metadata sizes to ensure there is enough space for farmer to not
    //  fail later (note that multiple farms can use the same location for metadata)
    for (farm_index, mut disk_farm) in disk_farms.into_iter().enumerate() {
        if disk_farm.allocated_plotting_space < 1024 * 1024 {
            return Err(anyhow::anyhow!(
                "Plot size is too low ({0} bytes). Did you mean {0}G or {0}T?",
                disk_farm.allocated_plotting_space
            ));
        }

        info!("Connecting to node at {}", node_rpc_url);
        let archiving_client = NodeRpcClient::new(&node_rpc_url).await?;
        let farming_client = NodeRpcClient::new(&node_rpc_url).await?;

        let mut farmer_protocol_info = farming_client
            .farmer_protocol_info()
            .await
            .map_err(|error| anyhow!(error))?;

        if farmer_protocol_info.genesis_hash == GEMINI_2A_GENESIS_HASH {
            if farm_index > 0 {
                warn!("This chain only supports one disk farm");
                break;
            }

            if disk_farm.allocated_plotting_space > GEMINI_2A_MAX_ALLOCATED_SIZE {
                warn!(
                    "This chain only supports up to 100GiB of allocated space, force-limiting \
                    allocated space to 100GiB"
                );

                disk_farm.allocated_plotting_space = GEMINI_2A_MAX_ALLOCATED_SIZE;
            }
        }

        if let Some(max_plot_size) = max_plot_size {
            let max_plot_size = max_plot_size.as_u64();
            if max_plot_size > farmer_protocol_info.max_plot_size {
                warn!("Passed `max_plot_size` is too big. Fallback to the one from consensus.");
            } else {
                farmer_protocol_info.max_plot_size = max_plot_size;
            }
        }

        record_size.replace(farmer_protocol_info.record_size);
        recorded_history_segment_size.replace(farmer_protocol_info.recorded_history_segment_size);

        let single_disk_farm = SingleDiskFarm::new(SingleDiskFarmOptions {
            plot_directory: disk_farm.plot_directory,
            metadata_directory: disk_farm.metadata_directory,
            allocated_plotting_space: disk_farm.allocated_plotting_space,
            farmer_protocol_info,
            disk_concurrency,
            archiving_client,
            farming_client,
            reward_address,
            bootstrap_nodes: bootstrap_nodes.clone(),
            listen_on: vec![],
            enable_dsn_archiving: matches!(archiving, ArchivingFrom::Dsn),
            enable_dsn_sync: dsn_sync,
            enable_farming: !disable_farming,
            plot_factory: move |options: PlotFactoryOptions<'_>| {
                Plot::open_or_create(
                    options.single_plot_farm_id,
                    options.plot_directory,
                    options.metadata_directory,
                    options.public_key,
                    options.max_plot_size,
                )
            },
        })
        .await?;

        single_disk_farms.push(single_disk_farm);
    }

    let record_size = record_size.expect("At least one farm is always present, checked above; qed");
    let recorded_history_segment_size = recorded_history_segment_size
        .expect("At least one farm is always present, checked above; qed");

    // Start RPC server
    let ws_server = match WsServerBuilder::default()
        .build(ws_server_listen_addr)
        .await
    {
        Ok(ws_server) => ws_server,
        Err(jsonrpsee::core::Error::Transport(error)) => {
            warn!(
                address = %ws_server_listen_addr,
                %error,
                "Failed to start WebSocket RPC server on, trying random port"
            );
            ws_server_listen_addr.set_port(0);
            WsServerBuilder::default()
                .build(ws_server_listen_addr)
                .await?
        }
        Err(error) => {
            return Err(error.into());
        }
    };
    let ws_server_addr = ws_server.local_addr()?;
    let rpc_server = RpcServerImpl::new(
        record_size.get(),
        recorded_history_segment_size,
        Arc::new(
            single_disk_farms
                .iter()
                .map(|single_disk_farm| single_disk_farm.piece_getter())
                .collect::<Vec<_>>(),
        ),
        Arc::new(
            single_disk_farms
                .iter()
                .flat_map(|single_disk_farm| {
                    single_disk_farm
                        .single_plot_farms()
                        .iter()
                        .map(|single_plot_farm| single_plot_farm.object_mappings().clone())
                })
                .collect::<Vec<_>>(),
        ),
    );
    let _ws_server_guard = CallOnDrop::new({
        let ws_server = ws_server.start(rpc_server.into_rpc())?;
        let tokio_handle = tokio::runtime::Handle::current();

        move || {
            if let Ok(waiter) = ws_server.stop() {
                tokio::task::block_in_place(move || tokio_handle.block_on(waiter));
            }
        }
    });

    info!("WS RPC server listening on {ws_server_addr}");

    let mut single_disk_farms_stream = single_disk_farms
        .into_iter()
        .map(|single_disk_farm| single_disk_farm.wait())
        .collect::<FuturesUnordered<_>>();

    select(
        Box::pin(async move {
            signal.await;

            Ok(())
        }),
        Box::pin(async move {
            while let Some(result) = single_disk_farms_stream.next().await {
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

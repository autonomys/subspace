mod cache;
mod controller;
mod farmer;
mod plotter;

use crate::commands::cluster::cache::{cache, CacheArgs};
use crate::commands::cluster::controller::{controller, ControllerArgs};
use crate::commands::cluster::farmer::{farmer, FarmerArgs};
use crate::commands::cluster::plotter::{plotter, PlotterArgs};
use crate::utils::shutdown_signal;
use anyhow::anyhow;
use async_nats::ServerAddr;
use backoff::ExponentialBackoff;
use clap::{Parser, Subcommand};
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, StreamExt};
use prometheus_client::registry::Registry;
use std::env::current_exe;
use std::mem;
use std::net::SocketAddr;
use subspace_farmer::cluster::nats_client::NatsClient;
use subspace_farmer::utils::AsyncJoinOnDrop;
use subspace_metrics::{start_prometheus_metrics_server, RegistryAdapter};
use subspace_proof_of_space::Table;

/// Arguments for cluster
#[derive(Debug, Parser)]
pub(crate) struct ClusterArgs {
    /// Shared arguments for all subcommands
    #[clap(flatten)]
    shared_args: SharedArgs,
    /// Cluster subcommands
    #[clap(flatten)]
    subcommands: ClusterSubcommands,
}

/// Recursive cluster subcommands
#[derive(Debug, Parser)]
struct ClusterSubcommands {
    /// Cluster subcommands
    #[clap(subcommand)]
    subcommand: ClusterSubcommand,
}

/// Shared arguments
#[derive(Debug, Parser)]
struct SharedArgs {
    /// NATS server address, typically in `nats://server1:port1` format, can be specified multiple
    /// times.
    ///
    /// NOTE: NATS must be configured for message sizes of 2MiB or larger (1MiB is the default),
    /// which can be done by starting NATS server with config file containing `max_payload = 2MB`.
    #[arg(long = "nats-server", required = true)]
    nats_servers: Vec<ServerAddr>,
    /// Defines endpoints for the prometheus metrics server. It doesn't start without at least
    /// one specified endpoint. Format: 127.0.0.1:8080
    #[arg(long, aliases = ["metrics-endpoint", "metrics-endpoints"])]
    prometheus_listen_on: Vec<SocketAddr>,
}

/// Cluster subcommands
#[derive(Debug, Subcommand)]
enum ClusterSubcommand {
    /// Farming cluster controller
    Controller(ControllerArgs),
    /// Farming cluster farmer
    Farmer(FarmerArgs),
    /// Farming cluster plotter
    Plotter(PlotterArgs),
    /// Farming cluster cache
    Cache(CacheArgs),
}

impl ClusterSubcommand {
    fn extract_additional_components(&mut self) -> Vec<String> {
        match self {
            ClusterSubcommand::Controller(args) => mem::take(&mut args.additional_components),
            ClusterSubcommand::Farmer(args) => mem::take(&mut args.additional_components),
            ClusterSubcommand::Plotter(args) => mem::take(&mut args.additional_components),
            ClusterSubcommand::Cache(args) => mem::take(&mut args.additional_components),
        }
    }
}

pub(crate) async fn cluster<PosTable>(cluster_args: ClusterArgs) -> anyhow::Result<()>
where
    PosTable: Table,
{
    let signal = shutdown_signal();

    let ClusterArgs {
        shared_args,
        subcommands,
    } = cluster_args;
    let SharedArgs {
        nats_servers,
        prometheus_listen_on,
    } = shared_args;
    let ClusterSubcommands { mut subcommand } = subcommands;

    let nats_client = NatsClient::new(
        nats_servers,
        ExponentialBackoff {
            max_elapsed_time: None,
            ..ExponentialBackoff::default()
        },
    )
    .await
    .map_err(|error| anyhow!("Failed to connect to NATS server: {error}"))?;
    let mut registry = Registry::with_prefix("subspace_farmer");

    let mut tasks = FuturesUnordered::new();

    loop {
        let nats_client = nats_client.clone();
        let additional_components = subcommand.extract_additional_components();

        tasks.push(match subcommand {
            ClusterSubcommand::Controller(controller_args) => {
                controller(nats_client, &mut registry, controller_args).await?
            }
            ClusterSubcommand::Farmer(farmer_args) => {
                farmer::<PosTable>(nats_client, &mut registry, farmer_args).await?
            }
            ClusterSubcommand::Plotter(plotter_args) => {
                plotter::<PosTable>(nats_client, &mut registry, plotter_args).await?
            }
            ClusterSubcommand::Cache(cache_args) => {
                cache(nats_client, &mut registry, cache_args).await?
            }
        });

        if additional_components.is_empty() {
            break;
        }

        let binary_name = current_exe()
            .ok()
            .and_then(|path| {
                path.file_name()
                    .and_then(|file_name| file_name.to_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "subspace-farmer".to_string());
        ClusterSubcommands { subcommand } =
            ClusterSubcommands::parse_from([binary_name].into_iter().chain(additional_components));
    }

    if !prometheus_listen_on.is_empty() {
        let prometheus_task = start_prometheus_metrics_server(
            prometheus_listen_on,
            RegistryAdapter::PrometheusClient(registry),
        )?;

        let join_handle = tokio::spawn(prometheus_task);
        tasks.push(Box::pin(async move {
            Ok(AsyncJoinOnDrop::new(join_handle, true).await??)
        }));
    }

    select! {
        // Signal future
        _ = signal.fuse() => {
            Ok(())
        },

        // Run future
        result = tasks.next() => {
            result.expect("List of tasks is not empty; qed")
        },
    }
}

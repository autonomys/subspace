//! Simple bootstrap node implementation

#![feature(type_changing_struct_update)]

use clap::Parser;
use futures::{select, FutureExt};
use libp2p::identity::ed25519::Keypair;
use libp2p::kad::Mode;
use libp2p::{identity, Multiaddr, PeerId};
use prometheus_client::registry::Registry;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;
use std::{panic, process, thread};
use subspace_metrics::{start_prometheus_metrics_server, RegistryAdapter};
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::{peer_id, Config, KademliaMode};
use tokio::runtime::{Handle, Runtime};
use tokio::signal;
use tracing::{debug, error, info, Level};
use tracing_subscriber::fmt::Subscriber;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Size of the LRU cache for peers.
pub const KNOWN_PEERS_CACHE_SIZE: u32 = 10000;

/// The amount of time we wait for tasks to finish when shutting down.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);

/// When shutting down, the amount of extra time we wait for async task dumps to complete, or the
/// user to trace the process, before exiting.
pub const TRACE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Parser)]
#[clap(about, version)]
enum Command {
    /// Start bootstrap node
    Start {
        /// Multiaddresses of bootstrap nodes to connect to on startup, multiple are supported
        #[arg(long = "bootstrap-node")]
        bootstrap_nodes: Vec<Multiaddr>,
        /// Keypair for node identity, can be obtained with `generate-keypair` command
        #[clap(long)]
        keypair: String,
        /// Multiaddr to listen on for subspace networking, multiple are supported
        #[arg(long, default_values_t = [
            Multiaddr::from(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                .with(Protocol::Tcp(0)),
            Multiaddr::from(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
                .with(Protocol::Tcp(0))
        ])]
        listen_on: Vec<Multiaddr>,
        /// Multiaddresses of reserved peers to maintain connections to, multiple are supported
        #[arg(long = "reserved-peer")]
        reserved_peers: Vec<Multiaddr>,
        /// Maximum established incoming connections limit for the peer.
        #[arg(long, default_value_t = 300)]
        in_peers: u32,
        /// Maximum established outgoing connections limit for the peer.
        #[arg(long, default_value_t = 300)]
        out_peers: u32,
        /// Maximum pending incoming connections limit for the peer.
        #[arg(long, default_value_t = 300)]
        pending_in_peers: u32,
        /// Maximum pending outgoing connections limit for the peer.
        #[arg(long, default_value_t = 300)]
        pending_out_peers: u32,
        /// Enable non-global (private, shared, loopback..) addresses in the Kademlia DHT.
        /// By default these addresses are excluded from the DHT.
        #[arg(long, default_value_t = false)]
        allow_private_ips: bool,
        /// Protocol version for libp2p stack, should be set as genesis hash of the blockchain for
        /// production use.
        #[arg(long)]
        protocol_version: String,
        /// Known external addresses
        #[arg(long = "external-address")]
        external_addresses: Vec<Multiaddr>,
        /// Endpoints for the prometheus metrics server. It doesn't start without at least one
        /// specified endpoint. Format: 127.0.0.1:8080
        #[arg(long, aliases = ["metrics-endpoint", "metrics-endpoints"])]
        prometheus_listen_on: Vec<SocketAddr>,
    },
    /// Generate a new keypair
    GenerateKeypair {
        /// Produce output in JSON format.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

/// Helper struct for the `GenerateKeypair` command output.
#[derive(Debug, Serialize, Deserialize)]
struct KeypairOutput {
    keypair: String,
    peer_id: String,
}

impl Display for KeypairOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "PeerId: {}", self.peer_id)?;
        writeln!(f, "Keypair: {}", self.keypair)
    }
}

impl KeypairOutput {
    fn new(keypair: Keypair) -> Self {
        Self {
            keypair: hex::encode(keypair.to_bytes()),
            peer_id: peer_id_from_keypair(keypair).to_base58(),
        }
    }
}

/// Install a panic handler which exits on panics, rather than unwinding. Unwinding can hang the
/// tokio runtime waiting for stuck tasks or threads.
fn set_exit_on_panic() {
    let default_panic_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        default_panic_hook(panic_info);
        exit(1);
    }));
}

fn init_logging() {
    // set default log to info if the RUST_LOG is not set.
    let env_filter = EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();

    let builder = Subscriber::builder().with_env_filter(env_filter).finish();

    builder.init()
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
                tracing::info!("Received SIGINT, shutting down gateway...");
            }),),
        pin!(signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Setting signal handlers must never fail")
            .recv()
            .map(|_| {
                tracing::info!("Received SIGTERM, shutting down gateway...");
            }),),
    )
    .await;
}

#[cfg(not(unix))]
pub(crate) async fn shutdown_signal() {
    signal::ctrl_c()
        .await
        .expect("Setting signal handlers must never fail");

    tracing::info!("Received Ctrl+C, shutting down gateway...");
}

/// Spawns a thread which forces a shutdown after [`SHUTDOWN_TIMEOUT`], if an async task is
/// blocking. If a second Ctrl-C is received, the thread will force a shut down immediately.
///
/// If compiled with `--cfg tokio_unstable,tokio_taskdump`, logs backtraces of the async tasks
/// blocking shutdown on `runtime_handle`.
///
/// When `tokio::main()` returns, the runtime will be dropped. A dropped runtime can wait forever for
/// all async tasks to reach an await point, or all blocking tasks to finish. If the runtime is
/// dropped before the timeout, the underlying `main()` function will return, and the `exit()` in
/// this spawned thread will never be called.
#[cfg_attr(
    not(all(tokio_unstable, tokio_taskdump)),
    expect(unused_variables, reason = "handle only used in some configs")
)]
pub fn spawn_shutdown_watchdog(runtime_handle: Handle) {
    // TODO: replace tokio::main with runtime::Builder, and call Runtime::shutdown_timeout()
    // instead of sleep() and exit()

    thread::spawn(move || {
        // Shut down immediately if we get a second Ctrl-C.
        //
        // A tokio runtime that's shutting down will cancel pending futures, so we need to
        // wait for ctrl_c() on a separate runtime.
        thread::spawn(|| {
            debug!("waiting for a second shutdown signal");
            Runtime::new()
                .expect("creating a runtime to wait for shutdown signal failed")
                .block_on(async {
                    let _ = shutdown_signal().await;
                    info!("second shutdown signal received, shutting down immediately");
                    exit(1);
                });
        });

        debug!(?SHUTDOWN_TIMEOUT, "waiting for tokio runtime to shut down");
        thread::sleep(SHUTDOWN_TIMEOUT);

        // Force a shutdown if a task is blocking.
        error!(?SHUTDOWN_TIMEOUT, "shutdown timed out, forcing an exit");
        info!(
            "run `flamegraph --pid {}` or similar to generate a stack dump",
            process::id()
        );

        // Log all the async tasks and spawn_blocking() tasks that are still running.
        //
        // A tokio runtime that's shutting down will cancel a dump at its first await
        // point, so we need to call dump() on a separate runtime.
        #[cfg(all(tokio_unstable, tokio_taskdump))]
        thread::spawn(move || {
            use tracing::warn;

            error!(
                ?SHUTDOWN_TIMEOUT,
                "shutdown timed out, trying to dump blocking tasks"
            );
            Runtime::new()
                .expect("creating a runtime to dump blocking tasks failed")
                .block_on(async move {
                    for (task_number, task) in handle.dump().await.tasks().iter().enumerate() {
                        let trace = task.trace();
                        warn!(task_number, trace, "blocking task backtrace");
                    }
                });
        });

        // Give the log messages time to flush, and any dumps time to finish.
        thread::sleep(TRACE_TIMEOUT);
        exit(1);
    });
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    set_exit_on_panic();
    init_logging();

    let command: Command = Command::parse();

    match command {
        Command::Start {
            bootstrap_nodes,
            keypair,
            listen_on,
            reserved_peers,
            in_peers,
            out_peers,
            pending_in_peers,
            pending_out_peers,
            allow_private_ips,
            protocol_version,
            external_addresses,
            prometheus_listen_on,
        } => {
            debug!(
                "Libp2p protocol stack instantiated with version: {} ",
                protocol_version
            );

            let decoded_keypair = Keypair::try_from_bytes(hex::decode(keypair)?.as_mut_slice())?;
            let keypair = identity::Keypair::from(decoded_keypair);

            // Metrics
            let should_start_prometheus_server = !prometheus_listen_on.is_empty();
            let mut metrics_registry = Registry::default();
            let dsn_metrics_registry =
                should_start_prometheus_server.then_some(&mut metrics_registry);

            let config = Config {
                listen_on,
                allow_non_global_addresses_in_dht: allow_private_ips,
                reserved_peers,
                max_established_incoming_connections: in_peers,
                max_established_outgoing_connections: out_peers,
                max_pending_incoming_connections: pending_in_peers,
                max_pending_outgoing_connections: pending_out_peers,
                bootstrap_addresses: bootstrap_nodes,
                kademlia_mode: KademliaMode::Static(Mode::Server),
                external_addresses,

                ..Config::new(
                    protocol_version.to_string(),
                    keypair,
                    (),
                    dsn_metrics_registry,
                )
            };

            // These tasks can hang on shutdown or when dropped. But there are no error returns
            // here, so the only way we exit is when a task finishes. That means we can just launch
            // the shutdown watchdog at the end of the block.
            let (node, mut node_runner) =
                subspace_networking::construct(config).expect("Networking stack creation failed.");

            node.on_new_listener(Arc::new({
                let node_id = node.id();

                move |multiaddr| {
                    info!(
                        "Listening on {}",
                        multiaddr.clone().with(Protocol::P2p(node_id))
                    );
                }
            }))
            .detach();

            info!("Subspace Bootstrap Node started");

            let prometheus_task = should_start_prometheus_server
                .then(|| {
                    start_prometheus_metrics_server(
                        prometheus_listen_on,
                        RegistryAdapter::PrometheusClient(metrics_registry),
                    )
                })
                .transpose()?;
            if let Some(prometheus_task) = prometheus_task {
                select! {
                    _ = node_runner.run().fuse() => {},
                    _ = prometheus_task.fuse() => {},
                }
            } else {
                node_runner.run().await
            }
            spawn_shutdown_watchdog(Handle::current());
        }
        Command::GenerateKeypair { json } => {
            let output = KeypairOutput::new(Keypair::generate());

            if json {
                let json_output = serde_json::to_string(&output)?;

                println!("{json_output}")
            } else {
                println!("{output}")
            }
        }
    }

    Ok(())
}

fn peer_id_from_keypair(keypair: Keypair) -> PeerId {
    peer_id(&libp2p::identity::Keypair::from(keypair))
}

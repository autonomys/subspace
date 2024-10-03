// TODO: Remove
#![allow(
    clippy::needless_return,
    reason = "https://github.com/rust-lang/rust-clippy/issues/13458"
)]

use backoff::future::retry;
use backoff::ExponentialBackoff;
use clap::Parser;
use futures::channel::oneshot;
use futures::future::pending;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use parking_lot::Mutex;
use std::error::Error;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subspace_core_primitives::pieces::{Piece, PieceIndex};
use subspace_networking::utils::piece_provider::{NoPieceValidator, PieceProvider, PieceValidator};
use subspace_networking::{Config, Node, PieceByIndexRequestHandler};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, trace, warn, Level};
use tracing_subscriber::fmt::Subscriber;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Defines initial duration between get_piece calls.
const GET_PIECE_INITIAL_INTERVAL: Duration = Duration::from_secs(5);
/// Defines max duration between get_piece calls.
const GET_PIECE_MAX_INTERVAL: Duration = Duration::from_secs(40);

/// Returns piece by its index from farmer's piece cache (L2).
/// Uses retry policy for error handling.
async fn get_piece_from_dsn_cache_with_retries<PV>(
    piece_provider: &PieceProvider<PV>,
    piece_index: PieceIndex,
    max_retries: u32,
) -> Result<Option<Piece>, Box<dyn Error + Send + Sync + 'static>>
where
    PV: PieceValidator,
{
    trace!(%piece_index, "Piece request.");

    let backoff = ExponentialBackoff {
        initial_interval: GET_PIECE_INITIAL_INTERVAL,
        max_interval: GET_PIECE_MAX_INTERVAL,
        // Try until we get a valid piece
        max_elapsed_time: None,
        multiplier: 1.75,
        ..ExponentialBackoff::default()
    };

    let retries = AtomicU32::default();

    retry(backoff, || async {
        let current_attempt = retries.fetch_add(1, Ordering::Relaxed);

        if let Some(piece) = piece_provider.get_piece_from_cache(piece_index).await {
            trace!(%piece_index, current_attempt, "Got piece");
            return Ok(Some(piece));
        }

        if current_attempt >= max_retries {
            if max_retries > 0 {
                debug!(
                    %piece_index,
                    current_attempt,
                    max_retries,
                    "Couldn't get a piece from DSN L2. No retries left."
                );
            }
            return Ok(None);
        }

        trace!(%piece_index, current_attempt, "Couldn't get a piece from DSN L2. Retrying...");

        Err(backoff::Error::transient(
            "Couldn't get piece from DSN".into(),
        ))
    })
    .await
}

#[derive(Debug, Parser)]
struct Args {
    /// Multiaddresses of bootstrap nodes to connect to on startup, multiple are supported
    #[arg(long = "bootstrap-node", required = true)]
    bootstrap_nodes: Vec<Multiaddr>,
    /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses in Kademlia DHT.
    #[arg(long, default_value_t = false)]
    allow_private_ips: bool,
    /// Protocol version for libp2p stack, should be set as genesis hash of the blockchain for
    /// production use.
    #[arg(long, required = true)]
    protocol_version: String,
    /// Defines max established outgoing connections limit for the peer.
    #[arg(long, default_value_t = 100)]
    out_peers: u32,
    /// Defines max pending outgoing connections limit for the peer.
    #[arg(long, default_value_t = 100)]
    pending_out_peers: u32,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    Simple {
        #[arg(long, default_value_t = 100)]
        max_pieces: usize,
        #[arg(long, default_value_t = 0)]
        start_with: usize,
        #[arg(long, default_value_t = 0)]
        retries: u16,
    },
    Parallel {
        #[arg(long, default_value_t = 100)]
        max_pieces: usize,
        #[arg(long, default_value_t = 0)]
        start_with: usize,
        #[arg(long, default_value_t = 0)]
        retries: u16,
        #[arg(long, default_value_t = 1)]
        parallelism_level: u16,
        #[arg(long, default_value_t = 1)]
        repeat: u16,
    },
}

#[tokio::main]
async fn main() {
    init_logging();

    let args: Args = Args::parse();

    info!(?args, "Benchmark started.");

    let node = configure_dsn(
        args.bootstrap_nodes,
        args.protocol_version,
        args.allow_private_ips,
        args.pending_out_peers,
        args.out_peers,
    )
    .await;

    match args.command {
        Command::Simple {
            max_pieces,
            start_with,
            retries,
        } => {
            simple_benchmark(node, max_pieces, start_with, retries).await;
        }
        Command::Parallel {
            max_pieces,
            start_with,
            retries,
            parallelism_level,
            repeat,
        } => {
            parallel_benchmark(
                node,
                max_pieces,
                start_with,
                retries,
                parallelism_level,
                repeat,
            )
            .await;
        }
    }

    info!("Exiting..");
}

#[derive(Debug, Default)]
struct PieceRequestStats {
    found: u32,
    not_found: u32,
    error: u32,
}

impl PieceRequestStats {
    fn add_found(&mut self) {
        self.found += 1;
    }

    fn add_not_found(&mut self) {
        self.not_found += 1;
    }

    fn add_error(&mut self) {
        self.error += 1;
    }

    fn display(&self) {
        info!("Piece requests:");
        if self.found > 0 {
            info!("Found: {}", self.found);
        }
        if self.not_found > 0 {
            warn!("Not found: {}", self.not_found);
        }
        if self.error > 0 {
            error!("Error: {}", self.error);
        }
    }
}

async fn simple_benchmark(node: Node, max_pieces: usize, start_with: usize, retries: u16) {
    let mut stats = PieceRequestStats::default();
    if max_pieces == 0 {
        error!("Incorrect max_pieces variable set:{max_pieces}");
        return;
    }

    let piece_provider = PieceProvider::<NoPieceValidator>::new(node, None);
    let mut total_duration = Duration::default();
    for i in start_with..(start_with + max_pieces) {
        let piece_index = PieceIndex::from(i as u64);
        let start = Instant::now();
        let piece =
            get_piece_from_dsn_cache_with_retries(&piece_provider, piece_index, u32::from(retries))
                .await;
        let end = Instant::now();
        let duration = end.duration_since(start);
        total_duration += duration;
        match piece {
            Ok(Some(_)) => {
                info!(%piece_index, ?duration, "Piece found.");
                stats.add_found();
            }
            Ok(None) => {
                warn!(%piece_index, ?duration, "Piece not found.");
                stats.add_not_found();
            }
            Err(error) => {
                error!(%piece_index, ?duration, ?error, "Piece request failed.");
                stats.add_error();
            }
        }
    }
    let average_duration = total_duration / max_pieces as u32;
    info!("Total time for {max_pieces} pieces: {:?}", total_duration);
    info!(
        "Average time for {max_pieces} pieces: {:?}",
        average_duration
    );
    stats.display();
}

async fn parallel_benchmark(
    node: Node,
    max_pieces: usize,
    start_with: usize,
    retries: u16,
    parallelism_level: u16,
    repeat: u16,
) {
    let start = Instant::now();
    let mut stats = PieceRequestStats::default();
    if max_pieces == 0 {
        error!("Incorrect max_pieces variable set:{max_pieces}");
        return;
    }

    let semaphore = &Semaphore::new(parallelism_level.into());

    let piece_provider = &PieceProvider::<NoPieceValidator>::new(node, None);
    let mut total_duration = Duration::default();
    let mut pure_total_duration = Duration::default();
    let mut pending_pieces = (start_with..(start_with + max_pieces))
        .cycle()
        .take(max_pieces * repeat as usize)
        .map(|i| {
            let piece_index = PieceIndex::from(i as u64);
            async move {
                let start = Instant::now();

                let permit = semaphore
                    .acquire()
                    .await
                    .expect("Semaphore cannot be closed.");
                let semaphore_acquired = Instant::now();
                let maybe_piece = get_piece_from_dsn_cache_with_retries(
                    piece_provider,
                    piece_index,
                    u32::from(retries),
                )
                .await;

                let end = Instant::now();
                let pure_duration = end.duration_since(semaphore_acquired);
                let full_duration = end.duration_since(start);

                drop(permit);

                (piece_index, maybe_piece, pure_duration, full_duration)
            }
        })
        .collect::<FuturesUnordered<_>>();

    while let Some((piece_index, maybe_piece, pure_duration, full_duration)) =
        pending_pieces.next().await
    {
        total_duration += full_duration;
        pure_total_duration += pure_duration;
        match maybe_piece {
            Ok(Some(_)) => {
                info!(%piece_index, ?pure_duration, ?full_duration, "Piece found.");
                stats.add_found();
            }
            Ok(None) => {
                warn!(%piece_index, ?pure_duration, ?full_duration, "Piece not found.");
                stats.add_not_found();
            }
            Err(error) => {
                error!(%piece_index, ?pure_duration, ?full_duration, ?error, "Piece request failed.");
                stats.add_error();
            }
        }
    }

    let average_duration = total_duration / max_pieces as u32;
    let average_pure_duration = pure_total_duration / max_pieces as u32;
    info!(
        "Total time for {max_pieces} pieces: {:?}",
        Instant::now().duration_since(start)
    );
    info!(
        "Average time for {max_pieces} pieces: {:?}",
        average_duration
    );
    info!(
        "Average (no wait) time for {max_pieces} pieces: {:?}",
        average_pure_duration
    );
    stats.display();
}

pub async fn configure_dsn(
    bootstrap_addresses: Vec<Multiaddr>,
    protocol_prefix: String,
    allow_private_ips: bool,
    pending_out_peers: u32,
    out_peers: u32,
) -> Node {
    let keypair = Keypair::generate_ed25519();

    let default_config = Config::new(protocol_prefix, keypair, (), None);

    let config = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: allow_private_ips,
        request_response_protocols: vec![PieceByIndexRequestHandler::create(|_, _| async { None })],
        bootstrap_addresses,
        max_pending_outgoing_connections: pending_out_peers,
        max_established_outgoing_connections: out_peers,
        ..default_config
    };
    let (node, mut node_runner_1) = subspace_networking::construct(config).unwrap();

    let (node_address_sender, node_address_receiver) = oneshot::channel();
    let on_new_listener_handler = node.on_new_listener(Arc::new({
        let node_address_sender = Mutex::new(Some(node_address_sender));

        move |address| {
            if matches!(address.iter().next(), Some(Protocol::Ip4(_))) {
                if let Some(node_address_sender) = node_address_sender.lock().take() {
                    node_address_sender.send(address.clone()).unwrap();
                }
            }
        }
    }));

    tokio::spawn({
        let node = node.clone();
        async move {
            let _ = node.bootstrap().await;

            pending::<()>().await;
        }
    });

    tokio::spawn(async move {
        node_runner_1.run().await;
    });

    // Wait for first node to know its address
    let node_addr = node_address_receiver.await.unwrap();
    drop(on_new_listener_handler);

    println!("Node ID is {}", node.id());
    println!("Node address {}", node_addr);

    node
}

fn init_logging() {
    // set default log to info if the RUST_LOG is not set.
    let env_filter = EnvFilter::builder()
        .with_default_directive(Level::INFO.into())
        .from_env_lossy();

    let builder = Subscriber::builder().with_env_filter(env_filter).finish();

    builder.init()
}

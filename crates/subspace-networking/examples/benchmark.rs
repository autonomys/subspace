use clap::Parser;
use futures::channel::oneshot;
use futures::future::pending;
use libp2p::identity::Keypair;
use libp2p::kad::Mode;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subspace_core_primitives::PieceIndex;
use subspace_networking::utils::piece_provider::{NoPieceValidator, PieceProvider, RetryPolicy};
use subspace_networking::{Config, Node, PeerInfoProvider, PieceByIndexRequestHandler};
use tracing::{error, info, warn, Level};
use tracing_subscriber::fmt::Subscriber;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
struct Args {
    /// Multiaddresses of bootstrap nodes to connect to on startup, multiple are supported
    #[arg(long, alias = "bootstrap-node", required = true)]
    bootstrap_nodes: Vec<Multiaddr>,
    /// Determines whether we allow keeping non-global (private, shared, loopback..) addresses in Kademlia DHT.
    #[arg(long, default_value_t = false)]
    enable_private_ips: bool,
    /// Protocol version for libp2p stack, should be set as genesis hash of the blockchain for
    /// production use.
    #[arg(long, required = true)]
    protocol_version: String,
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
        args.enable_private_ips,
    )
    .await;

    match args.command {
        Command::Simple {
            max_pieces,
            start_with,
        } => {
            simple_benchmark(node, max_pieces, start_with).await;
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

async fn simple_benchmark(node: Node, max_pieces: usize, start_with: usize) {
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
        let piece = piece_provider
            .get_piece(piece_index, RetryPolicy::Limited(0))
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

pub async fn configure_dsn(
    bootstrap_addresses: Vec<Multiaddr>,
    protocol_prefix: String,
    enable_private_ips: bool,
) -> Node {
    let keypair = Keypair::generate_ed25519();

    let default_config = Config::new(protocol_prefix, keypair, (), Some(PeerInfoProvider::Client));

    let config = Config {
        listen_on: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
        allow_non_global_addresses_in_dht: enable_private_ips,
        kademlia_mode: Some(Mode::Client),
        request_response_protocols: vec![PieceByIndexRequestHandler::create(|_, _| async { None })],
        bootstrap_addresses,
        enable_autonat: false,
        ..default_config
    };
    let (node, mut node_runner_1) = subspace_networking::create(config).unwrap();

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

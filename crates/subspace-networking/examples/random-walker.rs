// TODO: Remove
#![allow(
    clippy::needless_return,
    reason = "https://github.com/rust-lang/rust-clippy/issues/13458"
)]

use clap::Parser;
use futures::channel::oneshot;
use futures::future::pending;
use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subspace_core_primitives::pieces::PieceIndex;
use subspace_networking::protocols::request_response::handlers::piece_by_index::{
    PieceByIndexRequest, PieceByIndexRequestHandler, PieceByIndexResponse,
};
use subspace_networking::{Config, Multihash, Node, PeerDiscovered, SendRequestError};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::fmt::Subscriber;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

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
    /// Enable piece retrieval retries on unsuccessful requests.
    #[arg(long, default_value_t = 0)]
    retries: u32,
    /// Logs peer and their addresses failed on dialing.
    #[arg(long, default_value_t = true)]
    print_failed_addresses: bool,
}

#[tokio::main]
async fn main() {
    init_logging();

    let args: Args = Args::parse();

    info!(?args, "Random walker started.");

    let node = configure_dsn(
        args.bootstrap_nodes,
        args.protocol_version,
        args.allow_private_ips,
        args.pending_out_peers,
        args.out_peers,
    )
    .await;

    start_walking(node, args.retries, args.print_failed_addresses).await;

    info!("Exiting..");
}

#[derive(Debug, Default)]
struct RequestResults {
    successful_requests: u32,
    /// Error type, error number
    failed_requests: HashMap<String, u32>,
}

#[derive(Debug, Default)]
struct PeerStats {
    request_results: HashMap<PeerId, RequestResults>,
    no_peers_found: u32,
    /// error type, number
    get_closest_peers_errors: HashMap<String, u32>,
    successful_retries: u32,
    failed_retries: u32,
}
impl PeerStats {
    fn report_successful_request(&mut self, peer_id: PeerId, retry: bool) {
        self.request_results
            .entry(peer_id)
            .and_modify(|res| res.successful_requests += 1)
            .or_insert(RequestResults {
                successful_requests: 1,
                ..Default::default()
            });

        if retry {
            self.successful_retries += 1;
        }
    }

    fn report_failed_request(&mut self, peer_id: PeerId, error: String, retry: bool) {
        self.request_results
            .entry(peer_id)
            .and_modify(|err| {
                err.failed_requests
                    .entry(error.clone())
                    .and_modify(|num| *num += 1)
                    .or_insert(1);
            })
            .or_insert(RequestResults {
                failed_requests: HashMap::from_iter(vec![(error, 1)]),
                ..Default::default()
            });

        if retry {
            self.failed_retries += 1;
        }
    }

    fn report_get_closest_peers_error(&mut self, error: String) {
        self.get_closest_peers_errors
            .entry(error)
            .and_modify(|number| *number += 1)
            .or_insert(1);
    }

    fn report_peers_not_found_event(&mut self) {
        self.no_peers_found += 1;
    }

    fn display(&self) {
        info!("                               ");
        info!("*******************************");
        info!("                               ");
        info!("Peer stats:");
        let successful_requests = self
            .request_results
            .values()
            .fold(0, |acc, res| acc + res.successful_requests);
        if successful_requests > 0 {
            info!("Successful piece requests: {}", successful_requests);
        }
        let total_failed_requests = self.request_results.values().fold(0, |acc, res| {
            acc + res.failed_requests.values().sum::<u32>()
        });

        if total_failed_requests > 0 {
            warn!("Failed piece requests: {}", total_failed_requests);

            let errors =
                self.request_results
                    .values()
                    .fold(HashMap::new(), |mut acc, peer_result| {
                        for (error_type, err_num) in &peer_result.failed_requests {
                            acc.entry(error_type)
                                .and_modify(|num| *num += *err_num)
                                .or_insert(*err_num);
                        }

                        acc
                    });

            for (error_type, err_num) in errors.into_iter() {
                warn!("Failed piece request type - {} : {}", error_type, err_num);
            }
        }
        if !self.get_closest_peers_errors.is_empty() {
            let total_error_number = self.get_closest_peers_errors.values().sum::<u32>();
            error!("Total 'get_closest_peers' errors: {}", total_error_number);
            for (error_type, error_number) in &self.get_closest_peers_errors {
                error!(
                    "'get_closest_peers' error type: {}  number: {}",
                    error_type, error_number
                );
            }
        }
        if self.no_peers_found > 0 {
            error!("'No peers found' events: {}", self.no_peers_found);
        }

        // Retries
        if self.successful_retries > 0 {
            info!("Successful retries: {}", self.successful_retries);
        }
        if self.failed_retries > 0 {
            error!("Failed retries: {}", self.failed_retries);
        }

        // Peers stats
        let unresponsive_peers = self
            .request_results
            .values()
            .filter(|stats| stats.successful_requests == 0)
            .count();
        warn!("Unresponsive peers number: {}", unresponsive_peers);
        let responsive_peers = self
            .request_results
            .values()
            .filter(|stats| stats.successful_requests > 0)
            .count();
        info!("Responsive peers number: {}", responsive_peers);
        info!("Known peers number: {}", self.request_results.len());
        info!("                               ");
        info!("*******************************");
    }
}

struct RetryJob {
    retries_left: u32,
    peer_id: PeerId,
    short_key: Vec<u8>,
}

async fn start_walking(node: Node, retries: u32, print_failed_addresses: bool) {
    let discovered_peers = Arc::new(Mutex::new(HashMap::<PeerId, PeerDiscovered>::new()));
    node.on_discovered_peer({
        let discovered_peers = discovered_peers.clone();
        Arc::new(move |event| {
            discovered_peers
                .lock()
                .insert(event.peer_id(), event.clone());
        })
    })
    .detach();

    const DISPLAY_DELAY_IN_SECS: u64 = 10;
    const RETRY_DELAY_IN_SECS: u64 = 100;

    let mut stats = PeerStats::default();
    let mut retry_jobs = Vec::new();
    let mut report_period_start = Instant::now();
    let mut retry_period_start = Instant::now();

    loop {
        let key = Multihash::from(PeerId::random());
        let short_key = &key.to_bytes()[0..4];
        let closest_peers_result = node.get_closest_peers(key).await;
        let mut no_peers_found = true;

        // Try to get sample piece
        match closest_peers_result {
            Ok(mut closest_peers) => {
                while let Some(peer_id) = closest_peers.next().await {
                    debug!(%peer_id, ?short_key, "get_closest_peers returned an item");
                    no_peers_found = false;

                    let (success, _) =
                        request_sample_piece(node.clone(), peer_id, short_key, &mut stats, false)
                            .await;

                    if !success && retries > 0 {
                        retry_jobs.push(RetryJob {
                            retries_left: retries,
                            short_key: short_key.to_vec(),
                            peer_id,
                        });
                    }
                }
            }
            Err(err) => {
                warn!(?err, ?short_key, "get_closest_peers returned an error");
                stats.report_get_closest_peers_error(err.to_string());
            }
        }

        if no_peers_found {
            stats.report_peers_not_found_event();
        }

        // Handle retries
        if retries > 0 {
            let elapsed_time = Instant::now().duration_since(retry_period_start);
            if elapsed_time > Duration::from_secs(RETRY_DELAY_IN_SECS) {
                let mut next_retries = Vec::new();
                while let Some(retry_job) = retry_jobs.pop() {
                    let retries_left = retry_job.retries_left - 1;
                    let (success, last_error) = request_sample_piece(
                        node.clone(),
                        retry_job.peer_id,
                        &retry_job.short_key,
                        &mut stats,
                        true,
                    )
                    .await;

                    if !success && retries_left > 0 {
                        next_retries.push(RetryJob {
                            retries_left,
                            short_key: short_key.to_vec(),
                            peer_id: retry_job.peer_id,
                        })
                    } else if print_failed_addresses {
                        let discovered_peers = discovered_peers.lock();
                        let peer_id = retry_job.peer_id;
                        let peer_info = discovered_peers.get(&peer_id);
                        info!(%peer_id, ?peer_info, ?last_error, "Failed to request piece.");
                    }
                }

                retry_jobs = next_retries;
                retry_period_start = Instant::now();
            }
        }

        // Display stats
        let elapsed_time = Instant::now().duration_since(report_period_start);
        if elapsed_time > Duration::from_secs(DISPLAY_DELAY_IN_SECS) {
            stats.display();
            report_period_start = Instant::now();
        }
    }
}

async fn request_sample_piece(
    node: Node,
    peer_id: PeerId,
    short_key: &[u8],
    stats: &mut PeerStats,
    retry: bool,
) -> (bool, Option<SendRequestError>) {
    let sample_piece_index = PieceIndex::from(0);

    let request_result = node
        .send_generic_request(
            peer_id,
            PieceByIndexRequest {
                piece_index: sample_piece_index,
                cached_pieces: Arc::default(),
            },
        )
        .await;

    match request_result {
        Ok(PieceByIndexResponse {
            piece: Some(..),
            cached_pieces: _,
        }) => {
            debug!(%peer_id, ?short_key, "Piece request succeeded.");
            stats.report_successful_request(peer_id, retry);

            (true, None)
        }
        Ok(PieceByIndexResponse {
            piece: None,
            cached_pieces: _,
        }) => {
            debug!(%peer_id, ?short_key, "Piece request returned empty piece.");
            stats.report_successful_request(peer_id, retry); // we just need to connect to the peer

            (true, None)
        }
        Err(error) => {
            debug!(%peer_id, ?short_key, ?error, "Piece request failed.");
            stats.report_failed_request(peer_id, error.to_string(), retry);

            (false, Some(error))
        }
    }
}

async fn configure_dsn(
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

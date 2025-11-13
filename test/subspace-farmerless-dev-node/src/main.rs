mod manual_rpc;

use clap::Parser;
use domain_test_service::{DomainNodeBuilder, EcdsaKeyring};
use manual_rpc::{
    ConsensusControl, consensus_control_channel, manual_block_production_rpc,
    spawn_consensus_worker,
};
use sc_cli::LoggerBuilder;
use sc_service::{BasePath, Role};
use sp_keyring::Sr25519Keyring;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use subspace_test_service::{MockConsensusNode, MockConsensusNodeRpcConfig};
use tempfile::TempDir;
use tokio::runtime::Builder as TokioBuilder;
use tracing::error;

#[derive(Debug, Parser)]
#[command(
    name = "subspace-farmerless-testnet",
    about = "Starts consensus and domain test nodes together (farmerless)"
)]
struct Cli {
    /// Finalization depth (K). Omit to disable finalization enforcement.
    #[arg(long)]
    finalize_depth: Option<u32>,

    /// Whether to start the EVM domain node
    #[arg(long, default_value_t = false)]
    domain: bool,

    /// Base path for node data. Defaults to a unique temporary directory per run.
    #[arg(long)]
    base_path: Option<PathBuf>,

    /// Consensus RPC host/interface
    #[arg(long, default_value = "127.0.0.1")]
    rpc_host: IpAddr,

    /// Consensus RPC port
    #[arg(long, default_value_t = 9944)]
    rpc_port: u16,

    /// Domain RPC host/interface
    #[arg(long, default_value = "127.0.0.1")]
    domain_rpc_host: IpAddr,

    /// Domain RPC port
    #[arg(long, default_value_t = 9945)]
    domain_rpc_port: u16,

    /// Block production interval in milliseconds (consensus). Use 0 to disable.
    #[arg(long, default_value_t = 6000)]
    block_interval_ms: u64,
}

fn init_logger() {
    let mut logger = LoggerBuilder::new("");
    logger.with_colors(false);
    let _ = logger.init();
}

fn compute_base_path(cli: &Cli) -> (PathBuf, Option<TempDir>) {
    match cli.base_path.clone() {
        Some(p) => (p, None),
        None => {
            let tmp = TempDir::new().expect("Must be able to create temporary directory");
            (tmp.path().to_path_buf(), Some(tmp))
        }
    }
}

fn build_runtime() -> tokio::runtime::Runtime {
    TokioBuilder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Tokio runtime must build")
}

fn start_consensus_node(
    tokio_handle: tokio::runtime::Handle,
    base_path: PathBuf,
    finalize_depth: Option<u32>,
    rpc_host: IpAddr,
    rpc_port: u16,
    consensus_control: ConsensusControl,
) -> MockConsensusNode {
    let private_evm = false;
    let consensus_key = Sr25519Keyring::Alice;
    let rpc_addr = SocketAddr::new(rpc_host, rpc_port);
    let rpc_config = MockConsensusNodeRpcConfig {
        base_path: BasePath::new(base_path),
        finalize_block_depth: finalize_depth,
        private_evm,
        evm_owner: None,
        rpc_addr: Some(rpc_addr),
        rpc_port: Some(rpc_port),
    };

    let mut node = MockConsensusNode::run_with_rpc_builder(
        tokio_handle,
        consensus_key,
        rpc_config,
        Box::new(move || Ok(manual_block_production_rpc(consensus_control.clone()))),
    );
    node.start_network();
    node
}

fn main() {
    init_logger();

    let cli = Cli::parse();
    let (base_path, _temp_dir_guard) = compute_base_path(&cli);
    let block_interval_ms = cli.block_interval_ms;

    let runtime = build_runtime();
    let _enter = runtime.enter();
    let tokio_handle = runtime.handle().clone();

    let (consensus_control, command_rx) = consensus_control_channel();

    // Start consensus
    let consensus_base = base_path.join("consensus");
    let mut consensus = start_consensus_node(
        tokio_handle.clone(),
        consensus_base,
        cli.finalize_depth,
        cli.rpc_host,
        cli.rpc_port,
        consensus_control.clone(),
    );

    // Optionally start domain (EVM)
    let domain = if cli.domain {
        let domain_base = BasePath::new(base_path.join("auto-evm"));
        let domain_addr = SocketAddr::new(cli.domain_rpc_host, cli.domain_rpc_port);
        Some(runtime.block_on(async {
            DomainNodeBuilder::new(tokio_handle.clone(), domain_base)
                .rpc_addr(domain_addr)
                .rpc_port(cli.domain_rpc_port)
                .build_evm_node(Role::Authority, EcdsaKeyring::Alice, &mut consensus)
                .await
        }))
    } else {
        None
    };

    consensus.start_cross_domain_gossip_message_worker();

    let worker_handle = spawn_consensus_worker(consensus, command_rx);

    let consensus_for_loop = consensus_control.clone();
    runtime.block_on(async move {
        let _domain_guard = domain;
        if block_interval_ms > 0 {
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    _ = tokio::time::sleep(Duration::from_millis(block_interval_ms)) => {
                        if let Err(err) = consensus_for_loop.produce_block(true).await {
                            error!(%err, "Failed to auto-produce block");
                        }
                    }
                }
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    });

    if let Err(err) = runtime.block_on(consensus_control.shutdown()) {
        error!(%err, "Failed to shut down consensus control");
    }

    worker_handle
        .join()
        .expect("Failed to join consensus control thread");
}

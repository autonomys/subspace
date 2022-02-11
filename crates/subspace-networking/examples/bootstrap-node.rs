//! Simple bootstrap node implementation

use clap::{AppSettings, Parser};
use env_logger::Env;
use libp2p::identity::ed25519::Keypair;
use libp2p::Multiaddr;
use log::info;
use std::sync::Arc;
use subspace_networking::libp2p::multiaddr::Protocol;
use subspace_networking::Config;

#[derive(Debug, Parser)]
#[clap(about, version)]
#[clap(global_setting(AppSettings::AllArgsOverrideSelf))]
enum Command {
    /// Start bootstrap node
    Start {
        /// Multiaddrs of bootstrap nodes to connect to on startup, multiple are supported
        #[clap(long)]
        bootstrap_node: Vec<Multiaddr>,
        /// Keypair for node identity, can be obtained with `generate-keypair` command
        keypair: String,
        /// Multiaddr to listen on for subspace networking, multiple are supported
        #[clap(default_value = "/ip4/0.0.0.0/tcp/0")]
        listen_on: Vec<Multiaddr>,
    },
    /// Generate a new keypair
    GenerateKeypair,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init_from_env(Env::new().default_filter_or("info"));

    let command: Command = Command::parse();

    match command {
        Command::Start {
            bootstrap_node,
            keypair,
            listen_on,
        } => {
            let config = Config {
                bootstrap_nodes: bootstrap_node,
                listen_on,
                allow_non_globals_in_dht: true,
                ..Config::with_keypair(Keypair::decode(hex::decode(keypair)?.as_mut_slice())?)
            };
            let (node, mut node_runner) = subspace_networking::create(config).await.unwrap();

            node.on_new_listener(Arc::new({
                let node_id = node.id();

                move |multiaddr| {
                    info!(
                        "Listening on {}",
                        multiaddr.clone().with(Protocol::P2p(node_id.into()))
                    );
                }
            }))
            .detach();

            node_runner.run().await
        }
        Command::GenerateKeypair => {
            println!("{}", hex::encode(Keypair::generate().encode()))
        }
    }

    Ok(())
}

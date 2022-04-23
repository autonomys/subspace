# Subspace Executor

## Run an executor local testnet

### Preparation

Compile all the binaries:

```bash
$ cargo build --release --bin subspace-farmer --bin subspace-node
```

### Spin up a local testnet

1. Run a primary node with an executor Alice running in authority mode.

```bash
$ ./target/release/subspace-node --dev -d tmp --log=runtime=debug -- --alice --dev --port 40333 --rpc-port 8845 --ws-port 8846
2022-04-24 17:00:27.700  INFO main sc_cli::runner: Subspace
2022-04-24 17:00:27.700  INFO main sc_cli::runner: ✌️  version 0.1.0-98f7e25b9
2022-04-24 17:00:27.700  INFO main sc_cli::runner: ❤️  by Subspace Labs <https://subspace.network>, 2021-2022
2022-04-24 17:00:27.700  INFO main sc_cli::runner: 📋 Chain specification: Subspace development
2022-04-24 17:00:27.701  INFO main sc_cli::runner: 🏷  Node name: squeamish-notebook-7882
2022-04-24 17:00:27.701  INFO main sc_cli::runner: 👤 Role: AUTHORITY
2022-04-24 17:00:27.701  INFO main sc_cli::runner: 💾 Database: RocksDb at tmp/chains/subspace_dev/db/full
2022-04-24 17:00:27.701  INFO main sc_cli::runner: ⛓  Native runtime: subspace-101 (subspace-1.tx1.au1)
2022-04-24 17:00:27.873  INFO main sc_service::client::client: [PrimaryChain] 🔨 Initializing Genesis block/state (state: 0x1727…4544, header-hash: 0xa3b7…a36c)
2022-04-24 17:00:28.003  INFO main subspace: [PrimaryChain] Starting archiving from genesis
2022-04-24 17:00:28.028  INFO main subspace: [PrimaryChain] Archiving already produced blocks 0..=0
2022-04-24 17:00:28.093  WARN main sc_service::config: [PrimaryChain] Using default protocol ID "sup" because none is configured in the chain specs
2022-04-24 17:00:28.094  INFO main sub-libp2p: [PrimaryChain] 🏷  Local node identity is: 12D3KooWEna4n2m3B6EKXQE1jZhQ5sfYcr9TpVmr8Yk9S8zCpnm4
2022-04-24 17:00:28.096  INFO main subspace: [PrimaryChain] 🧑‍🌾 Starting Subspace Authorship worker
2022-04-24 17:00:28.099  INFO main sc_sysinfo: [PrimaryChain] 💻 Operating system: macos
2022-04-24 17:00:28.099  INFO main sc_sysinfo: [PrimaryChain] 💻 CPU architecture: aarch64
2022-04-24 17:00:28.099  INFO main sc_service::builder: [PrimaryChain] 📦 Highest known block at #0
2022-04-24 17:00:28.099  INFO tokio-runtime-worker substrate_prometheus_endpoint: [PrimaryChain] 〽️ Prometheus exporter started at 127.0.0.1:9615
2022-04-24 17:00:28.100  INFO                 main parity_ws: [PrimaryChain] Listening for new connections on 127.0.0.1:9944.
2022-04-24 17:00:28.100  WARN                 main sc_cli::commands::run_cmd: [SecondaryChain] Running in --dev mode, RPC CORS has been disabled.
2022-04-24 17:00:28.235  INFO                 main sc_service::client::client: [SecondaryChain] 🔨 Initializing Genesis block/state (state: 0x8e63…66a2, header-hash: 0x35d4…5e4f)
2022-04-24 17:00:28.235  WARN                 main sc_service::config: [SecondaryChain] Using default protocol ID "sup" because none is configured in the chain specs 
2022-04-24 17:00:28.236  INFO                 main sub-libp2p: [SecondaryChain] 🏷  Local node identity is: 12D3KooWLDx1XEAyDWoxtJZhEj9WBspb8C9BQbyS7x4n6qoAFsAZ
2022-04-24 17:00:28.326  INFO                 main sc_sysinfo: [SecondaryChain] 💻 Operating system: macos
2022-04-24 17:00:28.326  INFO                 main sc_sysinfo: [SecondaryChain] 💻 CPU architecture: aarch64
2022-04-24 17:00:28.326  INFO                 main sc_service::builder: [SecondaryChain] 📦 Highest known block at #0
2022-04-24 17:00:28.326  INFO tokio-runtime-worker substrate_prometheus_endpoint: [SecondaryChain] 〽️ Prometheus exporter started at 127.0.0.1:9616
2022-04-24 17:00:28.326  INFO                 main parity_ws: [SecondaryChain] Listening for new connections on 127.0.0.1:8846.
```

Note the `Primary node identity`(`12D3KooWEna4n2m3B6EKXQE1jZhQ5sfYcr9TpVmr8Yk9S8zCpnm4`) from the log output. We'll start another primary node running an executor full node in next step and will use it to as a bootnode to connect to this primary node. You can also directly retrieve the primary peer id using the RPC `system_localPeerId`.

Start a farmer:

```bash
$ ./target/release/subspace-farmer wipe && ./target/release/subspace-farmer farm --reward-address REWARD_ADDRESS --plot-size 10G
```

Now the primary node should be producing blocks.

2. Run another executor running as a full node.

```bash
$ ./target/release/subspace-node \
    --chain dev \
    -d db1 \
    --bootnodes "/ip4/127.0.0.1/tcp/30333/p2p/PRIMARY_PEER_ID" \
    --port 30443 \
    --ws-port 9987 \
    -- \
        -- \
        --port 40233 \
        --rpc-port 8745 \
        --ws-port 8746
```

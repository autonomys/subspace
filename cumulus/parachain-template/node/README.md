# Subspace Executor

## Run an executor local testnet

### Preparation

Compile all the binaries:

```bash
$ cargo build --release
```

Build a chain spec which will be used for running the embedded primary node.

```bash
$ ./target/release/subspace-node build-spec --chain=dev --raw --disable-default-bootnode > dev.json
```

### Spin up a local testnet

1. Run a primary node.

```bash
$ ./target/release/subspace-node --dev -d tmp --log=txpool=trace,gossip::executor=trace
2022-04-01 09:45:14.383  INFO main sc_cli::runner: Subspace
2022-04-01 09:45:14.384  INFO main sc_cli::runner: ✌️  version 0.1.0-c3a2fe306-aarch64-macos
2022-04-01 09:45:14.384  INFO main sc_cli::runner: ❤️  by Subspace Labs <https://subspace.network>, 2021-2022
2022-04-01 09:45:14.384  INFO main sc_cli::runner: 📋 Chain specification: Development
2022-04-01 09:45:14.384  INFO main sc_cli::runner: 🏷  Node name: spotty-tomatoes-2275
2022-04-01 09:45:14.384  INFO main sc_cli::runner: 👤 Role: AUTHORITY
2022-04-01 09:45:14.384  INFO main sc_cli::runner: 💾 Database: RocksDb at tmp/chains/dev/db/full
2022-04-01 09:45:14.384  INFO main sc_cli::runner: ⛓  Native runtime: subspace-100 (subspace-1.tx1.au1)
2022-04-01 09:45:14.557  INFO main sc_service::client::client: 🔨 Initializing Genesis block/state (state: 0x5c13…52fa, header-hash: 0x64be…e482)
2022-04-01 09:45:14.693  INFO main subspace: Starting archiving from genesis
2022-04-01 09:45:14.718  INFO main subspace: Archiving already produced blocks 0..=0
2022-04-01 09:45:14.782  WARN main sc_service::config: Using default protocol ID "sup" because none is configured in the chain specs
2022-04-01 09:45:14.782  INFO main sub-libp2p: 🏷  Local node identity is: 12D3KooWRq7JqggfhBMzYY2bhAPzfR44zqgZUkphYi11UrYCVa94
2022-04-01 09:45:14.785  INFO main subspace: 🧑‍🌾 Starting Subspace Authorship worker
2022-04-01 09:45:14.787  INFO main sc_service::builder: 📦 Highest known block at #0
2022-04-01 09:45:14.787  INFO tokio-runtime-worker substrate_prometheus_endpoint: 〽️ Prometheus exporter started at 127.0.0.1:9615
2022-04-01 09:45:14.787  INFO                 main parity_ws: Listening for new connections on 127.0.0.1:9944.
2022-04-01 09:45:19.793  INFO tokio-runtime-worker substrate: 💤 Idle (0 peers), best: #0 (0x64be…e482), finalized #0 (0x64be…e482), ⬇ 0 ⬆ 0
```

Note the `Local node identity`(`12D3KooWRreNzoMVgM6HtPVP27enDaAuPuPbYgGCrSr2RWD8UBGf`) from the log output. the embedded primary node will use it to craft a bootnode for connecting to the primary node. You can also directly retrieve the primary peer id using the RPC `system_localPeerId`.

Start a farmer:

```bash
$ ./target/release/subspace-farmer wipe && ./target/release/subspace-farmer farm
```

Now the primary node should be producing blocks.

2. Run an executor as an authority node.

Ensure the bootnode for the primary node is correct and run this command to start an executor:

```bash
$ ./target/release/subspace-executor \
    --alice \
    --collator \
    --force-authoring \
    --base-path first-db \
    --port 40333 \
    --log=cirrus=trace,txpool=trace,gossip=trace \
    --rpc-port 8845 \
    --ws-port 8846 \
    -- \
        --validator \
        --log=trace \
        --chain dev.json \
        --bootnodes "/ip4/127.0.0.1/tcp/30333/p2p/PRIMARY_PEER_ID" \
        --port 30343 \
        --ws-port 9977
```

The log for running the secondary node will be prefixed as `[Secondarychain]`, you should see it start to produce blocks as well.

```
...
2022-04-01 09:34:56.010 TRACE tokio-runtime-worker cirrus::executor: [Secondarychain] Origin deduplicated extrinsics extrinsics=[]
2022-04-01 09:34:56.011 TRACE tokio-runtime-worker cirrus::executor: [Secondarychain] Shuffled extrinsics shuffled_extrinsics=[]
2022-04-01 09:34:56.013 TRACE tokio-runtime-worker txpool: [Secondarychain] Pruning transactions: []
2022-04-01 09:34:56.013 DEBUG tokio-runtime-worker txpool: [Secondarychain] Starting pruning of block BlockId::Hash(0x7089dfba167eeb17b361126db248dbb0bb2a1ded9f485e20c517b3a8f5800604) (extrinsics: 0)
2022-04-01 09:34:56.013 DEBUG tokio-runtime-worker txpool: [Secondarychain] Pruning at BlockId::Hash(0x7089dfba167eeb17b361126db248dbb0bb2a1ded9f485e20c517b3a8f5800604)
2022-04-01 09:34:56.013 TRACE tokio-runtime-worker txpool: [Secondarychain] Pruning at BlockId::Hash(0x7089dfba167eeb17b361126db248dbb0bb2a1ded9f485e20c517b3a8f5800604). Resubmitting transactions.
2022-04-01 09:34:56.013  INFO tokio-runtime-worker substrate: [Secondarychain] ✨ Imported #18 (0x7089…0604)
2022-04-01 09:34:56.013 DEBUG tokio-runtime-worker cirrus::executor: [Secondarychain] Trace root calculated for #0x7089…0604 trace=[0xe99ff5a2f994e4832ffc093c10b4d1d294a401b0bbd9d52db7523716d9864140, 0x63cf7a793cc3c20f68cd3d683ba9effe7d87245ddf3b0c52ba9bac43eef7b653] trace_root=[23, 87, 107, 20, 223, 81, 204, 197, 221, 24, 70, 36, 204, 4, 23, 135, 162, 250, 135, 179, 131, 83, 169, 73, 9, 72, 122, 237, 90, 139, 239, 25]
...

```

3. Run another executor as a full node.

```bash
$ ./target/release/subspace-executor \
    --alice \
    --base-path second-db \
    --port 40233 \
    --log=cirrus=trace,txpool=trace,gossip=trace \
    --rpc-port 8745 \
    --ws-port 8746 \
    -- \
        --validator \
        --log=trace \
        --chain dev.json \
        --bootnodes "/ip4/127.0.0.1/tcp/30333/p2p/PRIMARY_PEER_ID" \
        --port 30443 \
        --ws-port 9987
```

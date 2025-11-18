# Subspace Farmerless Dev Node

Developer utility binary that boots a local Subspace consensus node (mocked farmerless setup) and, optionally, an EVM domain node for integration testing and manual experimentation. It wraps helpers from `subspace-test-service` and `domain-test-service` so that devs can exercise cross-domain flows without spinning up a full farmer.

## Prerequisites

- Rust toolchain with `cargo`
- Workspace dependencies built once (`cargo build -p subspace-farmerless-dev-node`)

## Usage

From the workspace root:

```
cargo run -p subspace-farmerless-dev-node -- [FLAGS/OPTIONS]
```

Common flags:

- `--finalize-depth <K>`: Enforce finalization depth; omit to disable.
- `--domain`: Start the EVM domain node alongside consensus.
- `--base-path <PATH>`: Persist data instead of using a temp dir.
- `--rpc-host <IP>` / `--rpc-port <PORT>`: Consensus RPC interface (defaults `127.0.0.1:9944`).
- `--domain-rpc-host <IP>` / `--domain-rpc-port <PORT>`: Domain RPC interface (defaults `127.0.0.1:9945`).
- `--block-interval-ms <MS>`: Slot and block production cadence (default `6000`; use `0` to disable auto-production).

To inspect the full CLI help, run:

```
cargo run -p subspace-farmerless-dev-node -- --help
```

## Typical Scenarios

- **Quick smoke test:** `cargo run -p subspace-farmerless-dev-node` (produces consensus blocks every 6s using temp storage).
- **Run with domain node:** `cargo run -p subspace-farmerless-dev-node -- --domain`.
- **Fast integration testing:** `cargo run -p subspace-farmerless-dev-node -- --block-interval-ms 500 --domain`.
- **Manual block production:** `cargo run -p subspace-farmerless-dev-node -- --block-interval-ms 0 --domain` and trigger blocks via RPC helpers.

## Manual Block Production RPCs

When `--block-interval-ms 0` is set, the node exposes JSON-RPC endpoints for manual block production:

### `dev_produceBlock`

Produce a single consensus block.

**Parameters:**

- `wait_for_bundle` (optional, boolean): If `true`, wait for domain bundle submission before producing the block. Defaults to `false`.

**Example:**

```bash
curl -H "Content-Type: application/json" \
     --data '{"jsonrpc":"2.0","id":1,"method":"dev_produceBlock","params":[true]}' \
     http://127.0.0.1:9944
```

### `dev_produceBlocks`

Produce multiple consensus blocks.

**Parameters:**

- `count` (required, number): Number of blocks to produce.
- `wait_for_bundle` (optional, boolean): If `true`, wait for domain bundle submission before each block. Defaults to `false`.

**Example:**

```bash
# Produce 5 blocks without waiting for bundles
curl -H "Content-Type: application/json" \
     --data '{"jsonrpc":"2.0","id":1,"method":"dev_produceBlocks","params":[5]}' \
     http://127.0.0.1:9944

# Produce 5 blocks, waiting for bundles
curl -H "Content-Type: application/json" \
     --data '{"jsonrpc":"2.0","id":1,"method":"dev_produceBlocks","params":[5,true]}' \
     http://127.0.0.1:9944
```

**Note:** When `wait_for_bundle` is `true`, the domain node must be running (`--domain` flag) or the RPC call will timeout waiting for bundle submission.

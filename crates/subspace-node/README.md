<div align="center">

  <h1><code>subspace-node</code></h1>

  <strong>A Subspace Network Blockchain node.</strong>

</div>

# Overview

This repo is an implementation of Substrate consensus on Substrate framework.

# Subspace node

## Getting Started

Follow these steps to get started with the Subspace Node :hammer_and_wrench:

Note that this repo is for running a Subspace node. In order to run a full node which participates in consensus and produces blocks you must also run a subspace-farmer.

### Run with Docker

**Note:** These instructions assume you run the farmer in one terminal and the client in a second terminal.

First, install [Docker](https://docs.docker.com/get-docker/).

#### Run the Client (Terminal 1)

Create virtual network, pull the latest image and start a single node development chain:
```bash
docker network create subspace
docker pull subspacelabs/subspace-node
docker run --rm --init -it \
  --net subspace \
  --name subspace-node \
  --publish 127.0.0.1:30333:30333 \
  --publish 127.0.0.1:9944:9944 \
  --publish 127.0.0.1:9933:9933 \
  subspacelabs/subspace-node \
    --dev \
    --tmp \
    --ws-external \
    --node-key 0000000000000000000000000000000000000000000000000000000000000001
```

#### Run the Farmer (Terminal 2)

Once node is running, create volume for plot, pull the latest image and connect farmer to the node by running following in a separate terminal:
```bash
docker volume create subspace-farmer
docker pull subspacelabs/subspace-farmer
docker run --rm --init -it \
  --net subspace \
  --name subspace-farmer \
  --mount source=subspace-farmer,target=/var/subspace \
  subspacelabs/subspace-farmer \
    farm \
    --node-rpc-url ws://subspace-node:9944
```

Now you should see block production in the first terminal where node is running.

#### Running Full Client

We can now run another full client and sync the chain from the client we started earlier:
```
BOOTSTRAP_CLIENT_IP=$(docker inspect -f "{{.NetworkSettings.Networks.subspace.IPAddress}}" subspace-node)
docker run --rm --init -it \
  --net subspace \
  --name subspace-node-full \
  subspacelabs/subspace-node \
    --dev \
    --tmp \
    --ws-external \
    --bootnodes /ip4/$BOOTSTRAP_CLIENT_IP/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp
```

#### Running Light Client

We can also run light client and sync the chain from the client we started earlier:
```
BOOTSTRAP_CLIENT_IP=$(docker inspect -f "{{.NetworkSettings.Networks.subspace.IPAddress}}" subspace-node)
docker run --rm --init -it \
  --net subspace \
  --name subspace-node-light \
  subspacelabs/subspace-node \
    --dev \
    --tmp \
    --light \
    --ws-external \
    --bootnodes /ip4/$BOOTSTRAP_CLIENT_IP/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp
```

#### Run more nodes on the test network

If above setup is not enough, you can use `run-node-farmer-pair.sh` script to run more full nodes on the network, each with own farmer.

Usage is simple:
```
./run-node-farmer-pair.sh test
```

Where `test` is the name of the pair. You can create as many pairs as needed, they will all join the same test network.

Use `Ctrl+C` to stop the pair, everything will be stopped and cleaned up automatically.

### Run In Development Mode

#### Install Rust

Install Rust toolchain with [rustup.rs](https://rustup.rs/).

If you didn't re-login yet, make sure configure your shell in the meantime:
```bash
source ~/.cargo/env
```

Install nightly toolchain and wasm32 target for it:
```bash
rustup toolchain install nightly
rustup target add wasm32-unknown-unknown --toolchain nightly
```

#### Install Dependencies

On Linux, RocksDB requires Clang:
```bash
sudo apt-get install llvm clang
```

#### Install and Run Node

This will run a subspace-node in one terminal and a subspace-farmer farming in a second terminal.
The node will send slot notification challenges to the farmer.
If the farmer finds a valid solution it will reply, and the node will produce a new block.

```bash
# Get source code
git clone https://github.com/subspace/subspace.git
cd subspace

# Build and run Node (first terminal)
cargo run --bin subspace-node -- --dev --tmp

# wait for the client to start before continuing...

# Run Farmer (second terminal)
cargo run --bin subspace-farmer -- farm
```

### Test equivocation behavior
1. Run bootstrap client node with farmer according to instructions in "Run with Docker" section above
2. Start the first full client node and farmer with the same identity as the bootstrap client node:
  1. In one terminal run full client:
      ```bash
      BOOTSTRAP_CLIENT_IP=$(docker inspect -f "{{.NetworkSettings.Networks.subspace.IPAddress}}" subspace-node)
      docker run --rm --init -it \
        --net subspace \
        --name subspace-node-full-1 \
        subspacelabs/subspace-node \
          --dev \
          --tmp \
          --ws-external \
          --bootnodes /ip4/$BOOTSTRAP_CLIENT_IP/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp
      ```
  2. In another terminal plot with the same identity:
      ```bash
      docker volume create subspace-farmer-1
      docker run --rm -it \
        --entrypoint=/bin/cp \
        --mount source=subspace-farmer,target=/var/subspace-src \
        --mount source=subspace-farmer-1,target=/var/subspace \
        subspacelabs/subspace-farmer cp /var/subspace-src/identity.bin /var/subspace/identity.bin
      docker run --rm -it \
        --name subspace-farmer-1 \
        --mount source=subspace-farmer-1,target=/var/subspace \
        subspacelabs/subspace-farmer plot 256000 subspace
      ```
  3. And start farming while being connected to the full client:
      ```bash
      docker run --rm --init -it \
        --net subspace \
        --name subspace-farmer-1 \
        --mount source=subspace-farmer-1,target=/var/subspace \
        subspacelabs/subspace-farmer \
          farm \
          --node-rpc-url ws://subspace-node-full-1:9944
      ```
3. Repeat 2. with `-1` replaced with `-2` everywhere in order to obtain one more pair of client and farmer
4. Observe following messages in logs similar to these, also block production will stop:
    ```
    Slot author Public(X (Y...)) is equivocating at slot Z with headers W and A
    Submitted Subspace equivocation report.
    Submitted equivocation report for author Public(X (Y...))
    Ignoring solution for slot X provided by farmer in block list: Y
    ```

### Run Tests

```bash
cargo test
```

### Embedded Docs

Once the project has been built, the following command can be used to explore all parameters and
subcommands:

```bash
cargo run --bin subspace-node -- --help
```

## Run

The provided `cargo run` command will launch a temporary node and its state will be discarded after
you terminate the process. After the project has been built, there are other ways to launch the
node.

### Single-Node Development Chain

This command will start the single-node development chain with persistent state:

```bash
cargo run --bin subspace-node -- --dev
```

Purge the development chain's state:

```bash
cargo run --bin subspace-node -- purge-chain --dev
```

Start the development chain with detailed logging:

```bash
RUST_BACKTRACE=1 cargo run --bin subspace-node -- -ldebug --dev
```

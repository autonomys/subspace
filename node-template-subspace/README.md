<div align="center">

  <h1><code>node-template-subspace</code></h1>

  <strong>A Substrate Node Template which implements Subspace consensus.</strong>

</div>

# Overview

This repo is an implementation of Substrate consensus on Substrate framework.

# Node Template Subspace

A fresh FRAME-based [Substrate](https://www.substrate.io/) node, modified for Subspace consensus :rocket:

Based on a fork of Substrate Node Template.

**Notes:** The code is un-audited and not production ready, use it at your own risk.

## Getting Started

Follow these steps to get started with the Subspace Node Template :hammer_and_wrench:

Note that this repo is for running a Subspace node. In order to run a full node which participates in consensus and produces blocks you must also run a subspace-farmer.

### Run with Docker

**Note:** These instructions assume you run the farmer in one terminal and the client in a second terminal.

First, install [Docker](https://docs.docker.com/get-docker/).

#### Initialize Farmer (Terminal 1)

Create volume for plot, pull latest image and initialize 1 GiB plot (should take a thirty seconds to a few minutes):
```bash
docker volume create subspace-farmer
docker pull subspacelabs/subspace-farmer
docker run --rm -it \
  --name subspace-farmer \
  --mount source=subspace-farmer,target=/var/subspace \
  subspacelabs/subspace-farmer plot 256000 subspace
```

#### Run the Client (Terminal 2)

Create virtual network, pull latest image and start a single node development chain:
```bash
docker network create subspace
docker pull subspacelabs/node-template-subspace
docker run --rm --init -it \
  --net subspace \
  --name node-template-subspace \
  --publish 127.0.0.1:30333:30333 \
  --publish 127.0.0.1:9944:9944 \
  --publish 127.0.0.1:9933:9933 \
  subspacelabs/node-template-subspace \
    --dev \
    --tmp \
    --ws-external \
    --node-key 0000000000000000000000000000000000000000000000000000000000000001
```

#### Run the Farmer (Terminal 1)

Once node is running, you can connect farmer to it by running following in a separate terminal:
```bash
docker run --rm --init -it \
  --net subspace \
  --name subspace-farmer \
  --mount source=subspace-farmer,target=/var/subspace \
  subspacelabs/subspace-farmer \
    farm \
    --ws-server ws://node-template-subspace:9944
```

Now you should see block production in the first terminal where node is running.

#### Stopping the Client

The client container may not respond to kill commands in the same terminal.
If it happens, run this command in a separate terminal.

```
docker kill node-template-subspace
```

#### Running Full Client

We can now run another full client and sync the chain from the client we started earlier:
```
BOOTSTRAP_CLIENT_IP=$(docker inspect -f "{{.NetworkSettings.Networks.subspace.IPAddress}}" node-template-subspace)
docker run --rm --init -it \
  --net subspace \
  --name node-template-subspace-full \
  subspacelabs/node-template-subspace \
    --dev \
    --tmp \
    --ws-external \
    --bootnodes /ip4/$BOOTSTRAP_CLIENT_IP/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp
```

#### Running Light Client

We can also run light client and sync the chain from the client we started earlier:
```
BOOTSTRAP_CLIENT_IP=$(docker inspect -f "{{.NetworkSettings.Networks.subspace.IPAddress}}" node-template-subspace)
docker run --rm --init -it \
  --net subspace \
  --name node-template-subspace-light \
  subspacelabs/node-template-subspace \
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

First, complete the [basic Rust setup instructions](docs/rust-setup.md).

#### Install Dependencies
On Linux, RocksDB requires Clang

```bash
sudo apt-get install llvm clang gcc make m4
```

#### Setup subspace-farmer
Create 1 GiB plot according to following [instructions](https://github.com/subspace/subspace-farmer/tree/w3f-subspace-ms-1.1#install-and-run-manually)

#### Install and Run Node

This will run a node-template-subspace in one terminal and a subspace-farmer farming in a second terminal.
The node will send slot notification challenges to the farmer.
If the farmer finds a valid solution it will reply, and the node will produce a new block.

```bash
# Install Node
git clone https://github.com/subspace/subspace.git
cd subspace

# Build and run Node (first terminal)
cargo +nightly run --bin node-template-subspace -- --dev --tmp

# wait for the client to start before continuing...

# Run Farmer (second terminal)
cd /back/to/subspace-farmer
cargo +nightly run farm
```

NOTE: Above commands require nightly compiler for now, make sure to install it if you don't have one yet:
```
rustup toolchain install nightly
```

### Test equivocation behavior
1. Run bootstrap client node with farmer according to instructions in "Run with Docker" section above
2. Start the first full client node and farmer with the same identity as the bootstrap client node:
  1. In one terminal run full client:
      ```bash
      BOOTSTRAP_CLIENT_IP=$(docker inspect -f "{{.NetworkSettings.Networks.subspace.IPAddress}}" node-template-subspace)
      docker run --rm --init -it \
        --net subspace \
        --name node-template-subspace-full-1 \
        subspacelabs/node-template-subspace \
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
          --ws-server ws://node-template-subspace-full-1:9944
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

# Subspace tests
cd substrate/client/consensus/subspace
cargo +nightly test

# Offences Subspace tests
cd substrate/frame/offences-subspace
cargo +nightly test

# Subspace tests
cd substrate/frame/subspace
cargo +nightly test

# Farmer tests
cd subspace-farmer
cargo +nightly test

```

### Embedded Docs

Once the project has been built, the following command can be used to explore all parameters and
subcommands:

```bash
cargo +nightly run --bin node-template-subspace -- -h
```

## Run

The provided `cargo run` command will launch a temporary node and its state will be discarded after
you terminate the process. After the project has been built, there are other ways to launch the
node.

### Single-Node Development Chain

This command will start the single-node development chain with persistent state:

```bash
cargo +nightly run --bin node-template-subspace -- --dev
```

Purge the development chain's state:

```bash
cargo +nightly run --bin node-template-subspace -- purge-chain --dev
```

Start the development chain with detailed logging:

```bash
RUST_BACKTRACE=1 cargo +nightly run --bin node-template-subspace -- -ldebug --dev
```

<div align="center">

  <h1><code>node-template-spartan</code></h1>

  <strong>A Substrate Node Template which implements Spartan Proof-of-Capacity (PoC) consensus.</strong>

</div>

# Overview

This repo is an implementation of Spartan Proof-of-Capacity (PoC) consensus for the Substrate framework, organized as a Substrate pallet and several dependencies. It is largely based on a fork of `pallet_babe`, with which it shares many similarities. This work is supported by a [Web 3 Foundation grant](https://github.com/w3f/Open-Grants-Program/blob/master/applications/spartan_poc_consensus_module.md) to develop PoC consensus for Substrate. PoC is a generic term for consensus based on disk space, including proofs of space, storage, space-time, and replication.

Spartan is a simple and secure PoC consensus protocol, which replaces 'one-cpu-one-vote' with 'one-disk-one-vote'. This allows for mass participation in consensus by ordinary users with commodity hardware. Since PoC consensus is energy-efficient, widespread adoption is also environmentally sustainable. Spartan retains several key features of Nakamoto Consensus, including: the longest-chain fork-choice rule, dynamic availability (i.e., it is permissionless), and the honest majority assumption. Similar to proof-of-stake protocols, there is no mining delay, so we instead employ a round based notion of time, which is almost identical to the Ouroborous family of protocols and BABE.

To learn more about Spartan, read the [design document](https://github.com/subspace/substrate/blob/poc/frame/spartan/design.md).

Spartan is a stepping stone towards the larger goal of deploying [Subspace](https://www.subspace.network/) as a parachain on the Polkadot Network. Subspace is a proof-of-storage blockchain that resolves the farmer's dilemma, to learn more read our <a href="https://drive.google.com/file/d/1v847u_XeVf0SBz7Y7LEMXi72QfqirstL/view">white paper</a>.

# Node Template Spartan

A fresh FRAME-based [Substrate](https://www.substrate.io/) node, modified for Spartan PoC consensus :rocket:

Based on a fork of Substrate Node Template.

**Notes:** The code is un-audited and not production ready, use it at your own risk.

## Getting Started

Follow these steps to get started with the Spartan Node Template :hammer_and_wrench:

Note that this repo is for running a spartan-client. In order to run a full node which participates in consensus and produces blocks you must also run a [spartan-farmer](https://github.com/subspace/spartan-farmer/tree/w3f-spartan-ms-1.1) and that farmer must have first created a disk-based plot. For clarity we provide instructions for both repos in the docker guide below. For building and running the farmer in development mode from source, refer to the instructions in the [readme](https://github.com/subspace/spartan-farmer/tree/w3f-spartan-ms-1.1#install-and-run-manually).

### Run with Docker

**Note:** These instructions assume you run the farmer in one terminal and the client in a second terminal.

First, install [Docker](https://docs.docker.com/get-docker/).

#### Initialize Farmer (Terminal 1)

Create volume for plot, pull latest image and initialize 1 GiB plot (should take a thirty seconds to a few minutes):
```bash
docker volume create spartan-farmer
docker pull subspacelabs/spartan-farmer
docker run --rm -it \
  --name spartan-farmer \
  --mount source=spartan-farmer,target=/var/spartan \
  subspacelabs/spartan-farmer plot 256000 spartan
```

#### Run the Client (Terminal 2)

Create virtual network, pull latest image and start a single node development chain:
```bash
docker network create spartan
docker pull subspacelabs/node-template-spartan
docker run --rm --init -it \
  --net spartan \
  --name node-template-spartan \
  --publish 127.0.0.1:30333:30333 \
  --publish 127.0.0.1:9944:9944 \
  --publish 127.0.0.1:9933:9933 \
  subspacelabs/node-template-spartan \
    --dev \
    --tmp \
    --ws-external \
    --node-key 0000000000000000000000000000000000000000000000000000000000000001
```

#### Run the Farmer (Terminal 1)

Once node is running, you can connect farmer to it by running following in a separate terminal:
```bash
docker run --rm --init -it \
  --net spartan \
  --name spartan-farmer \
  --mount source=spartan-farmer,target=/var/spartan \
  subspacelabs/spartan-farmer \
    farm \
    --ws-server ws://node-template-spartan:9944
```

Now you should see block production in the first terminal where node is running.

#### Stopping the Client

The client container may not respond to kill commands in the same terminal.
If it happens, run this command in a separate terminal.

```
docker kill node-template-spartan
```

#### Running Full Client

We can now run another full client and sync the chain from the client we started earlier:
```
BOOTSTRAP_CLIENT_IP=$(docker inspect -f "{{.NetworkSettings.Networks.spartan.IPAddress}}" node-template-spartan)
docker run --rm --init -it \
  --net spartan \
  --name node-template-spartan-full \
  subspacelabs/node-template-spartan \
    --dev \
    --tmp \
    --ws-external \
    --bootnodes /ip4/$BOOTSTRAP_CLIENT_IP/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp
```

#### Running Light Client

We can also run light client and sync the chain from the client we started earlier:
```
BOOTSTRAP_CLIENT_IP=$(docker inspect -f "{{.NetworkSettings.Networks.spartan.IPAddress}}" node-template-spartan)
docker run --rm --init -it \
  --net spartan \
  --name node-template-spartan-light \
  subspacelabs/node-template-spartan \
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
If you have not previously installed the `gmp_mpfr_sys` crate, follow these [instructions](https://docs.rs/gmp-mpfr-sys/1.3.0/gmp_mpfr_sys/index.html#building-on-gnulinux).

On Linux, RocksDB requires Clang

```bash
sudo apt-get install llvm clang gcc make m4
```

#### Setup Spartan-Farmer
Create 1 GiB plot according to following [instructions](https://github.com/subspace/spartan-farmer/tree/w3f-spartan-ms-1.1#install-and-run-manually)

#### Install and Run Node

This will run a node-template-spartan in one terminal and a spartan-farmer farming in a second terminal.
The node will send slot notification challenges to the farmer.
If the farmer finds a valid solution it will reply, and the node will produce a new block.

```bash
# Install Node
git clone https://github.com/subspace/subspace.git
cd subspace

# Build and run Node (first terminal)
cargo +nightly run --bin node-template-spartan -- --dev --tmp

# wait for the client to start before continuing...

# Run Farmer (second terminal)
cd /back/to/spartan-farmer
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
      BOOTSTRAP_CLIENT_IP=$(docker inspect -f "{{.NetworkSettings.Networks.spartan.IPAddress}}" node-template-spartan)
      docker run --rm --init -it \
        --net spartan \
        --name node-template-spartan-full-1 \
        subspacelabs/node-template-spartan \
          --dev \
          --tmp \
          --ws-external \
          --bootnodes /ip4/$BOOTSTRAP_CLIENT_IP/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp
      ```
  2. In another terminal plot with the same identity:
      ```bash
      docker volume create spartan-farmer-1
      docker run --rm -it \
        --entrypoint=/bin/cp \
        --mount source=spartan-farmer,target=/var/spartan-src \
        --mount source=spartan-farmer-1,target=/var/spartan \
        subspacelabs/spartan-farmer cp /var/spartan-src/identity.bin /var/spartan/identity.bin
      docker run --rm -it \
        --name spartan-farmer-1 \
        --mount source=spartan-farmer-1,target=/var/spartan \
        subspacelabs/spartan-farmer plot 256000 spartan
      ```
  3. And start farming while being connected to the full client:
      ```bash
      docker run --rm --init -it \
        --net spartan \
        --name spartan-farmer-1 \
        --mount source=spartan-farmer-1,target=/var/spartan \
        subspacelabs/spartan-farmer \
          farm \
          --ws-server ws://node-template-spartan-full-1:9944
      ```
3. Repeat 2. with `-1` replaced with `-2` everywhere in order to obtain one more pair of client and farmer
4. Observe following messages in logs similar to these, also block production will stop:
    ```
    Slot author Public(X (Y...)) is equivocating at slot Z with headers W and A
    Submitted PoC equivocation report.
    Submitted equivocation report for author Public(X (Y...))
    Ignoring solution for slot X provided by farmer in block list: Y
    ```

### Run Tests

```bash

# PoC tests
cd substrate/client/consensus/poc
cargo +nightly test

# Offences PoC tests
cd substrate/frame/offences-poc
cargo +nightly test

# Spartan tests
cd substrate/frame/spartan
cargo +nightly test

# Farmer tests
cd spartan-farmer
cargo +nightly test

```

### Embedded Docs

Once the project has been built, the following command can be used to explore all parameters and
subcommands:

```bash
cargo +nightly run --bin node-template-spartan -- -h
```

## Run

The provided `cargo run` command will launch a temporary node and its state will be discarded after
you terminate the process. After the project has been built, there are other ways to launch the
node.

### Single-Node Development Chain

This command will start the single-node development chain with persistent state:

```bash
cargo +nightly run --bin node-template-spartan -- --dev
```

Purge the development chain's state:

```bash
cargo +nightly run --bin node-template-spartan -- purge-chain --dev
```

Start the development chain with detailed logging:

```bash
RUST_BACKTRACE=1 cargo +nightly run --bin node-template-spartan -- -ldebug --dev
```

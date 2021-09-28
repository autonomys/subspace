<div align="center">
  <h1><code>spartan-farmer</code></h1>
  <strong>A proof-of-concept farmer for the <a href="https://subspace.network/">Subspace Network Blockchain</a></strong>
</div>

## Overview
**Notes:** The code is un-audited and not production ready, use it at your own risk.

This repo is an implementation of a Farmer, designed to work with a seperate Client that implements [Spartan Proof-of-Capacity (PoC) consensus](https://github.com/subspace/substrate/blob/w3f-spartan-ms-1/frame/spartan/design.md). PoC is a generic term for consensus based on disk space, including proofs of space, storage, space-time, and replication. A farmer is similar to a miner in a proof-of-work blockchain, but instead of wasting CPU cycles, it wastes disk space. Much of this code is based on our earlier implementation, [subspace-core-rust](https://www.github.com/subspace/subspace-core-rust).

This work is supported by a [Web 3 Foundation grant](https://github.com/w3f/Open-Grants-Program/blob/master/applications/spartan_poc_consensus_module.md) to develop PoC consensus for the Substrate framework. It is specifically designed to work with [spartan-client](https://github.com/subspace/substrate/tree/w3f-spartan-ms-1/bin/node-template-spartan), a substrate client based on the substrate-node-template. 

Spartan is a stepping stone towards the larger goal of deploying [Subspace](https://www.subspace.network/) as a parachain on the Polkadot Network. Subspace is a proof-of-storage blockchain that resolves the farmer's dilemma, to learn more read our <a href="https://drive.google.com/file/d/1v847u_XeVf0SBz7Y7LEMXi72QfqirstL/view">white paper</a>.

## Some Notes on Plotting

### Time to Plot

Plotting time is roughly linear with respect to number of cores and clock speed of the host system. On average, it takes ~ 1 minute to create a 1GB plot or 18 hours to to create a 1TB plot, though these numbers will depend on the system used. This is largely independent of the storage media used (i.e. HDD, SATA SSD, NVME SSD) as it is largely a CPU-bound task.

### Disk Wear and Tear

Some PoC protocols require several passes over the disk in order to plot. For example, a 100GB plot might actually consume several TB of writes and reduce the expected lifetime of the disk. This is not the case with Spartan. The plot is created in a single pass on startup. 

### Storage Overhead

In addition the plot, a small Binary Search Tree (BST) is also stored on disk using RocksDB. This adds roughly 1% storage overhead. So creating a 1GB plot will actually consume about 1.01 GB of storage. 

## Run with Docker
The simplest way to use spartan-farmer is to use container image:
```bash
docker volume create spartan-farmer
docker run --rm -it --mount source=spartan-farmer,target=/var/spartan subspacelabs/spartan-farmer --help
```

`spartan-farmer` is the volume where plot and identity will be stored, it only needs to be created once.

## Install and Run Manually
Instead of Docker you can also install spartan-farmer natively by compiling it using cargo.

RocksDB on Linux needs LLVM/Clang:
```bash
sudo apt-get install llvm clang
```

Then install the framer using Cargo:
```
cargo +nightly install spartan-farmer
```

NOTE: Above command requires nightly compiler for now, make sure to install it if you don't have one yet:
```
rustup toolchain install nightly
```

## Usage
Commands here assume you installed native binary, but you can also easily adapt them to using with Docker.

Use `--help` to find out all available commands and their options:
```
spartan-farmer --help
```

### Create a New Plot
```
spartan-farmer plot <optional parameters> <piece-count> <seed>
```

This will create a 1 GB plot:
```
spartan-farmer plot 256000 test
```

For all supported options check help:
```
spartan-farmer plot --help
```

By default, plots are written to the OS-specific users local data directory.

```
Linux
$XDG_DATA_HOME or                   /home/alice/.local/share
$HOME/.local/share 

macOS
$HOME/Library/Application Support   /Users/Alice/Library/Application Support

Windows
{FOLDERID_LocalAppData}             C:\Users\Alice\AppData\Local
```

### Start the farmer
```
RUST_LOG=debug spartan-farmer farm
```

This will connect to local node and will try to solve on every slot notification.

*NOTE: You need to have a spartan-client node running before starting farmer, otherwise it will not be able to start*


## Design

The farmer has two modes: plotting and farming.

### Plotting
1. A genesis piece is created from a short seed.
2. A new Schnorr key pair is generated, and the farmer ID is derived from the public key.
3. New encodings are created by applying the time-asymmetric SLOTH permutation as `encode(genesis_piece, farmer_id, plot_index)`
4. Each encoding is written directly to disk.
5. A commitment, or tag, to each encoding is created as `hmac(encoding, salt)` and stored within a binary search tree (BST).

This process currently takes ~ 36 hours per TiB on a quad-core machine, but for 1 GiB plotting should take between a few seconds and a few minutes.

### Solving
Once plotting is complete the farmer may join the network and participate in consensus.

1. Connect to a client and subscribe to `slot_notifications` via JSON-RPC.
2. Given a global challenge as `hash(epoch_randomness || slot_index)` and `SOLUTION_RANGE`.
3. Derive local challenge as `hash(global_challenge || farmer_id)`.
4. Query the BST for the nearest tag to the local challenge.
5. If it within `SOLUTION_RANGE` return a `SOLUTION` else return `None`





<div align="center">
  <h1><code>subspace-farmer</code></h1>
  <strong>Farmer for the <a href="https://subspace.network/">Subspace Network Blockchain</a></strong>
</div>

## Overview
**Notes:** The code is un-audited and not production ready, use it at your own risk.

This repo is an implementation of a Farmer for [Subspace Network Blockchain](https://subspace.network).

Subspace is a proof-of-storage blockchain that resolves the farmer's dilemma, to learn more read our [white paper](https://drive.google.com/file/d/1v847u_XeVf0SBz7Y7LEMXi72QfqirstL/view).

## Some Notes on Plotting

### Time to Plot

Plotting time is roughly linear with respect to number of cores and clock speed of the host system. On average, it takes ~ 1 minute to create a 1GB plot or 18 hours to to create a 1TB plot, though these numbers will depend on the system used. This is largely independent of the storage media used (i.e. HDD, SATA SSD, NVME SSD) as it is largely a CPU-bound task.

### Storage Overhead

In addition, the plot, a small Binary Search Tree (BST) is also stored on disk using RocksDB. This adds roughly 1% storage overhead. So creating a 1GB plot will actually consume about 1.01 GB of storage. 

## Run with Docker
The simplest way to use subspace-farmer is to use container image:
```bash
docker volume create subspace-farmer
docker run --rm -it --mount source=subspace-farmer,target=/var/subspace subspacelabs/subspace-farmer --help
```

`subspace-farmer` is the volume where plot and identity will be stored, it only needs to be created once.

## Install and Run Manually
Instead of Docker you can also install subspace-farmer natively by compiling it using cargo.

RocksDB on Linux needs LLVM/Clang:
```bash
sudo apt-get install llvm clang
```

Then install the framer using Cargo:
```
cargo install subspace-farmer
```

## Usage
Commands here assume you installed native binary, but you can also easily adapt them to using with Docker.

Use `--help` to find out all available commands and their options:
```
subspace-farmer --help
```

### Start the farmer
```
subspace-farmer farm
```

This will connect to local node and will try to solve on every slot notification, while also plotting all existing and new history of the blockchain in parallel.

*NOTE: You need to have a subspace-client node running before starting farmer, otherwise it will not be able to start*

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

## Design

The farmer typically runs two processes in parallel: plotting and farming.

### Plotting
0. A new Schnorr key pair is generated, and the farmer ID is derived from the public key.
1. For every archived piece of the history encoding is created by applying the time-asymmetric SLOTH permutation as `encode(genesis_piece, farmer_public_key_hash, plot_index)`
2. Each encoding is written directly to disk.
3. A commitment, or tag, to each encoding is created as `hmac(encoding, salt)` and stored within a binary search tree (BST).

This process currently takes ~ 36 hours per TiB on a quad-core machine, but for 1 GiB plotting should take between a few seconds and a few minutes.

### Solving
1. Connect to a client and subscribe to `slot_notifications` via JSON-RPC.
2. Given a global challenge as `hash(randomness || slot_index)` and `SOLUTION_RANGE`.
3. Derive local challenge as `hash(global_challenge || farmer_public_key_hash)`.
4. Query the BST for the nearest tag to the local challenge.
5. If it within `SOLUTION_RANGE` return a `SOLUTION` else return `None`
6. All the above can and will happen in parallel to plotting process, so it is possible to participate right away





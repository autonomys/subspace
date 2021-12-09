# Subspace Network Monorepo

[![Rust](https://github.com/subspace/subspace/actions/workflows/rust.yaml/badge.svg)](https://github.com/subspace/subspace/actions/workflows/rust.yaml)
[![rustdoc](https://github.com/subspace/subspace/actions/workflows/rustdoc.yml/badge.svg)](https://subspace.github.io/subspace)

This is a mono repository for [Subspace Network](https://www.subspace.network/) implementation, primarily containing
Subspace node/client using Substrate framework and farmer app implementations.

### Repository structure

The structure of this repository is the following:

- `crates` contains Subspace-specific Rust crates used to build node and farmer, most are following Substrate naming conventions
  - `subspace-node` is an implementation of the node for Subspace protocol
  - `subspace-farmer` is a CLI farmer app
- `substrate` contains modified copies of Substrate's crates that we use for testing

### How to run (building from the source)

This is a monorepo with multiple binaries and the workflow is typical for Rust projects:

- `cargo run --release --bin subspace-node -- --dev --tmp` to run [a node](crates/subspace-node)
- `cargo run --release --bin subspace-farmer -- farm` to [start farming](crates/subspace-farmer#start-the-farmer)

NOTE 1: You need to have `nightly` version of Rust toolchain with `wasm32-unknown-unknown` target available or else you'll get a compilation error.
NOTE 2: Following the commands above, you will be farming in an offline setting (by yourself).

You can find readme files in corresponding crates for requirements, multi-node setup and other details.


## Releases (executables)

We are regularly releasing stable snapshots. Our CI builds container images and executables for 3 major platforms (Windows, MacOS, Linux). 
You can find these executables in the [Releases](https://github.com/subspace/subspace/releases).
With the provided executables, you can choose to `Farm` online by joining the network, or offline (by yourself, for test or development purposes).

### To Farm With The Network (Online)

**Mac/Linux**

1. Download the executables for your operating system
2. Open your favourite terminal, and go to the folder where you download the executables
3. This will start the node: `sudo ./subspace-node-x86_64-*-snapshot-test \
   --chain testnet
   --base-path /var/subspace \
   --name subspace-node \
   --pruning archive \
   --rpc-cors all \
   --ws-external \
   --rpc-methods unsafe \
   --wasm-execution compiled \
   --execution wasm \
   --validator \
   --telemetry-url "wss://telemetry.polkadot.io/submit/ 9" \` (replace the filename according to your downloaded file)
4. This will start the farmer: `sudo ./subspace-farmer-x86_64-*-snapshot-test -- farm` (replace the filename according to your downloaded file)

**Windows**

1. Download the executables for your operating system
2. Open your favourite terminal with admin privileges, and go to the folder where you download the executables
3. This will start the node: `./subspace-node-x86_64-*-snapshot-test --chain testnet --base-path /var/subspace --name subspace-node --pruning archive --rpc-cors all --ws-external --rpc-methods unsafe --wasm-execution compiled --execution wasm --validator --telemetry-url "wss://telemetry.polkadot.io/submit/ 9"` (replace the filename according to your downloaded file)
4. This will start the farmer: `sudo ./subspace-farmer-x86_64-*-snapshot-test -- farm` (replace the filename according to your downloaded file)

### To Farm By Yourself (Offline)
1. Download the executables for your operating system
2. Open your favourite terminal, and go to the folder where you download the executables (for Windows, open the terminal with admin privileges)

Linux/MacOS (remove `sudo` from the beginning for Windows):
3. `sudo ./subspace-node-x86_64-*-snapshot-test -- --dev --tmp` (replace the filename according to your downloaded file)
4. `sudo ./subspace-farmer-x86_64-*-snapshot-test -- farm` (replace the filename according to your downloaded file)

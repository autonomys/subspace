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

NOTE: replace these: `subspace-node-x86_64-*-snapshot`, `subspace-farmer-x86_64-*-snapshot`
in the below commands with the name of the file you downloaded for your operating system. 

**Mac/Linux**

1. Download the executables for your operating system
2. Open your favourite terminal, and go to the folder where you download the executables
3. Make them executable  `chmod +x subspace-farmer-x86_64-*-snapshot subspace-node-x86_64-*-snapshot`
4. This will start the node (replace `INSERT_YOUR_ID` with a nickname you choose): `./subspace-node-x86_64-*-snapshot \
   --chain testnet \
   --name INSERT_YOUR_ID \
   --rpc-cors all \
   --ws-external \
   --rpc-methods unsafe \
   --wasm-execution compiled \
   --execution wasm \
   --validator \
   --bootnodes "/dns/test-rpc.subspace.network/tcp/30333/p2p/12D3KooWAbeaefPbU9brfEUKZPeqptT5uxcsEQxQacPFhE1Z5nbs" \
   --telemetry-url "wss://telemetry.polkadot.io/submit/ 1"` 
5. This will start the farmer: `./subspace-farmer-x86_64-*-snapshot -- farm`

**Windows**

1. Download the executables for your operating system
2. Open your favourite terminal with admin privileges, and go to the folder where you download the executables
3. This will start the node (replace `INSERT_YOUR_ID` with a nickname you choose): `subspace-node-x86_64-*-snapshot ^
   --chain testnet ^
   --name INSERT_YOUR_ID ^
   --rpc-cors all ^
   --ws-external ^
   --rpc-methods unsafe ^
   --wasm-execution compiled ^
   --execution wasm ^
   --validator ^
   --bootnodes "/dns/test-rpc.subspace.network/tcp/30333/p2p/12D3KooWAbeaefPbU9brfEUKZPeqptT5uxcsEQxQacPFhE1Z5nbs" ^
   --telemetry-url "wss://telemetry.polkadot.io/submit/ 1"`
4. After running this command, Windows may ask you for permissions related to firewall, select `allow` in this case.
5. This will start the farmer: `./subspace-farmer-x86_64-*-snapshot -- farm` 

### To Farm By Yourself (Offline)

1. Download the executables for your operating system
2. Open your favourite terminal, and go to the folder where you download the executables


Linux/MacOS:
1. Make them executable: `chmod +x subspace-farmer-x86_64-*-snapshot subspace-node-x86_64-*-snapshot`
2. Run the node: `./subspace-node-x86_64-*-snapshot -- --dev --tmp`
3. Run the farmer: `./subspace-farmer-x86_64-*-snapshot -- farm`

Windows
1. Run the node: `subspace-node-x86_64-*-snapshot -- --dev --tmp`
2. After running this command, Windows may ask you for permissions related to firewall, select `allow` in this case.
3. Run the farmer: `subspace-farmer-x86_64-*-snapshot -- farm`

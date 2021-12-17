# Subspace Network Monorepo

[![Rust](https://github.com/subspace/subspace/actions/workflows/rust.yaml/badge.svg)](https://github.com/subspace/subspace/actions/workflows/rust.yaml)
[![rustdoc](https://github.com/subspace/subspace/actions/workflows/rustdoc.yml/badge.svg)](https://subspace.github.io/subspace)

This is a mono repository for [Subspace Network](https://www.subspace.network/) implementation, primarily containing
Subspace node/client using Substrate framework and farmer app implementations.

## Repository structure

The structure of this repository is the following:

- `crates` contains Subspace-specific Rust crates used to build node and farmer, most are following Substrate naming conventions
  - `subspace-node` is an implementation of the node for Subspace protocol
  - `subspace-farmer` is a CLI farmer app
- `cumulus` contains modified copies of Cumulus crates that we use right now
- `polkadot` contains modified copies of Polkadot crates that we use right now
- `substrate` contains modified copies of Substrate's crates that we use for testing

## How to run

We are regularly releasing stable snapshots. Our CI builds container images and executables for 3 major platforms (Windows, MacOS, Linux). 
With the provided executables, you can choose to `Farm` online by joining the network, or offline (by yourself, for test or development purposes).

You need 2 executables, select whichever applies to your operating system
* Node Executable - `subspace-node-...`
* Farmer Executable - `subspace-farmer-...`

You can find these executables in the [Releases](https://github.com/subspace/subspace/releases) section of this Repository.

> This is a ***non-incentivized*** testnet. Meaning there are no rewards in place at this time, and has absolutely no financial benefit to being run at this time.

### A. To Farm With The Network (Online)

> NOTE: replace these: `subspace-node-x86_64-*-snapshot`, `subspace-farmer-x86_64-*-snapshot`
> in the below commands with the name of the file you downloaded for your operating system. 

**Mac/Linux**

1. Download the executables for your operating system.
2. Open your favourite terminal, and go to the folder where you download the executables.
3. Make them executable  `chmod +x subspace-farmer-x86_64-*-snapshot subspace-node-x86_64-*-snapshot`
4. This will start the node (replace `INSERT_YOUR_ID` with a nickname you choose): 
```
./subspace-node-x86_64-*-snapshot --chain testnet --wasm-execution compiled --execution wasm --bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" --rpc-cors all --rpc-methods unsafe --ws-external --validator --telemetry-url "wss://telemetry.polkadot.io/submit/ 1" --name INSERT_YOUR_ID
```
5. It may prompt in here if you are using MacOS. Refer to the note below.
6. This will start the farmer (do this in another terminal): 
```
./subspace-farmer-x86_64-*-snapshot farm
```
7. It may prompt again in here if you are using MacOS. Refer to the note below.

*Note for MacOS (when prompted):* Click on `cancel` instead of moving it to trash.
To allow execution, go to `System Preferences -> Security & Privacy -> General`, and click on `allow`.
After this, simply repeat the step you prompted for (step 4 or 6). This time, click the `Open` button when prompted.

**Windows**

1. Download the executables for your operating system
2. Open your favourite terminal, and go to the folder where you download the executables
3. This will start the node (replace `INSERT_YOUR_ID` with a nickname you choose):
```
./subspace-node-x86_64-*-snapshot --chain testnet --wasm-execution compiled --execution wasm --bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" --rpc-cors all --rpc-methods unsafe --ws-external --validator --telemetry-url "wss://telemetry.polkadot.io/submit/ 1" --name INSERT_YOUR_ID
```
4. After running this command, Windows may ask you for permissions related to firewall, select `allow` in this case.
5. This will start the farmer (do this in another terminal): 
```
./subspace-farmer-x86_64-*-snapshot farm
```

### B. To Farm By Yourself (Offline)

1. Download the executables for your operating system
2. Open your favourite terminal, and go to the folder where you download the executables

**Linux/MacOS:**
1. Make them executable: `chmod +x subspace-farmer-x86_64-*-snapshot subspace-node-x86_64-*-snapshot`
2. Run the node: `./subspace-node-x86_64-*-snapshot -- --dev --tmp`
3. In macOS, it may prompt that this app is not verified. Click on `cancel` instead of moving it to trash.
   To allow execution, go to `System Preferences -> Security & Privacy -> General`, and click on `allow`.
   After this, simply repeat step 4. This time, there will be `Open` button in the prompt, click it to run node.
4. Run the farmer (do this in another terminal): `./subspace-farmer-x86_64-*-snapshot farm`
5. In macOS, it may prompt that this app is not verified. Click on `cancel` instead of moving it to trash.
   To allow execution, go to `System Preferences -> Security & Privacy -> General`, and click on `allow`.
   After this, simply repeat step 4. This time, there will be `Open` button in the prompt, click it to run node.

**Windows**
1. Run the node: `subspace-node-x86_64-*-snapshot -- --dev --tmp`
2. After running this command, Windows may ask you for permissions related to firewall, select `allow` in this case.
3. Run the farmer (do this in another terminal): `subspace-farmer-x86_64-*-snapshot farm`

### C. To Build From The Source (primarily for developers)

This is a monorepo with multiple binaries and the workflow is typical for Rust projects:

- `cargo run --release --bin subspace-node -- --dev --tmp` to run [a node](crates/subspace-node)
- `cargo run --release --bin subspace-farmer -- farm` to [start farming](crates/subspace-farmer#start-the-farmer)

NOTE 1: You need to have `nightly` version of Rust toolchain with `wasm32-unknown-unknown` target available or else you'll get a compilation error.
NOTE 2: Following the commands above, you will be farming in an offline setting (by yourself).
NOTE 3: To farm in online setting, you can modify the command accordingly.

You can find readme files in corresponding crates for requirements, multi-node setup and other details.

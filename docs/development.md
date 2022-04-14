# To Farm By Yourself (Offline)

1. Download the executables for your operating system
2. Open your favourite terminal, and go to the folder where you download the executables

**Linux/MacOS:**
1. Make them executable: `chmod +x subspace-farmer-x86_64-*-snapshot subspace-node-x86_64-*-snapshot`
2. Run the node: `./subspace-node-x86_64-*-snapshot --dev --tmp`
3. In macOS, it may prompt that this app is not verified. Click on `cancel` instead of moving it to trash.
   To allow execution, go to `System Preferences -> Security & Privacy -> General`, and click on `allow`.
   After this, simply repeat step 4. This time, there will be `Open` button in the prompt, click it to run node.
4. Run the farmer (do this in another terminal): `./subspace-farmer-x86_64-*-snapshot farm`
5. In macOS, it may prompt that this app is not verified. Click on `cancel` instead of moving it to trash.
   To allow execution, go to `System Preferences -> Security & Privacy -> General`, and click on `allow`.
   After this, simply repeat step 4. This time, there will be `Open` button in the prompt, click it to run node.

**Windows**
1. Run the node: `subspace-node-x86_64-*-snapshot --dev --tmp`
2. After running this command, Windows may ask you for permissions related to firewall, select `allow` in this case.
3. Run the farmer (do this in another terminal): `subspace-farmer-x86_64-*-snapshot farm`

## to Build From The Source for Public Testnet (primarily for developers)

1. Download the specific source code, example for now: `wget https://github.com/subspace/subspace/archive/refs/tags/snapshot-2022-mar-09.tar.gz`.
2. Unzip: `tar -zvxf snapshot-2022-mar-09.tar.gz`.
3. Install dependencies mentioned [here](/crates/subspace-node).
4. Build with Cargo: `cd ~/snapshot-2022-mar-09 && cargo build --release --bin subspace-node --bin subspace-farmer`.
5. Download the specific `chain-spec.json` file, example for now:`wget https://github.com/subspace/subspace/releases/download/snapshot-2022-mar-09/chain-spec-raw-snapshot-2022-mar-09.json`.
6. Run the node: `~/snapshot-2022-mar-09/target/release/subspace-node --chain /your-path/chain-spec-raw-snapshot-2022-mar-09.json --validator -d db --port your-P2P-port --bootnodes /dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr`.
7. Run the farmer: `~/snapshot-2022-mar-09/target/release/subspace-farmer farm --reward-address xxxx`.
8. Demo script:
```
#!/bin/bash
// install dependencies as mentioned above first of all!
// then update CARGO path with yours.

CARGO="/root/.cargo/bin/cargo"
mkdir -p subspace/log && cd subspace
wget https://github.com/subspace/subspace/archive/refs/tags/snapshot-2022-mar-09.tar.gz
tar -zvxf snapshot-2022-mar-09.tar.gz
cd snapshot-2022-mar-09

// build for your native cpu
$CARGO clean
RUSTFLAGS="-C target-cpu=native" $CARGO build --release --bin subspace-node

// run the node
wget https://github.com/subspace/subspace/releases/download/snapshot-2022-mar-09/chain-spec-raw-snapshot-2022-mar-09.json
./target/release/subspace-node --chain chain-spec-raw-snapshot-2022-mar-09.json --validator -d db --port 8888 --bootnodes /dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr >> ~/subspace/log/node.log &

// check status
tail -f  ~/subspace/log/node.log
```

## to Build From The Source (primarily for developers)

This is a monorepo with multiple binaries and the workflow is typical for Rust projects:

- `cargo run --release --bin subspace-node -- --dev --tmp` to run [a node](/crates/subspace-node)
- `cargo run --release --bin subspace-farmer farm` to [start farming](/crates/subspace-farmer)

NOTE 1: You need to have `nightly` version of Rust toolchain with `wasm32-unknown-unknown` target available or else you'll get a compilation error.
NOTE 2: Following the commands above, you will be farming in an offline setting (by yourself).
NOTE 3: To farm in online setting, you can modify the command accordingly.

You can find readme files in corresponding crates for requirements, multi-node setup and other details.

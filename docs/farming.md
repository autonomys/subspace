
# 👨‍🌾 Getting Started Farming

This is the documentation/guideline on how to run the farmer. You may also refer to the [help](#help) section for various commands.

We are regularly releasing stable snapshots. Our CI builds container images and executables for 3 major platforms (Windows, macOS, Linux).

Our snapshots are categorized as the following:
- **Stable releases (you should always grab the latest one, these are the ones that are tested by our team)**
- Pre-releases (for testing things early, intended for developers)

You need 2 executables, select whichever applies to your operating system
* Node Executable - `subspace-node-...`
* Farmer Executable - `subspace-farmer-...`

You can find these executables in the [Releases](https://github.com/subspace/subspace/releases) section of this Repository.

> This is a ***non-incentivized*** testnet. Meaning there are no rewards in place at this time, and has absolutely no financial benefit to being run at this time.

## Polkadot.js wallet

Before running anything you need to have a wallet where you'll receive testnet coins.
Install [Polkadot.js extension](https://polkadot.js.org/extension/) into your browser and create a new account there.
The address of your account will be necessary at the last step.

## 🖼️ Windows Instructions

1. Download the executables for your operating system from the [Releases](https://github.com/subspace/subspace/releases) tab.
2. Open `Powershell` (we do not recommend using Command Prompt as it's syntax is slightly different)
3. In the terminal we will change to the Downloads directory using this command `cd Downloads`
4. We will then start the node using the following command

```PowerShell
# Replace `NODE_FILE_NAME.exe` with the name of the node file you downloaded from releases
# Replace `INSERT_YOUR_ID` with a nickname you choose
# Copy all of the lines below, they are all part of the same command
.\NODE_FILE_NAME.exe `
--chain testnet `
--wasm-execution compiled `
--execution wasm `
--bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" `
--validator `
--telemetry-url "wss://telemetry.polkadot.io/submit/ 1" `
--telemetry-url "wss://telemetry.subspace.network/submit 1" `
--name INSERT_YOUR_ID
```
5. You should see something similar in the terminal:
```
2022-02-03 10:52:23 Subspace
2022-02-03 10:52:23 ✌️  version 0.1.0-35cf6f5-x86_64-windows
2022-02-03 10:52:23 ❤️  by Subspace Labs <https://subspace.network>, 2021-2022
2022-02-03 10:52:23 📋 Chain specification: Subspace testnet
2022-02-03 10:52:23 🏷  Node name: YOUR_FANCY_NAME
2022-02-03 10:52:23 👤 Role: AUTHORITY
2022-02-03 10:52:23 💾 Database: RocksDb at C:\Users\X\AppData\Local\subspace-node-windows-x86_64-snapshot-2022-jan-05.exe\data\chains\subspace_test\db\full
2022-02-03 10:52:23 ⛓  Native runtime: subspace-100 (subspace-1.tx1.au1)
2022-02-03 10:52:23 🔨 Initializing Genesis block/state (state: 0x22a5…17ea, header-hash: 0x6ada…0d38)
2022-02-03 10:52:24 ⏱  Loaded block-time = 1s from block 0x6ada0792ea62bf3501abc87d92e1ce0e78ddefba66f02973de54144d12ed0d38
2022-02-03 10:52:24 Starting archiving from genesis
2022-02-03 10:52:24 Archiving already produced blocks 0..=0
2022-02-03 10:52:24 🏷  Local node identity is: 12D3KooWBgKtea7MVvraeNyxdPF935pToq1x9VjR1rDeNH1qecXu
2022-02-03 10:52:24 🧑‍🌾 Starting Subspace Authorship worker
2022-02-03 10:52:24 📦 Highest known block at #0
2022-02-03 10:52:24 〽️ Prometheus exporter started at 127.0.0.1:9615
2022-02-03 10:52:24 Listening for new connections on 0.0.0.0:9944.
2022-02-03 10:52:26 🔍 Discovered new external address for our node: /ip4/176.233.17.199/tcp/30333/p2p/12D3KooWBgKtea7MVvraeNyxdPF935pToq1x9VjR1rDeNH1qecXu
2022-02-03 10:52:29 ⚙️  Syncing, target=#215883 (2 peers), best: #55 (0xafc7…bccf), finalized #0 (0x6ada…0d38), ⬇ 850.1kiB/s ⬆ 1.5kiB/s
```
6. After running this command, Windows may ask you for permissions related to firewall, select `allow` in this case.
7. We will then open another terminal, change to the downloads directory, then start the farmer node with the following command:
```PowerShell
# Replace `FARMER_FILE_NAME.exe` with the name of the node file you downloaded from releases
# Replace `WALLET_ADDRESS` below with your account address from Polkadot.js wallet
.\FARMER_FILE_NAME.exe farm --reward-address WALLET_ADDRESS
```

## 🐧 Linux Instructions

1. Download the executables for your operating system from the [Releases](https://github.com/subspace/subspace/releases) tab.
2. Open your favourite terminal, and change to the Downloads directory using `cd Downloads`
3. Make the farmer & node executable  `chmod +x farmer-name` & `chmod +X node-name`
4. We will then start the node using the following command

```bash
# Replace `NODE_FILE_NAME` with the name of the node file you downloaded from releases
# Replace `INSERT_YOUR_ID` with a nickname you choose
# Copy all of the lines below, they are all part of the same command
./NODE_FILE_NAME \
  --chain testnet \
  --wasm-execution compiled \
  --execution wasm \
  --bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" \
  --validator \
  --telemetry-url "wss://telemetry.polkadot.io/submit/ 1" \
  --telemetry-url "wss://telemetry.subspace.network/submit 1" \
  --name INSERT_YOUR_ID
```
5. You should see something similar in the terminal:
```
2022-02-03 10:52:23 Subspace
2022-02-03 10:52:23 ✌️  version 0.1.0-35cf6f5-x86_64-ubuntu
2022-02-03 10:52:23 ❤️  by Subspace Labs <https://subspace.network>, 2021-2022
2022-02-03 10:52:23 📋 Chain specification: Subspace testnet
2022-02-03 10:52:23 🏷  Node name: YOUR_FANCY_NAME
2022-02-03 10:52:23 👤 Role: AUTHORITY
2022-02-03 10:52:23 💾 Database: RocksDb at /home/X/.local/share/subspace-node-x86_64-ubuntu-20.04-snapshot-2022-jan-05/chains/subspace_test/db/full
2022-02-03 10:52:23 ⛓  Native runtime: subspace-100 (subspace-1.tx1.au1)
2022-02-03 10:52:23 🔨 Initializing Genesis block/state (state: 0x22a5…17ea, header-hash: 0x6ada…0d38)
2022-02-03 10:52:24 ⏱  Loaded block-time = 1s from block 0x6ada0792ea62bf3501abc87d92e1ce0e78ddefba66f02973de54144d12ed0d38
2022-02-03 10:52:24 Starting archiving from genesis
2022-02-03 10:52:24 Archiving already produced blocks 0..=0
2022-02-03 10:52:24 🏷  Local node identity is: 12D3KooWBgKtea7MVvraeNyxdPF935pToq1x9VjR1rDeNH1qecXu
2022-02-03 10:52:24 🧑‍🌾 Starting Subspace Authorship worker
2022-02-03 10:52:24 📦 Highest known block at #0
2022-02-03 10:52:24 〽️ Prometheus exporter started at 127.0.0.1:9615
2022-02-03 10:52:24 Listening for new connections on 0.0.0.0:9944.
2022-02-03 10:52:26 🔍 Discovered new external address for our node: /ip4/176.233.17.199/tcp/30333/p2p/12D3KooWBgKtea7MVvraeNyxdPF935pToq1x9VjR1rDeNH1qecXu
2022-02-03 10:52:29 ⚙️  Syncing, target=#215883 (2 peers), best: #55 (0xafc7…bccf), finalized #0 (0x6ada…0d38), ⬇ 850.1kiB/s ⬆ 1.5kiB/s
```
7. We will then open another terminal, change to the downloads directory, then start the farmer node with the following command:
```bash
# Replace `FARMER_FILE_NAME` with the name of the node file you downloaded from releases
# Replace `WALLET_ADDRESS` below with your account address from Polkadot.js wallet
./FARMER_FILE_NAME farm --reward-address WALLET_ADDRESS
```

## 🍎 macOS Instructions

1. Download the executables for your operating system from the [Releases](https://github.com/subspace/subspace/releases) tab and extract binaries from ZIP archives.
2. Open your favourite terminal, and change to the Downloads directory using `cd Downloads`
3. Make the farmer & node executable  `chmod +x farmer-name` & `chmod +X node-name`
4. We will then start the node using the following command

> *Note, when attempting to run this command you may be prompted:* Click on `cancel` instead of moving it to trash.
To allow execution, go to `System Preferences -> Security & Privacy -> General`, and click on `allow`.
After this, simply repeat the step you prompted for (step 4 or 6). This time, click the `Open` button when prompted.

```bash
# Replace `NODE_FILE_NAME` with the name of the node file you downloaded from releases
# Replace `INSERT_YOUR_ID` with a nickname you choose
# Copy all of the lines below, they are all part of the same command
./NODE_FILE_NAME \
  --chain testnet \
  --wasm-execution compiled \
  --execution wasm \
  --bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" \
  --validator \
  --telemetry-url "wss://telemetry.polkadot.io/submit/ 1" \
  --telemetry-url "wss://telemetry.subspace.network/submit 1" \
  --name INSERT_YOUR_ID
```
5. You should see something similar in the terminal:
```
2022-02-03 10:52:23 Subspace
2022-02-03 10:52:23 ✌️  version 0.1.0-35cf6f5-x86_64-macos
2022-02-03 10:52:23 ❤️  by Subspace Labs <https://subspace.network>, 2021-2022
2022-02-03 10:52:23 📋 Chain specification: Subspace testnet
2022-02-03 10:52:23 🏷  Node name: YOUR_FANCY_NAME
2022-02-03 10:52:23 👤 Role: AUTHORITY
2022-02-03 10:52:23 💾 Database: RocksDb at /Users/X/Library/Application Support/subspace-node-x86_64-macos-11-snapshot-2022-jan-05/chains/subspace_test/db/full
2022-02-03 10:52:23 ⛓  Native runtime: subspace-100 (subspace-1.tx1.au1)
2022-02-03 10:52:23 🔨 Initializing Genesis block/state (state: 0x22a5…17ea, header-hash: 0x6ada…0d38)
2022-02-03 10:52:24 ⏱  Loaded block-time = 1s from block 0x6ada0792ea62bf3501abc87d92e1ce0e78ddefba66f02973de54144d12ed0d38
2022-02-03 10:52:24 Starting archiving from genesis
2022-02-03 10:52:24 Archiving already produced blocks 0..=0
2022-02-03 10:52:24 🏷  Local node identity is: 12D3KooWBgKtea7MVvraeNyxdPF935pToq1x9VjR1rDeNH1qecXu
2022-02-03 10:52:24 🧑‍🌾 Starting Subspace Authorship worker
2022-02-03 10:52:24 📦 Highest known block at #0
2022-02-03 10:52:24 〽️ Prometheus exporter started at 127.0.0.1:9615
2022-02-03 10:52:24 Listening for new connections on 0.0.0.0:9944.
2022-02-03 10:52:26 🔍 Discovered new external address for our node: /ip4/176.233.17.199/tcp/30333/p2p/12D3KooWBgKtea7MVvraeNyxdPF935pToq1x9VjR1rDeNH1qecXu
2022-02-03 10:52:29 ⚙️  Syncing, target=#215883 (2 peers), best: #55 (0xafc7…bccf), finalized #0 (0x6ada…0d38), ⬇ 850.1kiB/s ⬆ 1.5kiB/s
```
7. We will then open another terminal, change to the downloads directory, then start the farmer node with the following command:
```bash
# Replace `FARMER_FILE_NAME` with the name of the node file you downloaded from releases
# Replace `WALLET_ADDRESS` below with your account address from Polkadot.js wallet
./FARMER_FILE_NAME farm --reward-address WALLET_ADDRESS
```
7. It may prompt again in here. Refer to the note on step 4.

## 🐋 Docker Instructions

Create `subspace` directory and `docker-compose.yml` in it with following contents:
```yml
version: "3.7"
services:
  node:
    # Replace `snapshot-DATE` with latest release (like `snapshot-2022-mar-09`)
    image: ghcr.io/subspace/node:snapshot-DATE
    volumes:
# Instead of specifying volume (which will store data in `/var/lib/docker`), you can
# alternatively specify path to the directory where files will be stored, just make
# sure everyone is allowed to write there
      - node-data:/var/subspace:rw
#      - /path/to/subspace-node:/var/subspace:rw
    ports:
# If port 30333 is already occupied by another Substrate-based node, replace all
# occurrences of `30333` in this file with another value
      - "0.0.0.0:30333:30333"
    restart: unless-stopped
    command: [
      "--chain", "testnet",
      "--base-path", "/var/subspace",
      "--wasm-execution", "compiled",
      "--execution", "wasm",
      "--bootnodes", "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr",
      "--port", "30333",
      "--telemetry-url", "wss://telemetry.polkadot.io/submit/ 1",
      "--telemetry-url", "wss://telemetry.subspace.network/submit/ 1",
      "--rpc-cors", "all",
      "--rpc-methods", "safe",
      "--unsafe-ws-external",
      "--validator",
# Replace `INSERT_YOUR_ID` with your node ID (will be shown in telemetry)
      "--name", "INSERT_YOUR_ID"
    ]
    healthcheck:
      timeout: 5s
# If node setup takes longer then expected, you want to increase `interval` and `retries` number.
      interval: 30s
      retries: 5

  farmer:
    depends_on:
      node:
        condition: service_healthy
# Replace `snapshot-DATE` with latest release (like `snapshot-2022-mar-09`)
    image: ghcr.io/subspace/farmer:snapshot-DATE
# Un-comment following 2 lines to unlock farmer's RPC
#    ports:
#      - "127.0.0.1:9955:9955"
# Instead of specifying volume (which will store data in `/var/lib/docker`), you can
# alternatively specify path to the directory where files will be stored, just make
# sure everyone is allowed to write there
    volumes:
      - farmer-data:/var/subspace:rw
#      - /path/to/subspace-farmer:/var/subspace:rw
    restart: unless-stopped
    command: [
      "farm",
      "--node-rpc-url", "ws://node:9944",
      "--ws-server-listen-addr", "0.0.0.0:9955",
# Replace `WALLET_ADDRESS` with your Polkadot.js wallet address
      "--reward-address", "WALLET_ADDRESS"
    ]
volumes:
  node-data:
  farmer-data:
```

After which follow these steps:
* Now edit created file:
  1. Replace `snapshot-DATE` with the latest release (not pre-release!) snapshot (like `snapshot-2022-mar-09`)
  2. Replace `INSERT_YOUR_ID` with desired name that will be shown in telemetry (doesn't impact anything else)
  3. Replace `WALLET_ADDRESS` with your wallet address
  4. If you want to store files on a separate disk or customize port, read comments in the file
* Ensure [Docker](https://www.docker.com/) is installed and running
* Now go to directory with `docker-compose.yml` and type `docker-compose up -d` to start everything

You can read logs with `docker-compose logs --tail=1000 -f`, for the rest read [Docker Compose CLI reference](https://docs.docker.com/compose/reference/).

# 🤔Notes

## Checking results and interacting with farmnet

Visit [Polkadot.js explorer](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Ffarm-rpc.subspace.network#/explorer), from there you can interact with the Subspace Farmnet as any Substrate-based blockchain.

## Invalid Solution
If you are getting `invalid solution` errors (visible on the terminal that Node runs), please follow "Switching to a new snapshot" steps below and start afresh.

---
## Switching to a new snapshot

### CLI

If you were running a node previously, and want to switch to a new snapshot, please perform these steps and then follow the guideline again:
```
# Replace `FARMER_FILE_NAME` with the name of the node file you downloaded from releases
./FARMER_FILE_NAME wipe
# Replace `NODE_FILE_NAME` with the name of the node file you downloaded from releases
./NODE_FILE_NAME purge-chain --chain testnet
```
Does not matter if the node/farmer executable is the previous one or from the new snapshot, both will work :)
The reason we require this is, with every snapshot change, the network might get partitioned, and you may be on a different genesis than the current one.
In plain English, these commands are like a `reset` button for snapshot changes.

Now follow installation guide.

### Docker

In case of Docker setup run `docker-compose down` (and manually delete custom directories if you have specified them).

Now follow installation guide.

## Help

There are extra commands and parameters you can use on farmer or node, use the `--help` after any other command to display additional options.

Below are some helpful farmer commands:

- `farm --reward-address WALLET_ADDRESS` : starts background plotting and farming together, farmed testnet coins will be sent to `WALLET_ADDRESS`
- `wipe` : erases the plot and identity (including plot, commitment, object mappings and identity files)

Examples:
```bash
# Replace `FARMER_FILE_NAME` with the name of the node file you downloaded from releases
./FARMER_FILE_NAME farm --help
./FARMER_FILE_NAME wipe
```

## [Advanced] Build from source (Linux)

If you're running unsupported Linux distribution or CPU architecture, you may try to build binaries yourself from source.

NOTE: This is primarily targeted at tech-savvy users and not recommended unless you know what you're doing.
Please try to find answer to your question online before reaching out to maintainers.

You'll have to have [Rust toolchain](https://rustup.rs/) installed as well as LLVM and Clang in addition to usual developer tooling (Ubuntu example):
```bash
sudo apt-get install llvm clang
```

Now clone the source and build snapshot `snapshot-2022-mar-09` (replace occurrences with the snapshot you want to build):
```bash
git clone https://github.com/subspace/subspace.git
cd subspace
git checkout snapshot-2022-mar-09
wget -O chain-spec.json https://github.com/subspace/subspace/releases/download/snapshot-2022-mar-09/chain-spec-raw-snapshot-2022-mar-09.json
cargo build \
    --profile production \
    --bin subspace-node \
    --bin subspace-farmer \
    --features=subspace-node/json-chain-spec
```

You'll find two binaries under `target/production` directory once it succeeds, after which refer to instructions above on how to use them.

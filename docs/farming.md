
# 👨‍🌾 Getting Started Farming

This is the documentation/guideline on how to run the farmer. You may also refer to the [help](#help) section for
various commands.

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
.\NODE_FILE_NAME.exe --chain testnet --wasm-execution compiled --execution wasm --bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" --rpc-cors all --rpc-methods unsafe --ws-external --validator --telemetry-url "wss://telemetry.polkadot.io/submit/ 1" --name INSERT_YOUR_ID
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
./NODE_FILE_NAME --chain testnet --wasm-execution compiled --execution wasm --bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" --rpc-cors all --rpc-methods unsafe --ws-external --validator --telemetry-url "wss://telemetry.polkadot.io/submit/ 1" --name INSERT_YOUR_ID
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
./NODE_FILE_NAME --chain testnet --wasm-execution compiled --execution wasm --bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" --rpc-cors all --rpc-methods unsafe --ws-external --validator --telemetry-url "wss://telemetry.polkadot.io/submit/ 1" --name INSERT_YOUR_ID
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

# 🤔Notes

## Checking results and interacting with farmnet

Visit [Polkadot.js explorer](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Ffarm-rpc.subspace.network#/explorer), from there you can interact with the Subspace Farmnet as any Substrate-based blockchain.

## Invalid Solution
If you are getting `invalid solution` errors (visible on the terminal that Node runs), please follow "Switching to a new snapshot" steps below and start afresh.

---
## Switching to a new snapshot
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

## Help

For additional commands for the farmer or node use the `--help` command, which will display additional options for your farming or node configuration. 

An example command:
```bash
# Replace `FARMER_FILE_NAME` with the name of the node file you downloaded from releases
``./FARMER_FILE_NAME --help
```

# ⚠️ Living document

**‼️ NOTE: This is a living document reflecting current state of the codebase, make sure to open this page from the [release you want to install](https://github.com/autonomys/subspace/releases) and not directly ‼️**

# 👨‍🌾 Getting Started Farming

This is the documentation/guideline on how to run the farmer. You may also refer to the [help](#help) section for various commands.

We are regularly releasing stable snapshots. Our CI builds container images and executables for 3 major platforms (Windows, macOS, Linux).

Our snapshots are categorized as the following:
- **Stable releases (you should always grab the latest one, these are the ones that are tested by our team)**
- Pre-releases (for testing things early, intended for developers)

You need 2 executables, select whichever applies to your operating system
* Node Executable - `subspace-node-...`
* Farmer Executable - `subspace-farmer-...`

You can find these executables in the [Releases](https://github.com/autonomys/subspace/releases) section of this Repository.

## Polkadot.js wallet

Before running anything you need to have a wallet where you'll receive testnet coins.
Install [Polkadot.js extension](https://polkadot.js.org/extension/) into your browser and create a new account there.
The address of your account will be necessary at the last step.

## Required ports
Currently, TCP ports `30333`, `30433` and `30533` need to be exposed for node and farmer to work properly.

If you have a server with no firewall, there is nothing to be done, but otherwise make sure to open TCP ports `30333`, `30433` and `30533` for incoming connections.

On the desktop side if you have a router in front of your computer, you'll need to forward TCP ports `30333`, `30433` and `30533` to the machine on which your node is running (how this is done varied from router to router, but there is always a feature like this, ask [on the forum](https://forum.subspace.network/) if you have questions).
If you're connected directly without any router, then again nothing needs to be done in such case.

## 🖼️ Windows Instructions

1. Download the executables for your operating system from the [Releases](https://github.com/autonomys/subspace/releases) tab.
2. Open `Powershell` (we do not recommend using Command Prompt as its syntax is slightly different)
3. In the terminal we will change to the Downloads directory using this command `cd Downloads`
4. We will then start the node using the following command

```PowerShell
# Replace `NODE_FILE_NAME.exe` with the name of the node file you downloaded from releases
# Replace `PATH_TO_NODE` with location where you want to store node data
# Replace `INSERT_YOUR_ID` with a nickname you choose
# Copy all of the lines below, they are all part of the same command
.\NODE_FILE_NAME.exe run `
--base-path PATH_TO_NODE `
--chain gemini-3h `
--farmer `
--name "INSERT_YOUR_ID"
```
5. You should see something similar in the terminal:
```
2022-02-03 10:52:23 Subspace
2022-02-03 10:52:23 ✌️  version 0.1.0-35cf6f5-x86_64-windows
2022-02-03 10:52:23 ❤️  by Subspace Labs <https://subspace.network>, 2021-2022
2022-02-03 10:52:23 📋 Chain specification: Subspace Gemini 3e
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
# Replace `FARMER_FILE_NAME.exe` with the name of the farmer file you downloaded from releases
# Replace `PATH_TO_FARM` with location where you want to store plot files
# Replace `WALLET_ADDRESS` below with your account address from Polkadot.js wallet
# Replace `PLOT_SIZE` with plot size in gigabytes or terabytes, for example 100G or 2T (but leave at least 60G of disk space for node and some for OS)
.\FARMER_FILE_NAME.exe farm --reward-address WALLET_ADDRESS path=PATH_TO_FARM,size=PLOT_SIZE
```

## 🐧 Ubuntu Instructions

1. Download the executables for your operating system from the [Releases](https://github.com/autonomys/subspace/releases) tab.
2. Open your favourite terminal, and change to the Downloads directory using `cd Downloads`
3. Make the farmer & node executable  `chmod +x farmer-name` & `chmod +X node-name`
4. We will then start the node using the following command

```bash
# Replace `NODE_FILE_NAME` with the name of the node file you downloaded from releases
# Replace `PATH_TO_NODE` with location where you want to store node data
# Replace `INSERT_YOUR_ID` with a nickname you choose
# Copy all of the lines below, they are all part of the same command
./NODE_FILE_NAME run \
  --base-path PATH_TO_NODE \
  --chain gemini-3h \
  --farmer \
  --name "INSERT_YOUR_ID"
```
5. You should see something similar in the terminal:
```
2022-02-03 10:52:23 Subspace
2022-02-03 10:52:23 ✌️  version 0.1.0-35cf6f5-x86_64-ubuntu
2022-02-03 10:52:23 ❤️  by Subspace Labs <https://subspace.network>, 2021-2022
2022-02-03 10:52:23 📋 Chain specification: Subspace Gemini 3e
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
# Replace `FARMER_FILE_NAME` with the name of the farmer file you downloaded from releases
# Replace `PATH_TO_FARM` with location where you want to store plot files
# Replace `WALLET_ADDRESS` below with your account address from Polkadot.js wallet
# Replace `PLOT_SIZE` with plot size in gigabytes or terabytes, for example 100G or 2T (but leave at least 60G of disk space for node and some for OS)
./FARMER_FILE_NAME farm --reward-address WALLET_ADDRESS path=PATH_TO_FARM,size=PLOT_SIZE
```

## 🍎 macOS Instructions

1. Download the executables for your operating system from the [Releases](https://github.com/autonomys/subspace/releases) tab and extract binaries from ZIP archives.
2. Open your favourite terminal, and change to the Downloads directory using `cd Downloads`
3. Make the farmer & node executable  `chmod +x farmer-name` & `chmod +X node-name`
4. We will then start the node using the following command

> *Note, when attempting to run this command you may be prompted:* Click on `cancel` instead of moving it to trash.
To allow execution, go to `System Preferences -> Security & Privacy -> General`, and click on `allow`.
After this, simply repeat the step you prompted for (step 4 or 6). This time, click the `Open` button when prompted.

```bash
# Replace `NODE_FILE_NAME` with the name of the node file you downloaded from releases
# Replace `PATH_TO_NODE` with location where you want to store node data
# Replace `INSERT_YOUR_ID` with a nickname you choose
# Copy all of the lines below, they are all part of the same command
./NODE_FILE_NAME run \
  --base-path PATH_TO_NODE \
  --chain gemini-3h \
  --farmer \
  --name "INSERT_YOUR_ID"
```
5. You should see something similar in the terminal:
```
2022-02-03 10:52:23 Subspace
2022-02-03 10:52:23 ✌️  version 0.1.0-35cf6f5-x86_64-macos
2022-02-03 10:52:23 ❤️  by Subspace Labs <https://subspace.network>, 2021-2022
2022-02-03 10:52:23 📋 Chain specification: Subspace Gemini 3e
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
# Replace `PATH_TO_FARM` with location where you want to store plot files
# Replace `FARMER_FILE_NAME` with the name of the farmer file you downloaded from releases
# Replace `WALLET_ADDRESS` below with your account address from Polkadot.js wallet
# Replace `PLOT_SIZE` with plot size in gigabytes or terabytes, for example 100G or 2T (but leave at least 60G of disk space for node and some for OS)
./FARMER_FILE_NAME farm --reward-address WALLET_ADDRESS path=PATH_TO_FARM,size=PLOT_SIZE
```
7. It may prompt again in here. Refer to the note on step 4.

## 🐋 Docker Instructions

Create `subspace` directory and `docker-compose.yml` in it with following contents:
```yml
services:
  node:
    # Replace `snapshot-DATE` with the latest release (like `snapshot-2022-apr-29`)
    image: ghcr.io/autonomys/node:snapshot-DATE
    volumes:
# Instead of specifying volume (which will store data in `/var/lib/docker`), you can
# alternatively specify path to the directory where files will be stored, just make
# sure everyone is allowed to write there
      - node-data:/var/subspace:rw
#      - /path/to/subspace-node:/var/subspace:rw
    ports:
# If port 30333 or 30433 is already occupied by another Substrate-based node, replace all
# occurrences of `30333` or `30433` in this file with another value
      - "0.0.0.0:30333:30333/tcp"
      - "0.0.0.0:30433:30433/tcp"
    restart: unless-stopped
    command: [
      "run",
      "--chain", "gemini-3h",
      "--base-path", "/var/subspace",
      "--listen-on", "/ip4/0.0.0.0/tcp/30333",
      "--dsn-listen-on", "/ip4/0.0.0.0/tcp/30433",
      "--rpc-listen-on", "0.0.0.0:9944",
      "--rpc-cors", "all",
      "--rpc-methods", "unsafe",
      "--farmer",
# Replace `INSERT_YOUR_ID` with your node ID (will be shown in telemetry)
      "--name", "INSERT_YOUR_ID"
    ]
    healthcheck:
      timeout: 5s
# If node setup takes longer than expected, you want to increase `interval` and `retries` number.
      interval: 30s
      retries: 60

  farmer:
    depends_on:
      node:
        condition: service_healthy
    # Replace `snapshot-DATE` with latest release (like `snapshot-2022-apr-29`)
    image: ghcr.io/autonomys/farmer:snapshot-DATE
    volumes:
# Instead of specifying volume (which will store data in `/var/lib/docker`), you can
# alternatively specify path to the directory where files will be stored, just make
# sure everyone is allowed to write there
      - farmer-data:/var/subspace:rw
#      - /path/to/subspace-farmer:/var/subspace:rw
    ports:
# If port 30533 is already occupied by something else, replace all
# occurrences of `30533` in this file with another value
      - "0.0.0.0:30533:30533/tcp"
    restart: unless-stopped
    command: [
      "farm",
      "--node-rpc-url", "ws://node:9944",
      "--listen-on", "/ip4/0.0.0.0/tcp/30533",
# Replace `WALLET_ADDRESS` with your Polkadot.js wallet address
      "--reward-address", "WALLET_ADDRESS",
      # Replace `PLOT_SIZE` with plot size in gigabytes or terabytes, for example 100G or 2T (but leave at least 60G of disk space for node and some for OS)
      "path=/var/subspace,size=PLOT_SIZE",
    ]
volumes:
  node-data:
  farmer-data:
```

After which follow these steps:
* Now edit created file:
  * Replace `snapshot-DATE` with the latest release (not pre-release!) snapshot (like `snapshot-2022-apr-29`)
  * Replace `INSERT_YOUR_ID` with desired name that will be shown in telemetry (doesn't impact anything else)
  * Replace `WALLET_ADDRESS` with your wallet address
  * Replace `PLOT_SIZE` with plot size in gigabytes or terabytes, for example 100G or 2T (but leave at least 10G of disk space for node)
  * If you want to store files on a separate disk or customize port, read comments in the file
* Ensure [Docker](https://www.docker.com/) is installed and running
* Now go to directory with `docker-compose.yml` and type `docker-compose up -d` to start everything

You can read logs with `docker-compose logs --tail=1000 -f`, for the rest read [Docker Compose CLI reference](https://docs.docker.com/compose/reference/).

# 🤔Notes

## Checking results and interacting with the network

Visit [Polkadot.js explorer](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Feu-0.gemini-3h.subspace.network%2Fws#/explorer), from there you can interact with Autonomys Network as any Substrate-based blockchain.

## Switching from older/different versions of Subspace

### CLI

If you were running a node previously, and want to switch to a new snapshot, please perform these steps and then follow the guideline again:
```
# Replace `FARMER_FILE_NAME` with the name of the node file you downloaded from releases
./FARMER_FILE_NAME wipe PATH_TO_FARM
# Replace `NODE_FILE_NAME` with the name of the node file you downloaded from releases
./NODE_FILE_NAME wipe PATH_TO_NODE
```
Does not matter if the node/farmer executable is the previous one or from the new snapshot, both will work :)
The reason we require this is, with every snapshot change, the network might get partitioned, and you may be on a different genesis than the current one.
In plain English, these commands are like a `reset` button for snapshot changes.

Now follow installation guide.

### Docker

In case of Docker setup run `docker-compose down -v` (and manually delete custom directories if you have specified them).

Now follow installation guide.

## Help

There are extra commands and parameters you can use on farmer or node, use the `--help` after any other command to display additional options.

Below are some helpful samples:

- `./FARMER_FILE_NAME benchmark audit PATH_TO_FARM`: benchmark auditing performance of the farm at `PATH_TO_FARM`
- `./FARMER_FILE_NAME info PATH_TO_FARM`: show information about the farm at `PATH_TO_FARM`
- `./FARMER_FILE_NAME scrub PATH_TO_FARM`: Scrub the farm to find and fix farm at `PATH_TO_FARM` corruption
- `./FARMER_FILE_NAME wipe PATH_TO_FARM`: erases everything related to farmer if data were stored in `PATH_TO_FARM`
- `./NODE_FILE_NAME wipe PATH_TO_NODE`: erases data related to the node if data were stored in `PATH_TO_NODE`

Examples:
```bash
# Replace `FARMER_FILE_NAME` with the name of the node file you downloaded from releases
./FARMER_FILE_NAME farm --help
./FARMER_FILE_NAME wipe PATH_TO_FARM
```

## [Advanced] Support for multiple disks

Farm path and size you have seen above can be specified more than once to engage multiple disks.
It is recommended to specify multiple disks explicitly rather than using RAID for better hardware utilization and efficiency.

Example:
```
./FARMER_FILE_NAME farm --reward-address WALLET_ADDRESS \
    path=/media/ssd1,size=100GiB \
    path=/media/ssd2,size=10T \
    path=/media/ssd3,size=10T
```

## [Advanced] Build from source (Linux)

If you're running unsupported Linux distribution or CPU architecture, you may try to build binaries yourself from source.

NOTE: This is primarily targeted at tech-savvy users and not recommended unless you know what you're doing.
Please try to find answer to your question online before reaching out to maintainers.

Check [crates/subspace-node](../crates/subspace-node/README.md) and [crates/subspace-farmer](../crates/subspace-farmer/README.md) for required dependencies.

Now clone the source and build snapshot `snapshot-2022-apr-29` (replace occurrences with the snapshot you want to build):
```bash
git clone https://github.com/autonomys/subspace.git
cd subspace
git checkout snapshot-2022-apr-29
cargo build \
    --profile production \
    --bin subspace-node \
    --bin subspace-farmer
```

You'll find two binaries under `target/production` directory once it succeeds, after which refer to instructions above on how to use them.

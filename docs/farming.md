# ⚠️ Living document

**‼️ NOTE: This is a living document reflecting current state of the codebase, make sure to open this page from the [release you want to install](https://github.com/subspace/subspace/releases) and not directly ‼️**

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

1. Download the executables for your operating system from the [Releases](https://github.com/subspace/subspace/releases) tab.
2. Open `Powershell` (we do not recommend using Command Prompt as its syntax is slightly different)
3. In the terminal we will change to the Downloads directory using this command `cd Downloads`
4. We will then start the node using the following command

```PowerShell
# Replace `NODE_FILE_NAME.exe` with the name of the node file you downloaded from releases
# Replace `PATH_TO_NODE` with location where you want you store node data
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
# Replace `PATH_TO_FARM` with location where you want you store plot files
# Replace `WALLET_ADDRESS` below with your account address from Polkadot.js wallet
# Replace `PLOT_SIZE` with plot size in gigabytes or terabytes, for example 100G or 2T (but leave at least 60G of disk space for node and some for OS)
.\FARMER_FILE_NAME.exe farm --reward-address WALLET_ADDRESS path=PATH_TO_FARM,size=PLOT_SIZE
```

## 🐧 Ubuntu Instructions

1. Download the executables for your operating system from the [Releases](https://github.com/subspace/subspace/releases) tab.
2. Open your favourite terminal, and change to the Downloads directory using `cd Downloads`
3. Make the farmer & node executable  `chmod +x farmer-name` & `chmod +X node-name`
4. We will then start the node using the following command

```bash
# Replace `NODE_FILE_NAME` with the name of the node file you downloaded from releases
# Replace `PATH_TO_NODE` with location where you want you store node data
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
# Replace `PATH_TO_FARM` with location where you want you store plot files
# Replace `WALLET_ADDRESS` below with your account address from Polkadot.js wallet
# Replace `PLOT_SIZE` with plot size in gigabytes or terabytes, for example 100G or 2T (but leave at least 60G of disk space for node and some for OS)
./FARMER_FILE_NAME farm --reward-address WALLET_ADDRESS path=PATH_TO_FARM,size=PLOT_SIZE
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
# Replace `PATH_TO_NODE` with location where you want you store node data
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
# Replace `PATH_TO_FARM` with location where you want you store plot files
# Replace `FARMER_FILE_NAME` with the name of the farmer file you downloaded from releases
# Replace `WALLET_ADDRESS` below with your account address from Polkadot.js wallet
# Replace `PLOT_SIZE` with plot size in gigabytes or terabytes, for example 100G or 2T (but leave at least 60G of disk space for node and some for OS)
./FARMER_FILE_NAME farm --reward-address WALLET_ADDRESS path=PATH_TO_FARM,size=PLOT_SIZE
```
7. It may prompt again in here. Refer to the note on step 4.

## 🐋 Docker Instructions

Create `subspace` directory and `docker-compose.yml` in it with following contents:
```yml
version: "3.7"
services:
  node:
    # Replace `snapshot-DATE` with the latest release (like `snapshot-2022-apr-29`)
    # For running on Aarch64 add `-aarch64` after `DATE`
    image: ghcr.io/subspace/node:snapshot-DATE
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
    # For running on Aarch64 add `-aarch64` after `DATE`
    image: ghcr.io/subspace/farmer:snapshot-DATE
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

Visit [Polkadot.js explorer](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Feu-0.gemini-3h.subspace.network%2Fws#/explorer), from there you can interact with Subspace Network as any Substrate-based blockchain.

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
git clone https://github.com/subspace/subspace.git
cd subspace
git checkout snapshot-2022-apr-29
cargo build \
    --profile production \
    --bin subspace-node \
    --bin subspace-farmer
```

You'll find two binaries under `target/production` directory once it succeeds, after which refer to instructions above on how to use them.

# ⚠️ 活动文档

**‼️ 注意：这是一个活动文档，反映了当前代码库的状态，请确保从 [您想安装的版本](https://github.com/subspace/subspace/releases) 打开此页面，而不是直接打开 ‼️**

# 👨‍🌾 入门种植

这是关于如何运行农民的文档/指南。您还可以参考 [帮助](#help) 部分获取各种命令的信息。

我们定期发布稳定快照。我们的 CI 构建容器影像和可执行文件适用于 3 个主要平台（Windows、macOS、Linux）。

我们的快照被分类如下：
- **稳定版本（您应该始终选择最新版本，这些版本由我们的团队测试）**
- 预发布版本（用于尽早测试，面向开发人员）

您需要 2 个可执行文件，根据您的操作系统选择相应的文件
* 节点可执行文件 - `subspace-node-...`
* 农民可执行文件 - `subspace-farmer-...`

您可以在此存储库的 [发布](https://github.com/subspace/subspace/releases) 部分找到这些可执行文件。

## Polkadot.js 钱包

在运行任何内容之前，您需要有一个钱包，您将在其中收到测试网络币。
在浏览器中安装 [Polkadot.js 扩展程序](https://polkadot.js.org/extension/) 并在此处创建新账户。
您的账户地址将在最后一步中用到。

## 需要打开的端口
目前，需要打开 TCP 端口 `30333`、`30433` 和 `30533` 才能使节点和农民正常工作。

如果您有一台没有防火墙的服务器，则无需执行任何操作，但如果有，请确保打开 TCP 端口 `30333`、`30433` 和 `30533` 以便接受连接。

如果您的电脑前面有一个路由器，则需要将 TCP 端口 `30333`、`30433` 和 `30533` 转发到运行节点的机器上（这是如何完成的因路由器而异，但总会有类似功能，请在[论坛](https://forum.subspace.network/)上提问，如果您有疑问）。
如果直接连接而没有任何路由器，则在这种情况下无需执行任何操作。

## 🖼️ Windows 指南

1. 从 [Releases](https://github.com/subspace/subspace/releases) 选项卡下载适用于您的操作系统的可执行文件。
2. 打开 `Powershell`（我们不推荐使用命令提示符，因为其语法略有不同）
3. 在终端中，使用以下命令切换到 Downloads 目录 `cd Downloads`
4. 然后使用以下命令启动节点

```PowerShell
# 用您从发布中下载的节点文件名替换 `NODE_FILE_NAME.exe`
# 用您要存储节点数据的位置替换 `PATH_TO_NODE`
# 用您选择的昵称替换 `INSERT_YOUR_ID`
# 将下面所有的行都复制，它们都是同一条命令的一部分
.\NODE_FILE_NAME.exe run `
--base-path PATH_TO_NODE `
--chain gemini-3h `
--farmer `
--name "INSERT_YOUR_ID"
```
5. 您将在终端上看到类似的输出内容：
```
2022-02-03 10:52:23 Subspace
2022-02-03 10:52:23 ✌️  版本 0.1.0-35cf6f5-x86_64-windows
2022-02-03 10:52:23 ❤️  由 Subspace Labs <https://subspace.network>，2021-2022 提供
2022-02-03 10:52:23 📋 链规范: Subspace Gemini 3e
2022-02-03 10:52:23 🏷  节点名称: YOUR_FANCY_NAME
2022-02-03 10:52:23 👤 角色: AUTHORITY
2022-02-03 10:52:23 💾 数据库: RocksDb 位于 C:\Users\X\AppData\Local\subspace-node-windows-x86_64-snapshot-2022-jan-05.exe\data\chains\subspace_test\db\full
2022-02-03 10:52:23 ⛓  本机运行时: subspace-100 (subspace-1.tx1.au1)
2022-02-03 10:52:23 🔨 正在初始化创世块/状态（状态: 0x22a5…17ea，头哈希: 0x6ada…0d38）
2022-02-03 10:52:24 ⏱  从块 0x6ada0792ea62bf3501abc87d92e1ce0e78ddefba66f02973de54144d12ed0d38 加载的块时间 = 1s
2022-02-03 10:52:24 从创世块开始存档
2022-02-03 10:52:24 存档已生成的块范围为 0..=0
2022-02-03 10:52:24 🏷  本地节点身份是: 12D3KooWBgKtea7MVvraeNyxdPF935pToq1x9VjR1rDeNH1qecXu
2022-02-03 10:52:24 🧑‍🌾 正在启动 Subspace 作者工作进程
2022-02-03 10:52:24 📦 当前已知的最高块为 #0
2022-02-03 10:52:24 〽️ Prometheus 导出器已启动在 127.0.0.1:9615 上
2022-02-03 10:52:24 正在侦听新连接于 0.0.0.0:9944.
2022-02-03 10:52:26 🔍 发现了我们节点的新外部地址: /ip4/176.233.17.199/tcp/30333/p2p/12D3KooWBgKtea7MVvraeNyxdPF935pToq1x9VjR1rDeNH1qecXu
2022-02-03 10:52:29 ⚙️  同步中，目标=#215883（2 个对等节点），最佳块: #55（0xafc7…bccf），已最终化块: #0（0x6ada…0d38），⬇ 850.1kiB/s ⬆ 1.5kiB/s
```
6. 在运行此命令之后，Windows 可能会要求您关于防火墙的权限，请选择 `允许`。
7. 然后我们将打开另一个终端，切换到下载目录，然后使用以下命令启动农民节点：
```PowerShell
# 用您从发布中下载的农民文件名替换 `FARMER_FILE_NAME.exe`
# 用您要存储绘图文件的位置替换 `PATH_TO_FARM`
# 使用您在 Polkadot.js 钱包中的账户地址替换下面的 `WALLET_ADDRESS`
# 使用绘图大小（以千兆字节或兆字节为单位）替换 `PLOT_SIZE`，例如 100G 或 2T（但为节点保留至少 60G 的磁盘空间，以及一些为操作系统保留的空间）
.\FARMER_FILE_NAME.exe farm --reward-address WALLET_ADDRESS path=PATH_TO_FARM,size=PLOT_SIZE
```

## 🐧 Ubuntu 指南

1. 从 [Releases](https://github.com/subspace/subspace/releases) 选项卡下载适用于您的操作系统的可执行文件。
2. 打开您喜欢使用的终端，并使用 `cd Downloads` 命令切换到 Downloads 目录。
3. 使农民和节点可执行 `chmod +x farmer-name` & `chmod +X node-name`。
4. 然后使用以下命令启动节点

## 翻译 private_upload/default_user/2024-04-23-09-08-19/farming.md.part-1.md

```bash
# 将 `NODE_FILE_NAME` 替换为您从发布中下载的节点文件的名称
# 将 `PATH_TO_NODE` 替换为您想要存储节点数据的位置
# 将 `INSERT_YOUR_ID` 替换为您选择的昵称
# 复制下面的所有行，它们都是同一条命令的一部分
./NODE_FILE_NAME run \
  --base-path PATH_TO_NODE \
  --chain gemini-3h \
  --farmer \
  --name "INSERT_YOUR_ID"
```
5. 您应该在终端看到类似的信息:
```
2022-02-03 10:52:23 Subspace
2022-02-03 10:52:23 ✌️  版本 0.1.0-35cf6f5-x86_64-ubuntu
2022-02-03 10:52:23 ❤️  由 Subspace Labs <https://subspace.network>, 2021-2022
2022-02-03 10:52:23 📋 链规范: Subspace Gemini 3e
2022-02-03 10:52:23 🏷  节点名称: YOUR_FANCY_NAME
2022-02-03 10:52:23 👤 角色: AUTHORITY
2022-02-03 10:52:23 💾 数据库: RocksDb 位于 /home/X/.local/share/subspace-node-x86_64-ubuntu-20.04-snapshot-2022-jan-05/chains/subspace_test/db/full
2022-02-03 10:52:23 ⛓  本机运行时: subspace-100 (subspace-1.tx1.au1)
2022-02-03 10:52:23 🔨 初始化 Genesis 区块/状态 (状态: 0x22a5…17ea，头哈希: 0x6ada…0d38)
2022-02-03 10:52:24 ⏱  从块 0x6ada0792ea62bf3501abc87d92e1ce0e78ddefba66f02973de54144d12ed0d38 加载的块时间 = 1s
2022-02-03 10:52:24 从 Genesis 开始归档
2022-02-03 10:52:24 归档已产生的块 0..=0
2022-02-03 10:52:24 🏷  本地节点身份是: 12D3KooWBgKtea7MVvraeNyxdPF935pToq1x9VjR1rDeNH1qecXu
2022-02-03 10:52:24 🧑‍🌾 启动 Subspace 作者工作
2022-02-03 10:52:24 📦 最高已知块为 #0
2022-02-03 10:52:24 〽️ Prometheus 导出器已在 127.0.0.1:9615 启动
2022-02-03 10:52:24 正在监听新连接：0.0.0.0:9944
2022-02-03 10:52:26 🔍 发现了我们节点的新外部地址：/ip4/176.233.17.199/tcp/30333/p2p/12D3KooWBgKtea7MVvraeNyxdPF935pToq1x9VjR1rDeNH1qecXu
2022-02-03 10:52:29 ⚙️  正在同步，目标=#215883（2 个对等点），最好:#55（0xafc7…bccf）, 最终:#0（0x6ada…0d38），⬇ 850.1kiB/s ⬆ 1.5kiB/s
```
7. 然后我们将打开另一个终端，切换到下载目录，然后使用以下命令启动农民节点：
```bash
# 将 `FARMER_FILE_NAME` 替换为您从发布中下载的农民文件的名称
# 将 `PATH_TO_FARM` 替换为您想要存储绘图文件的位置
# 将下面的 `WALLET_ADDRESS` 替换为 Polkadot.js 钱包中的您的账户地址
# 将 `PLOT_SIZE` 替换为绘图大小，以GB或TB为单位，例如100G或2T（但至少保留60G的磁盘空间给节点，还可能需要一些用于系统）
./FARMER_FILE_NAME farm --reward-address WALLET_ADDRESS path=PATH_TO_FARM,size=PLOT_SIZE
```

## 🍎 macOS 指南

1. 从 [Releases](https://github.com/subspace/subspace/releases) 选项卡下载适用于您的操作系统的可执行文件，并从ZIP归档中提取二进制文件。
2. 打开您喜欢使用的终端，使用 `cd Downloads` 命令切换到 Downloads 目录。
3. 使农民和节点可执行  `chmod +x farmer-name` & `chmod +X node-name`
4. 然后我们将使用以下命令启动节点

> *注意: 当尝试运行此命令时，您可能会收到提示:* 点击`取消`而不是将其移至垃圾箱.
要允许执行，请转到`系统偏好设置 -> 安全性与隐私 -> 通用`，然后点击`允许`。
之后，只需重复提示的步骤（步骤4或6）。这次，在提示时点击`打开`按钮。

## 翻译 private_upload/default_user/2024-04-23-09-08-19/farming.md.part-2.md

```bash
# 用下载的节点文件的名称替换`NODE_FILE_NAME`
# 用你想要存储节点数据的位置替换`PATH_TO_NODE`
# 用你选择的昵称替换`INSERT_YOUR_ID`
# 复制下面的所有行，它们都是同一条命令的一部分
./NODE_FILE_NAME run \
  --base-path PATH_TO_NODE \
  --chain gemini-3h \
  --farmer \
  --name "INSERT_YOUR_ID"
```

5. 你应该在终端中看到类似的内容：
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
7. 然后我们将打开另一个终端，切换到下载目录，然后使用以下命令启动农民节点：
```bash
# 用你想要存储绘图文件的位置替换`PATH_TO_FARM`
# 用你从 Polkadot.js 钱包中得到的账户地址替换下面的`WALLET_ADDRESS`
# 用绘图大小（以千兆字节或千兆字节为单位）替换`PLOT_SIZE`，例如 100G 或 2T（但是为节点保留至少 60G 的磁盘空间，以及一些用于操作系统）
./FARMER_FILE_NAME farm --reward-address WALLET_ADDRESS path=PATH_TO_FARM,size=PLOT_SIZE
```
7. 这里可能会再次提示。请参考第 4 步的注意事项。

## 🐋 Docker 说明

在 `subspace` 目录中创建 `docker-compose.yml` 文件，并写入以下内容：
```yml
version: "3.7"
services:
  node:
    # 用最新发布（如`snapshot-2022-apr-29`）替换`snapshot-DATE`
    # 以在 Aarch64 上运行，请在`DATE`后面添加`-aarch64`
    image: ghcr.io/subspace/node:snapshot-DATE
    volumes:
# 替代指定卷（将数据存储在`/var/lib/docker`），你可以
# 替代地指定目录路径，在那里文件将被存储，只需确保
# 每个人都被允许在那里写入
      - node-data:/var/subspace:rw
#      - /path/to/subspace-node:/var/subspace:rw
    ports:
# 如果端口30333或30433已被其他基于Substrate的节点占用，
# 将此文件中的所有`30333`或`30433`替换为其他值
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
# 用你的节点 ID 替换`INSERT_YOUR_ID`（将在网络传输中显示）
      "--name", "INSERT_YOUR_ID"
    ]
    healthcheck:
      timeout: 5s
# 如果节点设置花费的时间比预期的时间长，您可能需要增加`interval`和`retries`数字。
      interval: 30s
      retries: 60

  farmer:
    depends_on:
      node:
        condition: service_healthy
    # 用最新发布（如`snapshot-2022-apr-29`）替换`snapshot-DATE`
    # 以在 Aarch64 上运行，请在`DATE`后面添加`-aarch64`
    image: ghcr.io/subspace/farmer:snapshot-DATE
    volumes:
# 替代指定卷（将数据存储在`/var/lib/docker`），你可以
# 替代地指定目录路径，在那里文件将被存储，只需确保
# 每个人都被允许在那里写入
      - farmer-data:/var/subspace:rw
#      - /path/to/subspace-farmer:/var/subspace:rw
    ports:
# 如果端口 30533 已被其他服务占用，请将此文件中的所有 `30533` 替换为其他值
      - "0.0.0.0:30533:30533/tcp"
    restart: unless-stopped
    command: [
      "farm",
      "--node-rpc-url", "ws://node:9944",
      "--listen-on", "/ip4/0.0.0.0/tcp/30533",
# 用你的 Polkadot.js 钱包地址替换`WALLET_ADDRESS`
      "--reward-address", "WALLET_ADDRESS",
      # 用绘图大小（以千兆字节或千兆字节为单位）替换`PLOT_SIZE`，例如 100G 或 2T（但是为节点保留至少 60G 的磁盘空间，以及一些用于操作系统）
      "path=/var/subspace,size=PLOT_SIZE",
    ]
volumes:
  node-data:
  farmer-data:
```

然后按照以下步骤操作：
* 现在编辑创建的文件：
  * 用最新发布（非预发布！）快照（如`snapshot-2022-apr-29`）替换`snapshot-DATE`
  * 用要在遥测中显示的所需名称替换`INSERT_YOUR_ID`（不会对其他任何内容产生影响）
  * 用你的钱包地址替换`WALLET_ADDRESS`
  * 用按千兆字节或千兆字节计量的绘图大小替换`PLOT_SIZE`，例如 100G 或 2T（但是为节点保留至少 10G 的磁盘空间）
  * 如果要将文件存储在独立磁盘上或自定义端口，请阅读文件中的注释
* 确保 [Docker](https://www.docker.com/) 已安装并正在运行
* 现在转到包含 `docker-compose.yml` 的目录，并输入 `docker-compose up -d` 以启动所有内容

你可以使用 `docker-compose logs --tail=1000 -f` 查看日志，有关其余内容，请阅读 [Docker Compose CLI 参考](https://docs.docker.com/compose/reference/)。

## 翻译 private_upload/default_user/2024-04-23-09-08-19/farming.md.part-3.md

## 检查结果并与网络交互

访问[Polkadot.js资源管理器](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Feu-0.gemini-3h.subspace.network%2Fws#/explorer)，从那里您可以像与任何基于Substrate的区块链一样与Subspace Network进行交互。

## 从旧版本/不同版本的Subspace切换

### 命令行界面

如果您之前运行了一个节点，并且想要切换到一个新的快照，请执行以下步骤，然后再次按照指南进行操作：
```
# 将`FARMER_FILE_NAME`替换为您从发布中下载的节点文件的名称
./FARMER_FILE_NAME wipe PATH_TO_FARM
# 将`NODE_FILE_NAME`替换为您从发布中下载的节点文件的名称
./NODE_FILE_NAME wipe PATH_TO_NODE
```
无论节点/农民可执行文件是之前的还是来自新的快照，都可以使用:)
我们要求这样做的原因是，每次快照更改时，网络可能会被分区，您可能会处于与当前快照不同的起源状态。
用通俗的话来说，这些命令就像是快照更改的“重置”按钮。

现在按照安装指南进行操作。

### Docker

如果使用Docker环境，请运行`docker-compose down -v`（并手动删除自定义目录，如果您指定了）。

现在按照安装指南进行操作。

## 帮助

农民或节点上可以使用额外的命令和参数，在任何其他命令之后加上`--help`以显示其他选项。

以下是一些有用的示例：

- `./FARMER_FILE_NAME benchmark audit PATH_TO_FARM`：对`PATH_TO_FARM`上的农场进行性能审计
- `./FARMER_FILE_NAME info PATH_TO_FARM`：显示有关`PATH_TO_FARM`上的农场的信息
- `./FARMER_FILE_NAME scrub PATH_TO_FARM`：清理农场，找到并修复`PATH_TO_FARM`上的农场损坏
- `./FARMER_FILE_NAME wipe PATH_TO_FARM`：擦除与农民相关的所有内容（如果数据存储在`PATH_TO_FARM`中）
- `./NODE_FILE_NAME wipe PATH_TO_NODE`：擦除与节点相关的数据（如果数据存储在`PATH_TO_NODE`中）

示例：
```bash
# 将`FARMER_FILE_NAME`替换为您从发布中下载的节点文件的名称
./FARMER_FILE_NAME farm --help
./FARMER_FILE_NAME wipe PATH_TO_FARM
```

## [高级] 支持多个磁盘

您在上面看到的农场路径和大小可以多次指定以使用多个磁盘。
建议明确指定多个磁盘，而不是使用RAID，以提高硬件利用率和效率。

示例：
```
./FARMER_FILE_NAME farm --reward-address WALLET_ADDRESS \
    path=/media/ssd1,size=100GiB \
    path=/media/ssd2,size=10T \
    path=/media/ssd3,size=10T
```

## [高级] 从源代码构建（Linux）

如果您使用的是不受支持的Linux发行版或CPU架构，可以尝试从源代码自行构建二进制文件。

注意：这主要面向技术熟练的用户，不建议除非您知道自己在做什么。
在寻求维护者帮助之前，请尝试在网上找到相关问题的答案。

请查看[crates/subspace-node](../crates/subspace-node/README.md)和[crates/subspace-farmer](../crates/subspace-farmer/README.md)以获取所需的依赖项。

现在克隆源代码并构建快照`snapshot-2022-apr-29`（用您想要构建的快照替换出现的内容）：
```bash
git clone https://github.com/subspace/subspace.git
cd subspace
git checkout snapshot-2022-apr-29
cargo build \
    --profile production \
    --bin subspace-node \
    --bin subspace-farmer
```

一旦成功，您将在`target/production`目录下找到两个二进制文件，之后请参考上面的说明来使用它们。


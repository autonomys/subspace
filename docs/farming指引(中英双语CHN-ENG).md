# 👨‍🌾 准备工作 (Getting Started Farming)

This is the documentation/guideline on how to run the farmer. You may also refer to the [help](#help) section for various commands.

本指南主要内容是如何运行farmer。您也可以参考[帮助](#help) 环节，查看更多其他命令。

We are regularly releasing stable snapshots. Our CI builds container images and executables for 3 major platforms (Windows, macOS, Linux).

我们会定期发布稳定的快照(snapshots)。我们团队主要向3个平台(Windows, macOS, Linux)构建封装镜像和可执行文件。

Our snapshots are categorized as the following:
我们的快照按以下分类：
- **Stable releases (you should always grab the latest one, these are the ones that are tested by our team)**
  **稳定发布(您应该总是获取已经被我们团队测试过的最新版本)**
- Pre-releases (for testing things early, intended for developers)
   前瞻发布(只为开发者用作测试目的)

You need 2 executables, select whichever applies to your operating system
你需要2个可执行文件，请选择两个和您操作系统匹配的文件
* Node Executable(Node可执行文件) - `subspace-node-...`
* Farmer Executable(Farmer可执行文件) - `subspace-farmer-...`

You can find these executables in the [Releases](https://github.com/subspace/subspace/releases) section of this Repository.
您可以在 [发布(Releases)](https://github.com/subspace/subspace/releases) 找到对应的文件。

> This is a ***non-incentivized*** testnet. Meaning there are no rewards in place at this time, and has absolutely no financial benefit to being run at this time.
> 
> 请注意这是***非激励性***的测试网，这意味着目前参与没有奖励和财务上的回报。



## Polkadot.js钱包(Polkadot.js wallet)

Before running anything you need to have a wallet where you'll receive testnet coins.
Install [Polkadot.js extension](https://polkadot.js.org/extension/) into your browser and create a new account there.
The address of your account will be necessary at the last step.

在运行任何东西之前，您需要一个钱包来获取测试代币。请在您的浏览器安装
[Polkadot.js extension](https://polkadot.js.org/extension/) 并创建一个账户。您账户的地址在最后一步设置时是必要的。


## 🖼️ Windows指引 (Windows Instructions)

1. Download the executables for your operating system from the [Releases](https://github.com/subspace/subspace/releases) tab.
2. Open `Powershell` (we do not recommend using Command Prompt as it's syntax is slightly different)
3. In the terminal we will change to the Downloads directory using this command `cd Downloads`
4. We will then start the node using the following command

1. 从 [Releases](https://github.com/subspace/subspace/releases) 下载适用于您操作系统的可执行文件。
2. 打开`Powershell`（不建议使用命令提示符，因为它的语法略有不同）
3. 在终端中，我们将使用此命令 `cd Downloads` 切换到 Downloads 目录
4. 我们将使用以下命令启动节点

```PowerShell
# Replace `NODE_FILE_NAME.exe` with the name of the node file you downloaded from releases(将`NODE_FILE_NAME.exe`替换为您从releases下载的node文件)
# Replace `INSERT_YOUR_ID` with a nickname you choose(将`INSERT_YOUR_ID`替换为任何一个您选择的名称)
# Copy all of the lines below, they are all part of the same command(复制下列所有代码，他们是一体的)
.\NODE_FILE_NAME.exe `
--chain testnet `
--wasm-execution compiled `
--execution wasm `
--bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" `
--rpc-cors all `
--rpc-methods unsafe `
--ws-external `
--validator `
--telemetry-url "wss://telemetry.polkadot.io/submit/ 1" `
--telemetry-url "wss://telemetry.subspace.network/submit 1" `
--name INSERT_YOUR_ID
```
5. You should see something similar in the terminal(您应该在终端看到和以下类似的内容):
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

6. 运行此命令后，Windows 可能会要求您提供与防火墙相关的权限，请您选择“允许”。
7. 然后我们将打开另一个终端，切换到下载目录，然后使用以下命令启动farmer节点：

```PowerShell
# Replace `FARMER_FILE_NAME.exe` with the name of the node file you downloaded from releases(将`FARMER_FILE_NAME.exe`替换为您从releases下载的farmer文件)
# Replace `WALLET_ADDRESS` below with your account address from Polkadot.js wallet(将`WALLET_ADDRESS`替换为您Polkadot.js的账户地址)
.\FARMER_FILE_NAME.exe farm --reward-address WALLET_ADDRESS
```

## 🐧 Linux指引 (Linux Instructions)

1. Download the executables for your operating system from the [Releases](https://github.com/subspace/subspace/releases) tab.
2. Open your favourite terminal, and change to the Downloads directory using `cd Downloads`
3. Make the farmer & node executable  `chmod +x farmer-name` & `chmod +X node-name`
4. We will then start the node using the following command

1. 从 [Releases](https://github.com/subspace/subspace/releases) 下载适用于您操作系统的可执行文件。
2. 打开你喜欢的终端，使用`cd Downloads`切换到Downloads目录
3. 使farmer和node可执行 `chmod +x farmer-name` & `chmod +X node-name`
4. 然后我们将用以下命令启动节点

```bash
# Replace `NODE_FILE_NAME.exe` with the name of the node file you downloaded from releases(将`NODE_FILE_NAME.exe`替换为您从releases下载的node文件)
# Replace `INSERT_YOUR_ID` with a nickname you choose(将`INSERT_YOUR_ID`替换为任何一个您选择的名称)
# Copy all of the lines below, they are all part of the same command(复制下列所有代码，他们是一体的)
./NODE_FILE_NAME \
  --chain testnet \
  --wasm-execution compiled \
  --execution wasm \
  --bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" \
  --rpc-cors all \
  --rpc-methods unsafe \
  --ws-external \
  --validator \
  --telemetry-url "wss://telemetry.polkadot.io/submit/ 1" \
  --telemetry-url "wss://telemetry.subspace.network/submit 1" \
  --name INSERT_YOUR_ID
```
5. You should see something similar in the termina(您应该在终端看到和以下类似的内容)l:
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
7. We will then open another terminal, change to the downloads directory, then start the farmer node with the following command(然后我们将打开另一个终端，切换到下载目录，然后使用以下命令启动farmer节点):
```bash
# Replace `FARMER_FILE_NAME.exe` with the name of the node file you downloaded from releases(将`NODE_FILE_NAME.exe`替换为您从releases下载的farmer文件)
# Replace `WALLET_ADDRESS` below with your account address from Polkadot.js wallet(将`WALLET_ADDRESS`替换为您Polkadot.js的账户地址)

./FARMER_FILE_NAME farm --reward-address WALLET_ADDRESS
```

## 🍎 macOS指引(macOS Instructions)

1. Download the executables for your operating system from the [Releases](https://github.com/subspace/subspace/releases) tab and extract binaries from ZIP archives.
2. Open your favourite terminal, and change to the Downloads directory using `cd Downloads`
3. Make the farmer & node executable  `chmod +x farmer-name` & `chmod +X node-name`
4. We will then start the node using the following command

1. 从 [Releases](https://github.com/subspace/subspace/releases) 下载适用于您操作系统的可执行文件。
2. 打开你喜欢的终端，使用`cd Downloads`切换到Downloads目录
3. 使farmer和node可执行 `chmod +x farmer-name` & `chmod +X node-name`
4. 然后使用以下命令启动节点

> *Note, when attempting to run this command you may be prompted:* Click on `cancel` instead of moving it to trash.To allow execution, go to `System Preferences -> Security & Privacy -> General`, and click on `allow`.After this, simply repeat the step you prompted for (step 4 or 6). This time, click the `Open` button when prompted.
> *注意，尝试运行此命令时可能会弹出提示：* 单击`取消`而不是将其移至垃圾箱。要允许执行，请转到“系统偏好设置 -> 安全和隐私 -> 常规”，然后单击`允许`。在此之后，只需重复您提示的步骤（步骤 4 或 6）。这一次，在出现提示时单击“打开”按钮。

```bash
# Replace `NODE_FILE_NAME.exe` with the name of the node file you downloaded from releases(将`NODE_FILE_NAME.exe`替换为您从releases下载的node文件)
# Replace `INSERT_YOUR_ID` with a nickname you choose(将`INSERT_YOUR_ID`替换为任何一个您选择的名称)
# Copy all of the lines below, they are all part of the same command(复制下列所有代码，他们是一体的)
./NODE_FILE_NAME \
  --chain testnet \
  --wasm-execution compiled \
  --execution wasm \
  --bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" \
  --rpc-cors all \
  --rpc-methods unsafe \
  --ws-external \
  --validator \
  --telemetry-url "wss://telemetry.polkadot.io/submit/ 1" \
  --telemetry-url "wss://telemetry.subspace.network/submit 1" \
  --name INSERT_YOUR_ID
```
5. You should see something similar in the terminal(您应该在终端看到和以下类似的内容):
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
7. We will then open another terminal, change to the downloads directory, then start the farmer node with the following command(然后我们将打开另一个终端，切换到下载目录，然后使用以下命令启动farmer节点):
```bash
# Replace `FARMER_FILE_NAME.exe` with the name of the node file you downloaded from releases(将`FARMER_FILE_NAME.exe`替换为您从releases下载的farmer文件)
# Replace `WALLET_ADDRESS` below with your account address from Polkadot.js wallet(将`WALLET_ADDRESS`替换为您Polkadot.js的账户地址)

./FARMER_FILE_NAME farm --reward-address WALLET_ADDRESS
```
7. It may prompt again in here. Refer to the note on step 4(这里可能会再次提示。请参阅步骤 4 中的注释).

# 🤔注意事项(Notes)

## 检查结果及与farmnet互动(Checking results and interacting with farmnet)

Visit [Polkadot.js explorer](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Ffarm-rpc.subspace.network#/explorer), from there you can interact with the Subspace Farmnet as any Substrate-based blockchain.

访问 [Polkadot.js explorer](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Ffarm-rpc.subspace.network#/explorer)，与任何基于 Substrate 的区块链一样，您可以从那里与 Subspace Farmnet 进行交互。

## 无效方案(Invalid Solution)
If you are getting `invalid solution` errors (visible on the terminal that Node runs), please follow "Switching to a new snapshot" steps below and start afresh

如果您遇到“无效方案”错误（在 Node 运行的终端上可见），请按照下面的“切换到新快照”重新开始。

---
## 切换到新快照 (Switching to a new snapshot)
If you were running a node previously, and want to switch to a new snapshot, please perform these steps and then follow the guideline again:

如果您之前正在运行一个节点，并且想要切换到新快照，请执行这些步骤，然后再次按照指南进行操作：

```
# Replace `FARMER_FILE_NAME` with the name of the node file you downloaded from releases(将`FARMER_FILE_NAME.exe`替换为您从releases下载的farmer文件)

./FARMER_FILE_NAME wipe

# Replace `NODE_FILE_NAME` with the name of the node file you downloaded from releases(将`NODE_FILE_NAME.exe`替换为您从releases下载的node文件)

./NODE_FILE_NAME purge-chain --chain testnet

```
Does not matter if the node/farmer executable is the previous one or from the new snapshot, both will work :)
The reason we require this is, with every snapshot change, the network might get partitioned, and you may be on a different genesis than the current one.
In plain English, these commands are like a `reset` button for snapshot changes.

node/farmer可执行文件是上一个版本还是最新的快照无关紧要，两者都可以工作:) 我们需要这样做的原因是，随着每个快照更改，网络可能会被分区，并且您可能处于与当前不同的创世（区块）。 用简单的英语来说，这些命令就像一个用于快照更改的“重置”按钮。

## 帮助(Help)

There are extra commands and parameters you can use on farmer or node, use the `--help` after any other command to display additional options.

您可以在farmer或node上使用额外的命令和参数，在任何其他命令之后使用`--help`来显示其他选项。

Below are some helpful farmer commands:
以下是一些有用的farmer命令：

- `farm --reward-address WALLET_ADDRESS` : starts background plotting and farming together, farmed testnet coins will be sent to `WALLET_ADDRESS`
   `farm --reward-address WALLET_ADDRESS` : 同时开启后台绘制(区块历史)和种收(farming)，收获的测试网硬币将被发送到`WALLET_ADDRESS`
   
- `farm` : starts background plotting and farming together, rewards are sent to auto-generated wallet (see `identity` commands below)
   `farm` : 同时开启后台绘制(区块历史)和种收(farming)，奖励发送到自动生成的钱包（请参阅下面的 `identity` 命令）
   
- `wipe` : erases the plot and identity (including plot, commitment, object mappings and identity files)
   `wipe` : 擦除绘制(历史)和身份（包括绘制、承诺、对象映射和身份文件）
   
- `identity import-from-mnemonic "spell out your seed phrase here"` : imports your existing identity from your seed phrase (not recommended! use `--reward-address` instead)
- `identity import-from-mnemonic “在这里拼出你的助记词”`：从助记词导入你现有的身份（不推荐！请用`--reward-address`）

- `identity view` : displays SS58 address (this is the same as `identity view --address`) where farmed testnet coins will be sent
   `identity view` : 显示 SS58 地址（这与`identity view --address` 相同），测试网代币将被发送到该地址
   
- `identity view --mnemonic` : displays mnemonic phrase of auto-generated wallet (sensitive information, keep this private, not very useful if `--reward-address` was used)
   `identity view --mnemonic` : 显示自动生成钱包的助记词（敏感信息，请保密，如果使用了`--reward-address`则用处不大）

Examples(举例):

```bash
# Replace `FARMER_FILE_NAME.exe` with the name of the node file you downloaded from releases(将`FARMER_FILE_NAME.exe`替换为您从releases下载的farmer文件)

./FARMER_FILE_NAME farm --help
./FARMER_FILE_NAME wipe
```

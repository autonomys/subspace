
# 👨‍🌾 Getting Started Farming

>This documentation will only cover connecting to the Farmnet, though you may run an independant chain if you would like. Please refer to the [Substrate Guide](https://docs.substrate.io/) for more information on how to develop on substrate based nodes.

This is the documentation/guideline on how to run the farmer. You may also refer to the [glossary](#glossary-for-farm-commands) for 
various farm commands. 

We are regularly releasing stable snapshots. Our CI builds container images and executables for 3 major platforms (Windows, macOS, Linux).

Our snapshots are categorized as the following:
- Stable (you can always grab the latest one, these are the ones that are tested by our team)
- Pre-releases (for testing things early, there may be bugs)

You need 2 executables, select whichever applies to your operating system
* Node Executable - `subspace-node-...`
* Farmer Executable - `subspace-farmer-...`

You can find these executables in the [Releases](https://github.com/subspace/subspace/releases) section of this Repository.

> This is a ***non-incentivized*** testnet. Meaning there are no rewards in place at this time, and has absolutely no financial benefit to being run at this time.

<details><summary> 🖼️ Windows Instructions (Click to Expand)</summary>
<p>

### 📝 Windows Installation

1. Download the executables for your operating system from the [Releases](https://github.com/subspace/subspace/releases) tab.
2. open a terminal, on Windows this is `Command Prompt` or `Powershell`
3. In the terminal we will change to the Downloads directory using this command `cd Downloads`
4. We will then start the node using the following command
>(replace `INSERT_YOUR_ID` with a nickname you choose)
```
./subspace-node-x86_64-*-snapshot --chain testnet --wasm-execution compiled --execution wasm --bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" --rpc-cors all --rpc-methods unsafe --ws-external --validator --telemetry-url "wss://telemetry.polkadot.io/submit/ 1" --name INSERT_YOUR_ID
```
5. You should see something similar as the output in the terminal.
```

```
6. After running this command, Windows may ask you for permissions related to firewall, select `allow` in this case.
7. We will then open another terminal, change to the downloads directory, then start the farmer node with the following command:
```
./subspace-farmer-x86_64-*-snapshot farm
```
</p>
</details>

<details><summary> 🐧 Linux Instructions (Click to Expand)</summary>
<p>

### 📝 Linux Installation

1. Download the executables for your operating system from the [Releases](https://github.com/subspace/subspace/releases) tab.
2. Open your favourite terminal, and change to the Downloads directory using `cd Downloads`
3. Make the farmer & node executable  `chmod +x $(farmer-name)` & `chmod +X $(node-name)`
4. We will then start the node using the following command
>(replace `INSERT_YOUR_ID` with a nickname you choose)

> *Note, when attempting to run this command you may be prompted:* Click on `cancel` instead of moving it to trash.
To allow execution, go to `System Preferences -> Security & Privacy -> General`, and click on `allow`.
After this, simply repeat the step you prompted for (step 4 or 6). This time, click the `Open` button when prompted.

```
./subspace-node-x86_64-*-snapshot \
  --chain testnet \
  --wasm-execution compiled \
  --execution wasm \
  --bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" \
  --rpc-cors all \
  --rpc-methods unsafe \
  --ws-external \
  --validator \
  --telemetry-url "wss://telemetry.polkadot.io/submit/ 1" \
  --name INSERT_YOUR_ID
```
5. You should see something similar as the output in the terminal.
```

```
7. We will then open another terminal, change to the downloads directory, then start the farmer node with the following command:
```
./subspace-farmer-x86_64-*-snapshot farm
```
7. It may prompt again in here. Refer to the note on step 4.
</p>
</details>

<details><summary> 🍎 macOS Instructions (Click to Expand)</summary>
<p>

### 📝 macOS Installation

1. Download the executables for your operating system from the [Releases](https://github.com/subspace/subspace/releases) tab.
2. Open your favourite terminal, and change to the Downloads directory using `cd Downloads`
3. Make the farmer & node executable  `chmod +x $(farmer-name)` & `chmod +X $(node-name)`
4. We will then start the node using the following command
>(replace `INSERT_YOUR_ID` with a nickname you choose)

> *Note, when attempting to run this command you may be prompted:* Click on `cancel` instead of moving it to trash.
To allow execution, go to `System Preferences -> Security & Privacy -> General`, and click on `allow`.
After this, simply repeat the step you prompted for (step 4 or 6). This time, click the `Open` button when prompted.

```
./subspace-node-x86_64-*-snapshot \
  --chain testnet \
  --wasm-execution compiled \
  --execution wasm \
  --bootnodes "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr" \
  --rpc-cors all \
  --rpc-methods unsafe \
  --ws-external \
  --validator \
  --telemetry-url "wss://telemetry.polkadot.io/submit/ 1" \
  --name INSERT_YOUR_ID
```
5. You should see something similar as the output in the terminal.
```

```
7. We will then open another terminal, change to the downloads directory, then start the farmer node with the following command:
```
./subspace-farmer-x86_64-*-snapshot farm
```
7. It may prompt again in here. Refer to the note on step 4.
</p>
</details>

## 🤔Notes

### Identity Management: 
If you would like to import your polkadot.js wallet so, you can interact with the network, you may do so via
```
subspace-farmer-x86_64-*-snapshot identity import-from-mnemonic "spell out your seed phrase here"
```
then start your farmer as normal.

> You may need to wipe the farm with the `wipe` command if you ran the farmer prior to importing a mnemonic.

You may visit the [Polkadot.js](https://polkadot.js.org/apps/?rpc=wss%3A%2F%2Ffarm-rpc.subspace.network#/explorer), from here you may interact with the Subspace Farmnet as any substrate based blockchain.

### Invalid Solution: 
If you are getting `invalid solution` errors (visible on the terminal that Node runs), please perform this step and then follow the guideline again:
```
./subspace-farmer-x86_64-*-snapshot erase-plot
```
This will basically erase your plot and commitments, so that the farmer can make a fresh start.

---
### Switching to a new snapshot:
If you were running a node previously, and want to switch to a new snapshot, please perform these steps and then follow the guideline again:
```
./subspace-node-x86_64-*-snapshot purge-chain --chain testnet
./subspace-farmer-x86_64-*-snapshot erase-plot
```
Does not matter if the node/farmer executable is the previous one or from the new snapshot, both will work :)
The reason we require this is, with every snapshot change, the network might get partitioned, and you may be on a different genesis than the current one.
In plain English, these commands are like a `reset` button for snapshot changes.

### Glossary For Farm Commands

Structure -> `subspace-farmer-x86_64-*-snapshot <COMMAND>`

- `farm` : starts background plotting and farming together
- `erase-plot` : erases the plot (including plot, commitments and object mappings)
- `wipe` : erases the plot and identity (including plot, commitment, object mappings and identity files)
- `identity import-from-mnemonic "spell out your seed phrase here"` : imports your existing identity from your seed phrase
- `identity view` : displays SS58 address (this is the same as `identity view --address`)
- `identity view --public-key` : displays the hex encoded public key
- `identity view --mnemonic` : displays your mnemonic (sensitive information, keep this private)

An example command: `subspace-farmer-x86_64-*-snapshot identity view --public-key`
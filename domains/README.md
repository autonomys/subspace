# Domain operator

Reference implementation of Domain Operator for Subspace Network Blockchain.

## Overview

Domains are the decoupled execution layer of the [Subspace Network Blockchain](https://subspace.network) (referred to as the consensus chain below).

The extrinsic of the domain chain is first collected into a bundle by the domain operator, the bundle is then broadcast to the consensus chain network as an extrinsic of the consensus chain.

The domain operator listening to the block import events of the consensus chain, extracts bundles from the imported consensus block and executes the extrinsics of the bundle to build and import a domain block in a deterministically way.

NOTE: currently, the domain chain does not support to syncing from other operator nodes and need to be deterministically derived from the consensus chain block by block.

### Build from source

The domain operator node is embeded within the `subspace-node` binary, please refer to [Subspace node](../crates/subspace-node/README.md) for how to build from source.

#### Create Operator key:
Operator needs key pair to participate in Bundle production.
You can create a key using following command:
```bash
target/production/subspace-node key generate --scheme sr25519
```

Backup the key. Take `Public key (hex)` of the Keypair. The public key is part of the Operator config.

#### Insert key to Keystore:
The above generated key is added to the Keystore so that Operator node can use to participate in Bundle production.
The key is inserted using the following command:
```bash
target/production/subspace-node key insert \
      --suri "<Secret phrase>" --key-type oper --scheme sr25519 --keystore-path /tmp/keystore
```
The above command assumes `/tmp/keystore` as the keystore location.
`suri` is the secret phrase of the Operator key.

#### Register Operator:
Operator needs to register to a domain they want to operate on using `register_operator`. Registration extrinsic requires Operator Config.
Once the domain epoch is finished, Operator can produce bundles from the new epoch.

### Start the domain operator node

The domain operator node is running with an embededded consensus node, thus you need to specify the args for both the consensus node and the domain operator node:

```bash
subspace-node [consensus-chain-args] -- [domain-args]
```

Example:
Start a node as Operator on `local` chain:
```bash
target/production/subspace-node \
    --chain local \
    --rpc-external \
    --node-key 0000000000000000000000000000000000000000000000000000000000000001 \
    -- \
    -- --domain-id 0 \
    --chain local \
    --operator \
    --keystore-path /tmp/keystore \
    --rpc-external
```

For `dev` chain, you can use `--dev` flag that combines `--chain dev` and `--operator`.
```bash
target/production/subspace-node \
    --dev \
    --rpc-external \
    --node-key 0000000000000000000000000000000000000000000000000000000000000001 \
    -- \
    -- --domain-id 0 \
    --dev \
    --rpc-external
```

Run another node and sync the consensus chain from the consensus node started earlier:
```bash
target/production/subspace-node \
    --dev \
    --rpc-external \
    --bootnodes /ip4/127.0.0.1/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp \
    -- \
    --domain-id 0 \
    --chain dev \
    --rpc-external
```
Since there is no `operator` flag, this node will not participate in Bundle production.

By default, node data is written to `subspace-node/domain-{domain-id}` subdirectory of the OS-specific user's local data directory.
```
Linux
$XDG_DATA_HOME or                   /home/alice/.local/share
$HOME/.local/share 

macOS
$HOME/Library/Application Support   /Users/Alice/Library/Application Support

Windows
{FOLDERID_LocalAppData}             C:\Users\Alice\AppData\Local
```

### Embedded Docs

Once the project has been built, the following command can be used to explore all parameters and subcommands:

```bash
target/production/subspace-node --help
```

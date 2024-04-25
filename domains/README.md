# Domain operator

Reference implementation of Domain Operator for Subspace Network Blockchain.

## Overview

Domains are the decoupled execution layer of the [Subspace Network Blockchain](https://subspace.network) (referred to as the consensus chain below).

The extrinsic of the domain chain is first collected into a bundle by the domain operator, the bundle is then broadcast to the consensus chain network as an extrinsic of the consensus chain.

The domain operator, which listens to the block import events of the consensus chain, extracts bundles from the imported consensus block and executes the extrinsics of the bundle to build and import a domain block in a deterministic manner.

NOTE: Currently, the domain chain does not support syncing from other operator nodes. It must be deterministically derived from the consensus chain block by block.

#### Create Operator key:

Operator needs key pair to participate in Bundle production.
You can create a key using following command:
```bash
target/production/subspace-node domain key create --base-path {subspace-node-base-path} --domain-id {domain-id}
```

Ensure to replace `{subspace-node-base-path}` and `{domain-id}` with the path to your node, and the domain ID value you want to become an operator on.

Backup the key. Take `Public key (hex)` of the keypair. The public key is part of the Operator config.

The key is automatically added to the keystore located under `/{subspace-node-base-path}/domains/{domain-id}`. 

#### Insert key to Keystore:
If you decided to switch domains or already have the secret phrase available, you might prefer to use `domain key insert` command.

The key is inserted using the following command:
```bash
target/production/subspace-node domain key insert \
--base-path {subspace-node-base-path} --domain-id {domain-id} --keystore-suri {secret-phrase}
```

The above command assumes `{subspace-node-base-path}` as the location of node data. `{domain-id}` is a domain for which to insert the key and `{secret-phrase}` is the secret phrase to use for keypair derivation.

#### Register Operator:

Operator needs to register to a domain they want to operate on using `register_operator`. Registration extrinsic requires Operator Config.
Once the domain epoch is finished, Operator can produce bundles from the new epoch.

### Start the domain operator node

The domain operator node runs with an embedded consensus node, thus you need to specify the args for both the consensus node and the domain operator node:

```bash
subspace-node [consensus-chain-args] -- [domain-args]
```

Example:
Start a node as Operator on `dev` chain:
```bash
target/production/subspace-node run \
    --dev \
    --node-key 0000000000000000000000000000000000000000000000000000000000000001 \
    -- --
```

`-- --` is such that domain `0` operator with ID `0` is started, with just `--` node will see no domain arguments and domain will not start.

For development purposes chain, you can use `--keystore-suri` option to inject keypair into keystore from a seed.
```bash
target/production/subspace-node run \
    --dev \
    --node-key 0000000000000000000000000000000000000000000000000000000000000001 \
    -- \
    --domain-id 0 \
    --operator-id 0 \
    --keystore-suri "//Alice" \
    --rpc-external
```

Run another node and sync the consensus chain from the consensus node started earlier:
```bash
target/production/subspace-node run \
    --dev \
    --bootnodes /ip4/127.0.0.1/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp \
    -- \
    --domain-id 0 \
    --rpc-external
```
Since there is no `operator` flag, this node will not participate in Bundle production.

By default, node data is written to `{subspace-node-base-path}/domains/{domain-id}` subdirectory.

### Embedded Docs

Once the project has been built, the following command can be used to explore all parameters and subcommands:

```bash
target/production/subspace-node run --dev -- --help
```

### Build from source

The domain operator node is embedded within the `subspace-node` binary, please refer to [Subspace node](../crates/subspace-node/README.md) for building it from source.

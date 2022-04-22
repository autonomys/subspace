# Subspace Node

Reference Node implementation for Subspace Network Blockchain using [Substrate](https://docs.substrate.io/) framework.

## Getting Started

Follow these steps to get started with the Subspace Node :hammer_and_wrench:

## Running

It is recommended to follow general farming instructions that explain how to run both farmer and node together.

## Build from source

Rust toolchain is expected to be installed for anything in this repository to compile, but there are some extra dependencies for farmer specifically.

RocksDB on Linux needs LLVM/Clang:
```bash
sudo apt-get install llvm clang
```

Then build the farmer using Cargo:
```
cargo build --profile production subspace-node
target/production/subspace-node --version
```

#### Start the node

Start a single node development chain:
```bash
target/production/subspace-node \
    --dev \
    --ws-external \
    --node-key 0000000000000000000000000000000000000000000000000000000000000001
```

#### Start full node

You can now run another full node and sync the chain from the node started earlier:
```bash
target/production/subspace-node \
    --dev \
    --ws-external \
    --bootnodes /ip4/127.0.0.1/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp
```

### Embedded Docs

Once the project has been built, the following command can be used to explore all parameters and subcommands:

```bash
target/production/subspace-node --help
```

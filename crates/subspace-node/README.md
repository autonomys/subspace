# Subspace Node

Reference Node implementation for Subspace Network Blockchain using [Substrate](https://docs.substrate.io/) framework.

## Getting Started

Follow these steps to get started with the Subspace Node :hammer_and_wrench:

## Running

It is recommended to follow general farming instructions that explain how to run both farmer and node together.

## Build from source

Rust toolchain is expected to be installed for anything in this repository to compile, but there are some extra dependencies for farmer specifically.

Prost library from libp2p dependency needs CMake:
```bash
sudo apt-get install cmake
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

By default, node data are written to `subspace-node` subdirectory of the OS-specific users local data directory.

```
Linux
$XDG_DATA_HOME or                   /home/alice/.local/share
$HOME/.local/share 

macOS
$HOME/Library/Application Support   /Users/Alice/Library/Application Support

Windows
{FOLDERID_LocalAppData}             C:\Users\Alice\AppData\Local
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

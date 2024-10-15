# Subspace Node

Reference Node implementation for Subspace Network Blockchain using [Substrate](https://docs.substrate.io/) framework.

## Getting Started

Follow these steps to get started with the Subspace Node :hammer_and_wrench:

## Running

We recommend following the general farming instructions that explain how to run both the farmer and node together.

## Build from source

A Rust toolchain is required to compile this repository, but there are some extra dependencies for the node.

`protoc` is required for `libp2p`.

### Ubuntu

LLVM/Clang and `make` are necessary:
```bash
sudo apt-get install llvm clang cmake make protobuf-compiler
```

### macOS

1. Install via Homebrew:

```bash
brew install llvm cmake make protobuf
```

2. Add `llvm` to your `~/.zshrc` or `~/.bashrc`:

```bash
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
```

3. Activate the changes:

```bash
source ~/.zshrc
```

4. Verify that `llvm` is installed:

```bash
llvm-config --version
```

### Build

Then build the node using Cargo:
```
cargo build --profile production --bin subspace-node
target/production/subspace-node --version
```

#### Start the node

Start a single node development chain:
```bash
target/production/subspace-node run \
    --dev \
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
target/production/subspace-node run \
    --dev \
    --bootnodes /ip4/127.0.0.1/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp
```

### Embedded Docs

Once the project has been built, the following command can be used to explore all parameters and subcommands:

```bash
target/production/subspace-node --help
```

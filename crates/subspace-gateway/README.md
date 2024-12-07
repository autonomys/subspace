# Subspace Gateway

Data Gateway implementation for the Subspace Network Blockchain.

## Getting Started

Follow these steps to get started with the Subspace Gateway :hammer_and_wrench:

## Running

It is recommended to follow general farming instructions that explain how to run both farmer and node together.

## Build from source

A Rust toolchain is required to compile this repository, but there are some extra dependencies for the gateway.

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

Then build the gateway using Cargo:
```
cargo build --profile production --bin subspace-gateway
target/production/subspace-gateway --version
```

#### Start the gateway

Start a gateway connected to a single node development chain:
```bash
target/production/subspace-gateway rpc \
    --dev
```

### Embedded Docs

Once the project has been built, the following command can be used to explore all parameters and subcommands:

```bash
target/production/subspace-gateway --help
```

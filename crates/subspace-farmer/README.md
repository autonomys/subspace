# Subspace Farmer

Reference implementation of Subspace Farmer for Subspace Network Blockchain.

## Running

We recommend following the general farming instructions that explain how to run both the farmer and node together.

## Build from source

A Rust toolchain is required to compile this repository, but there are some extra dependencies for the farmer.

`protoc` is required for `libp2p`.
`automake`,`libtool` and `pkg-config` on Linux/macOS or CMake on Windows for `hwlocality-sys` (if `numa` features is
enabled, it is by default), also LLVM/Clang is necessary.

### Ubuntu

```bash
sudo apt-get install automake libtool pkg-config llvm clang protobuf-compiler
```

### macOS

1. Install via Homebrew:

```bash
brew install automake libtool llvm protobuf
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

Then build the farmer using Cargo:
```
cargo build --profile production --bin subspace-farmer
target/production/subspace-farmer --version
```

## Usage

Commands here assume you installed native binary, but you can also easily adapt them to using with Docker.

Use `--help` to find out all available commands and their options:
```
target/production/subspace-farmer --help
```

### Start the farmer
```
target/production/subspace-farmer farm \
    --reward-address st... \
    path=/path/to/farm,size=100G
```

`st...` should be replaced with the reward address taken from [Polkadot.js wallet](https://polkadot.js.org/extension/) (or similar), `/path/to/farm` with location where you want to store plot and `100G` replaced with desired plot size.

This will connect to local node and will try to solve on every slot notification, while also plotting all existing and new history of the blockchain in parallel.

*NOTE: You need to have a `subspace-node` running before starting farmer, otherwise it will not be able to start*

### Benchmark auditing
```
target/production/subspace-farmer benchmark audit /path/to/farm
```

### Show information about the farm
```
target/production/subspace-farmer info /path/to/farm
```

### Scrub the farm to find and fix farm corruption
```
target/production/subspace-farmer scrub /path/to/farm
```

### Wipe the farm
```
target/production/subspace-farmer wipe /path/to/farm
```

This would wipe plots in the OS-specific users local data directory.

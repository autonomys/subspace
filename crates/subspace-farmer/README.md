# Subspace Farmer

Reference implementation of Subspace Farmer for Subspace Network Blockchain.

## Running

It is recommended to follow general farming instructions that explain how to run both farmer and node together.

## Build from source

Rust toolchain is expected to be installed for anything in this repository to compile, but there are some extra dependencies for farmer specifically.

Prost library from libp2p dependency needs CMake, also LLVM/Clang is necessary:
```bash
sudo apt-get install llvm clang cmake
```

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
target/production/subspace-farmer farm --reward-address st... path=/path/to/farm,size=100G
```

`st...` should be replaced with the reward address taken from Polkadot.js wallet (or similar), `/path/to/farm` with location where you want to store plot and `100G` replaced with desired plot size.

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

# Subspace Network Monorepo

[![Rust](https://github.com/subspace/subspace/actions/workflows/rust.yaml/badge.svg)](https://github.com/subspace/subspace/actions/workflows/rust.yaml)
[![TypeScript](https://github.com/subspace/subspace/actions/workflows/typescript.yaml/badge.svg)](https://github.com/subspace/subspace/actions/workflows/typescript.yaml)

This is a mono repository for [Subspace Network](https://www.subspace.network/) implementation, primarily containing
Subspace node/client using Substrate framework and farmer app implementations.

The implementation is currently being upgraded to Subspace, in the meantime you'll find multiple references to Spartan
Proof-of-Capacity (PoC) consensus, which is a simplified version of Subspace using proof of useless storage that was
implemented as part of [Web 3 Foundation Open Grant](https://github.com/w3f/Open-Grants-Program/blob/master/applications/spartan_poc_consensus_module.md).

### Repository structure

The structure of this repository is the following:

- `crates` contains Subspace-specific Rust crates used to build node and farmer, most are following Substrate naming conventions
- `substrate` contains modified copies of Substrate's crates that we use for testing
- `node-template-spartan` is the current implementation of the node for Spartan protocol (will be upgraded to Subspace soon)

### How to run

This is a monorepo with multiple binaries and the workflow is typical for Rust projects:

- `cargo run --bin node-template-spartan -- --dev --tmp` to run [a node](node-template-spartan)
- `cargo run --release --bin spartan-farmer -- plot 256000 spartan` to [create a 1 GiB plot](crates/spartan-farmer#create-a-new-plot)
- `cargo run --release --bin spartan-farmer -- farm` to [start farming](crates/spartan-farmer#start-the-farmer)

NOTE: You need to have `nightly` version of Rust toolchain with `wasm32-unknown-unknown` target available or else you'll get a compilation error.

You can find readme files in corresponding crates for requirements, multi-node setup and other details.

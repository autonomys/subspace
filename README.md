# Subspace Network Monorepo

[![Rust](https://github.com/subspace/subspace/actions/workflows/rust.yaml/badge.svg)](https://github.com/subspace/subspace/actions/workflows/rust.yaml)
[![TypeScript](https://github.com/subspace/subspace/actions/workflows/typescript.yaml/badge.svg)](https://github.com/subspace/subspace/actions/workflows/typescript.yaml)

This is a mono repository for [Subspace Network](https://www.subspace.network/) implementation, primarily containing
Subspace node/client using Substrate framework and farmer app implementations.

### Repository structure

The structure of this repository is the following:

- `crates` contains Subspace-specific Rust crates used to build node and farmer, most are following Substrate naming conventions
- `substrate` contains modified copies of Substrate's crates that we use for testing
- `node-template-subspace` is the current implementation of the node for Subspace protocol

### How to run

This is a monorepo with multiple binaries and the workflow is typical for Rust projects:

- `cargo run --bin node-template-subspace -- --dev --tmp` to run [a node](node-template-subspace)
- `cargo run --release --bin subspace-farmer -- farm` to [start farming](crates/subspace-farmer#start-the-farmer)

NOTE: You need to have `nightly` version of Rust toolchain with `wasm32-unknown-unknown` target available or else you'll get a compilation error.

You can find readme files in corresponding crates for requirements, multi-node setup and other details.

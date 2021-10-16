# Subspace Network Monorepo

[![Rust](https://github.com/subspace/subspace/actions/workflows/rust.yaml/badge.svg)](https://github.com/subspace/subspace/actions/workflows/rust.yaml)

This is a mono repository for [Subspace Network](https://www.subspace.network/) implementation, primarily containing
Subspace node/client using Substrate framework and farmer app implementations.

### Repository structure

The structure of this repository is the following:

- `crates` contains Subspace-specific Rust crates used to build node and farmer, most are following Substrate naming conventions
  - `subspace-node` is an implementation of the node for Subspace protocol
  - `subspace-farmer` is a CLI farmer app
- `substrate` contains modified copies of Substrate's crates that we use for testing

### How to run

This is a monorepo with multiple binaries and the workflow is typical for Rust projects:

- `cargo run --release --bin subspace-node -- --dev --tmp` to run [a node](crates/subspace-node)
- `cargo run --release --bin subspace-farmer -- farm` to [start farming](crates/subspace-farmer#start-the-farmer)

NOTE: You need to have `nightly` version of Rust toolchain with `wasm32-unknown-unknown` target available or else you'll get a compilation error.

You can find readme files in corresponding crates for requirements, multi-node setup and other details.

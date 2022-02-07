# Subspace Network Monorepo

[![Rust](https://github.com/subspace/subspace/actions/workflows/rust.yaml/badge.svg)](https://github.com/subspace/subspace/actions/workflows/rust.yaml)
[![rustdoc](https://github.com/subspace/subspace/actions/workflows/rustdoc.yml/badge.svg)](https://subspace.github.io/subspace)

This is a mono repository for [Subspace Network](https://www.subspace.network/) implementation, primarily containing
Subspace node/client using Substrate framework and farmer app implementations.

## Repository structure

The structure of this repository is the following:

- `crates` contains Subspace-specific Rust crates used to build node and farmer, most are following Substrate naming conventions
  - `subspace-node` is an implementation of the node for Subspace protocol
  - `subspace-farmer` is a CLI farmer app
- `cumulus` contains modified copies of Cumulus crates that we use right now
- `polkadot` contains modified copies of Polkadot crates that we use right now
- `substrate` contains modified copies of Substrate's crates that we use for testing

## How to run

Please refer to [farming.md](/docs/farming.md) on how to run farmer. 

If you are looking to build from the source refer to [development.md](/docs/development.md).

# Subspace Network Monorepo

[![Latest Release](https://img.shields.io/github/v/release/autonomys/subspace?display_name=tag&style=flat-square)](https://github.com/autonomys/subspace/releases)
[![Downloads Latest](https://img.shields.io/github/downloads/autonomys/subspace/latest/total?style=flat-square)](https://github.com/autonomys/subspace/releases/latest)
[![Rust](https://img.shields.io/github/actions/workflow/status/autonomys/subspace/rust.yml?branch=main)](https://github.com/autonomys/subspace/actions/workflows/rust.yaml)
[![Rust Docs](https://img.shields.io/github/actions/workflow/status/autonomys/subspace/rustdoc.yml?branch=main)](https://autonomys.github.io/subspace)

This is a mono repository for [Subspace Network](https://subspace.network/) implementation, primarily containing
Subspace node/client using Substrate framework and farmer app implementations.

## Repository structure

The structure of this repository is the following:

- `crates` contains Subspace-specific Rust crates used to build node and farmer, most are following Substrate naming conventions
  - `subspace-node` is an implementation of the node for Subspace protocol
  - `subspace-farmer` is a CLI farmer app
- `domains` contains client and runtime code for decoupled execution and domains

## How to run

Please refer to [farming.md](/docs/farming.md) on how to run farmer. 

If you are looking to farm offline, or build from source for development purposes please refer to [development.md](/docs/development.md).

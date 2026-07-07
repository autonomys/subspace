#!/usr/bin/env bash

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

echo "Current directory: $(pwd)"
if [[ ! -d "./crates/pallet-domains" ]] || [[ ! -d "./domains/runtime/evm" ]]; then
  echo "Changing to the root of the repository:"
  cd "$(dirname "$0")/.."
  echo "Current directory: $(pwd)"
  if [[ ! -d "./crates/pallet-domains" ]] || [[ ! -d "./domains/runtime/evm" ]]; then
    echo "Missing ./crates/pallet-domains or ./domains/runtime/evm directories"
    echo "This script must be run from the base of an autonomys/subspace repository checkout"
    exit 1
  fi
fi

# This feature list is `--all-features`. wgpu (GPU plotting) is a default feature and builds on all
# platforms, so it is part of the base list rather than a separate per-vendor check.
BASE_FEATURES="async-trait,binary,cluster,default-library,domain-block-builder,domain-block-preprocessor,frame-benchmarking-cli,frame-system-benchmarking,hex-literal,kzg,numa,pallet-subspace,pallet-timestamp,pallet-utility,parallel,parking_lot,rand,runtime-benchmarks,sc-client-api,sc-executor,schnorrkel,serde,sp-blockchain,sp-core,sp-io,sp-state-machine,sp-std,sp-storage,static_assertions,std,substrate-wasm-builder,testing,wasm-builder,wgpu,with-tracing,x509-parser,fuzz"

# Show commands before executing them
set -x

cargo -Zgitoxide -Zgit udeps --workspace --all-targets --locked --features "$BASE_FEATURES"

# Stop showing executed commands
set +x

echo
echo "============================================"
echo "Successfully checked for unused dependencies"
echo "============================================"
echo

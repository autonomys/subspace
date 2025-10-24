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

# This feature list is `--all-features` except `rocm`, which is incompatible with `cuda`
# When cargo supports excluding features (or mutually exclusive features), we can use
# `--all-features --exclude-feature rocm`
# <https://github.com/rust-lang/cargo/issues/11467>
# <https://internals.rust-lang.org/t/pre-rfc-mutually-excusive-global-features/19618>
BASE_FEATURES="async-trait,binary,cluster,default-library,domain-block-builder,domain-block-preprocessor,frame-benchmarking-cli,frame-system-benchmarking,hex-literal,kzg,numa,pallet-subspace,pallet-timestamp,pallet-utility,parallel,parking_lot,rand,runtime-benchmarks,sc-client-api,sc-executor,schnorrkel,serde,sp-blockchain,sp-core,sp-io,sp-state-machine,sp-std,sp-storage,static_assertions,std,subspace-proof-of-space-gpu,substrate-wasm-builder,testing,wasm-builder,with-tracing,x509-parser,fuzz"
if [[ "$(uname)" == "Darwin" ]]; then
  echo "Skipping GPU features because we're on macOS"
  EXTRA_FEATURES=("")
else
  # We skip non-GPU builds on Linux and Windows, because they have unused GPU deps
  EXTRA_FEATURES=("cuda,sppark,_gpu" "rocm,sppark,_gpu")
fi

# Show commands before executing them
set -x

for EXTRA_FEATURE in "${EXTRA_FEATURES[@]}"; do
  echo "Checking for unused dependencies with '$EXTRA_FEATURE' extra features..."
  cargo -Zgitoxide -Zgit udeps --workspace --all-targets --locked --features "$BASE_FEATURES,$EXTRA_FEATURE"
done

# Stop showing executed commands
set +x

echo
echo "============================================"
echo "Successfully checked for unused dependencies"
if [[ "$(uname)" == "Darwin" ]]; then
  echo "GPU features were not checked, because we're on macOS"
fi
echo "============================================"
echo

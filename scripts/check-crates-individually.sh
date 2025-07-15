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

# Show commands before executing them
set -x

# Pruning the target directory is only required if we're using a build cache or running locally
for crate in $(find . -name Cargo.toml -o -path ./target -prune | xargs -n 1 dirname | grep -v '^[.]$' | sort); do
  echo "Checking '$crate' will compile individually:"
  pushd "$crate"
  if ! cargo -Zgitoxide -Zgit clippy --locked --all-targets -- -D warnings; then
    echo "Crate '$crate' failed to compile individually"
    popd
    exit 1
  fi
  echo "Crate '$crate' successfully compiled individually"
  popd
done

# Stop showing executed commands
set +x

echo
echo "============================================="
echo "Successfully compiled all crates individually"
echo "============================================="
echo

#!/usr/bin/env bash

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

if [[ "$#" -ne 3 ]] || ([[ "$1" != "client" ]] && [[ "$1" != "consensus" ]] && [[ "$1" != "evm" ]] && [[ "$1" != "auto-id" ]]); then
  echo "Usage: $0 client|consensus|evm|auto-id <old-version> <new-version>"
  exit 1
fi

MODE="$1"
OLD_VERSION="$2"
NEW_VERSION="$3"

# Users can set their own SED_IN_PLACE, for example, if their GNU sed is `gsed`
if [[ -z "${SED_IN_PLACE[@]+"${SED_IN_PLACE[@]}"}" ]]; then
  if [[ "$(uname)" == "Darwin" ]]; then
    # BSD sed requires a space between -i and the backup extension
    SED_IN_PLACE=(sed -i "")
  else
    # Assume everything else has GNU sed, where the backup extension is optional
    SED_IN_PLACE=(sed --in-place)
  fi
fi

echo "Current directory: $(pwd)"
if [[ ! -d "./crates/subspace-node" ]] || [[ ! -d "./crates/subspace-runtime" ]] || [[ ! -d "./domains/runtime/evm" ]] || [[ ! -d "./domains/runtime/auto-id" ]]; then
  echo "Changing to the root of the repository:"
  cd "$(dirname "$0")/.."
  echo "Current directory: $(pwd)"
  if [[ ! -d "./crates/subspace-node" ]] || [[ ! -d "./crates/subspace-runtime" ]] || [[ ! -d "./domains/runtime/evm" ]] || [[ ! -d "./domains/runtime/auto-id" ]]; then
    echo "Missing ./crates/subspace-node, ./crates/subspace-runtime, ./domains/runtime/evm or ./domains/runtime/auto-id"
    echo "This script must be run from the base of an autonomys/subspace repository checkout"
    exit 1
  fi
fi

# show executed commands
set -x

echo "Replacing old '$MODE' version '$OLD_VERSION' with new version '$NEW_VERSION' in crates:"
if [[ "$MODE" == "client" ]]; then
  "${SED_IN_PLACE[@]}" -e "s/$OLD_VERSION/$NEW_VERSION/g" \
    ./crates/subspace-node/Cargo.toml \
    ./crates/subspace-gateway/Cargo.toml \
    ./crates/subspace-farmer/Cargo.toml \
    ./crates/subspace-bootstrap-node/Cargo.toml \
      || (echo "'$SED_IN_PLACE' failed, please set \$SED_IN_PLACE to a valid sed in-place replacement command" && exit 1)
elif [[ "$MODE" == "consensus" ]]; then
  "${SED_IN_PLACE[@]}" -e "s/spec_version: $OLD_VERSION,/spec_version: $NEW_VERSION,/g" \
    ./crates/subspace-runtime/src/lib.rs \
      || (echo "'$SED_IN_PLACE' failed, please set \$SED_IN_PLACE to a valid sed in-place replacement command" && exit 1)
elif [[ "$MODE" == "evm" ]]; then
  "${SED_IN_PLACE[@]}" -e "s/spec_version: $OLD_VERSION,/spec_version: $NEW_VERSION,/g" \
    ./domains/runtime/evm/src/lib.rs \
      || (echo "'$SED_IN_PLACE' failed, please set \$SED_IN_PLACE to a valid sed in-place replacement command" && exit 1)
elif [[ "$MODE" == "auto-id" ]]; then
  "${SED_IN_PLACE[@]}" -e "s/spec_version: $OLD_VERSION,/spec_version: $NEW_VERSION,/g" \
    ./domains/runtime/auto-id/src/lib.rs \
      || (echo "'$SED_IN_PLACE' failed, please set \$SED_IN_PLACE to a valid sed in-place replacement command" && exit 1)
fi

echo "Updating Cargo.lock..."
cargo check --profile release

if [[ "$MODE" == "client" ]]; then
  echo "Making sure the old version is not used anywhere else:"
  if ! grep --recursive --exclude-dir=target --exclude-dir=.git --exclude=Cargo.lock --exclude=Cargo.toml --fixed-strings "$OLD_VERSION" .; then
    # It worked, fall through to the success message
    echo "All old versions replaced"
  else
    # Stop showing executed commands
    set +x
    echo
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "Error: The old version ($OLD_VERSION) is still in use."
    echo "Please update this script ($0) to automatically replace it."
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo
    exit 1
  fi
fi

# Stop showing executed commands
set +x

echo
echo "======================================"
echo "Success: old '$MODE' versions replaced"
echo "======================================"
echo

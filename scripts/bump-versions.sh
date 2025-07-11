#!/usr/bin/env bash

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
    echo "Usage: $0 <old-version> <new-version>"
    exit 1
fi

OLD_VERSION="$1"
NEW_VERSION="$2"

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
if [[ ! -d "./crates/subspace-node" ]] || [[ ! -d "./crates/subspace-gateway" ]] || [[ ! -d "./crates/subspace-farmer" ]] || [[ ! -d "./crates/subspace-bootstrap-node" ]]; then
  echo "Changing to the root of the repository:"
  cd "$(dirname "$0")/.."
  echo "Current directory: $(pwd)"
  if [[ ! -d "./crates/subspace-node" ]] || [[ ! -d "./crates/subspace-gateway" ]] || [[ ! -d "./crates/subspace-farmer" ]] || [[ ! -d "./crates/subspace-bootstrap-node" ]]; then
    echo "Missing ./crates/subspace-node, ./crates/subspace-gateway, ./crates/subspace-farmer or ./crates/subspace-bootstrap-node"
    echo "This script must be run from the base of an autonomys/subspace repository checkout"
    exit 1
  fi
fi

# show executed commands
set -x

echo "Replacing the old version ($OLD_VERSION) with the new version ($NEW_VERSION) in binary crates:"
"${SED_IN_PLACE[@]}" -e "s/$OLD_VERSION/$NEW_VERSION/g" \
    ./crates/subspace-node/Cargo.toml \
    ./crates/subspace-gateway/Cargo.toml \
    ./crates/subspace-farmer/Cargo.toml \
    ./crates/subspace-bootstrap-node/Cargo.toml || (echo "'$SED_IN_PLACE' failed, please set \$SED_IN_PLACE to a valid sed in-place replacement command" && exit 1)

echo "Updating Cargo.lock..."
cargo check

echo "Making sure the old version is not used anywhere else:"
if ! grep --recursive --exclude-dir=target --exclude-dir=.git --exclude=Cargo.lock --exclude=Cargo.toml --fixed-strings "$OLD_VERSION" .; then
    # Stop showing executed commands
    set +x
    echo
    echo "==================================="
    echo "Success: all old versions replaced."
    echo "==================================="
    echo
else
    echo
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "Error: The old version ($OLD_VERSION) is still in use."
    echo "Please update this script ($0) to automatically replace it."
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo
    exit 1
fi

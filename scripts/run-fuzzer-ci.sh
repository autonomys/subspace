#!/usr/bin/env bash

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

sudo apt install -y protobuf-compiler binutils-dev

cd ./fuzz/staking && cargo ziggy build --no-honggfuzz
timeout 5m cargo ziggy fuzz

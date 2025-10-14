#!/usr/bin/env bash

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

sudo apt install -y protobuf-compiler binutils-dev

cd ./fuzz/staking && cargo ziggy build --no-honggfuzz
# cargo ziggy fuzz doesn't allow us to set a number of runs or a run time limit
timeout --preserve-status 5m cargo ziggy fuzz --release

#!/usr/bin/env bash
sudo apt install -y protobuf-compiler binutils-dev
cd ./fuzz/staking && cargo ziggy build --no-honggfuzz
AFL_SKIP_CPUFREQ=1 timeout 1m cargo ziggy fuzz

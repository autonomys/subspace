#!/usr/bin/env bash
sudo apt install -y protobuf-compiler binutils-dev
cd ./fuzz/staking && cargo ziggy build --no-honggfuzz

#!/usr/bin/env bash

local_peer_id() {
    curl --silent --location --request POST '127.0.0.1:9933' \
    --header 'Content-Type: application/json' \
    --data-raw '{
            "id":1,
            "jsonrpc":"2.0",
            "method":"system_localPeerId",
            "params":[]
    }'
}

subspace_bin=./target/release/subspace-node

echo 'Building raw chain spec...'
$subspace_bin build-spec --chain=dev --raw --disable-default-bootnode > subspace_dev.json

local_peer_id=$(local_peer_id | python3 -c "import sys, json; print(json.load(sys.stdin)['result'])")

echo
echo 'Starting Subspace Executor...'
rm -rf executor-db && ./target/release/parachain-collator \
--alice \
--collator \
--force-authoring \
--base-path executor-db \
--port 40333 \
--log=sync=trace,parachain=trace,cirrus=trace,txpool=trace,validate_transaction=trace \
--rpc-port 8845 \
--ws-port 8846 \
-- \
--execution wasm \
--log=trace \
--chain subspace_dev.json \
--port 30343 \
--unsafe-rpc-external \
--unsafe-ws-external \
--bootnodes "/ip4/127.0.0.1/tcp/30333/p2p/$local_peer_id" \
--ws-port 9977
# > c.log 2>&1

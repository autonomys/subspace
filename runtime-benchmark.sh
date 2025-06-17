#!/usr/bin/env bash

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

PROFILE="production"
FEATURES="runtime-benchmarks"
BENCH_SETTINGS="--extrinsic=* --wasm-execution=compiled --genesis-builder=none --steps=50 --repeat=20 --heap-pages=4096"

cargo build --profile "$PROFILE" --bin subspace-node --features "$FEATURES"

cargo build --profile "$PROFILE" --package subspace-runtime --features "$FEATURES"
SUBSPACE_RUNTIME_PALLETS=(
    "frame_system"
    "pallet_balances"
    "pallet_domains"
    "pallet_rewards"
    "pallet_runtime_configs"
    "pallet_subspace"
    "pallet_timestamp"
    "pallet_messenger"
    "pallet_transporter"
    "pallet_subspace_extension"
    "pallet_messenger_from_domains_extension"
    "pallet_transaction_payment"
    "pallet_utility"
    "pallet_sudo"
    "pallet_collective"
    "pallet_preimage"
    "pallet_scheduler"
    "pallet_multisig"
    # TODO: `pallet_democracy` benchmark are broken, need investigation
    # "pallet_democracy"
)
for PALLET in "${SUBSPACE_RUNTIME_PALLETS[@]}"; do
  CMD="./target/release/subspace-node benchmark pallet \
    --runtime=./target/release/wbuild/subspace-runtime/subspace_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./crates/subspace-runtime/src/weights/$PALLET.rs"
  echo "$CMD"
  $CMD
done

cargo build --profile "$PROFILE" --package evm-domain-runtime --features "$FEATURES"
EVM_DOMAIN_RUNTIME_PALLETS=(
    "frame_system"
    "domain_pallet_executive"
    "pallet_messenger"
    "pallet_messenger_from_consensus_extension"
    "pallet_messenger_between_domains_extension"
    "pallet_timestamp"
    "pallet_utility"
    "pallet_balances"
    "pallet_transporter"
    "pallet_evm"
    "pallet_transaction_payment"
)
for PALLET in "${EVM_DOMAIN_RUNTIME_PALLETS[@]}"; do
  CMD="./target/release/subspace-node domain benchmark pallet \
    --runtime=./target/release/wbuild/evm-domain-runtime/evm_domain_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./domains/runtime/evm/src/weights/$PALLET.rs"
  echo "$CMD"
  $CMD
done

cargo build --profile "$PROFILE" --package auto-id-domain-runtime --features "$FEATURES"
AUTO_ID_DOMAIN_RUNTIME_PALLETS=(
    "frame_system"
    "domain_pallet_executive"
    "pallet_messenger"
    "pallet_messenger_from_consensus_extension"
    "pallet_messenger_between_domains_extension"
    "pallet_auto_id"
    "pallet_timestamp"
    "pallet_utility"
    "pallet_balances"
    "pallet_transporter"
    "pallet_transaction_payment"
)
for PALLET in "${AUTO_ID_DOMAIN_RUNTIME_PALLETS[@]}"; do
  CMD="./target/release/subspace-node domain benchmark pallet \
    --runtime=./target/release/wbuild/auto-id-domain-runtime/auto_id_domain_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./domains/runtime/auto-id/src/weights/$PALLET.rs"
  echo "$CMD"
  $CMD
done

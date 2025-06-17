#!/usr/bin/env bash

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

PROFILE="production"
FEATURES="runtime-benchmarks"
BENCH_SETTINGS="--extrinsic=* --wasm-execution=compiled --genesis-builder=none --steps=50 --repeat=20 --heap-pages=4096"
# If you're sure the node and runtime binaries are up to date, set this to true to save rebuild and
# linking time
SKIP_BUILDS="false"

if [[ ! -d "./crates/subspace-runtime/src/weights" ]] || [[ ! -d "./domains/runtime/evm/src/weights" ]] || [[ ! -d "./domains/runtime/auto-id/src/weights" ]]; then
  echo "Missing ./crates/subspace-runtime/src/weights, ./domains/runtime/evm/src/weights or ./domains/runtime/auto-id/src/weights directories"
  echo "This script must be run from the base of an autonomys/subspace repository checkout"
  exit 1
fi

if [[ "$SKIP_BUILDS" != 'true' ]]; then
    # The node builds all the runtimes, and generating weights will rebuild some runtimes, even though
    # those weights are not used in the benchmarks. So it is faster to build everything upfront.
    echo "Building subspace-node and runtimes with profile: '$PROFILE' and features: '$FEATURES'..."
    # Show commands before executing them
    set -x
    cargo build --profile "$PROFILE" --bin subspace-node --features "$FEATURES"
    cargo build --profile "$PROFILE" --package subspace-runtime --features "$FEATURES"
    cargo build --profile "$PROFILE" --package evm-domain-runtime --features "$FEATURES"
    cargo build --profile "$PROFILE" --package auto-id-domain-runtime --features "$FEATURES"
    set +x
else
    echo "Skipping builds of subspace-node and runtimes"
fi

echo "Generating weights for Subspace runtime..."
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
  CMD="./target/$PROFILE/subspace-node benchmark pallet \
    --runtime=./target/$PROFILE/wbuild/subspace-runtime/subspace_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./crates/subspace-runtime/src/weights/$PALLET.rs"
  echo "$CMD"
  $CMD
done

echo "Generating weights for EVM domain runtime..."
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
  CMD="./target/$PROFILE/subspace-node domain benchmark pallet \
    --runtime=./target/$PROFILE/wbuild/evm-domain-runtime/evm_domain_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./domains/runtime/evm/src/weights/$PALLET.rs"
  echo "$CMD"
  $CMD
done

echo "Generating weights for Auto ID domain runtime..."
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
  CMD="./target/$PROFILE/subspace-node domain benchmark pallet \
    --runtime=./target/$PROFILE/wbuild/auto-id-domain-runtime/auto_id_domain_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./domains/runtime/auto-id/src/weights/$PALLET.rs"
  echo "$CMD"
  $CMD
done

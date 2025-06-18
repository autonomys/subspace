#!/usr/bin/env bash

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

PROFILE="production"
FEATURES="runtime-benchmarks"
# While testing the script, use --steps=2 --repeat=1 for quick but inaccurate benchmarks
BENCH_SETTINGS="--extrinsic=* --wasm-execution=compiled --genesis-builder=none --steps=50 --repeat=20 --heap-pages=4096"
# If you're sure the node and runtime binaries are up to date, set this to true to save rebuild and
# linking time
SKIP_BUILDS="false"

# This function searches through a runtime lib.rs file for benchmark definitions
function find_benchmarks () {
  grep '\[[a-z0-9_]*, [A-Za-z0-9:<>]*\]' | cut -d, -f1 | cut -d[ -f2
}

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
# frame_benchmarking is unused, it contains benchmarks for hashing and sr25519_verification
# TODO: `pallet_democracy` benchmark are broken, need investigation
SUBSPACE_RUNTIME_PALLETS=$(cat ./crates/subspace-runtime/src/lib.rs | \
    find_benchmarks | \
    grep -v -e "frame_benchmarking" -e "balance_transfer_check_extension" -e "pallet_democracy"
)
echo "Pallet list: $SUBSPACE_RUNTIME_PALLETS"
for PALLET in $SUBSPACE_RUNTIME_PALLETS; do
  CMD="./target/$PROFILE/subspace-node benchmark pallet \
    --runtime=./target/$PROFILE/wbuild/subspace-runtime/subspace_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./crates/subspace-runtime/src/weights/$PALLET.rs"
  echo "$CMD"
  $CMD
done

echo "Fixing pallet names in weights for Subspace runtime..."
set -x
sed -i "" -e "s/pallet_subspace_extension::WeightInfo/pallet_subspace::extensions::WeightInfo/g" \
    ./crates/subspace-runtime/src/weights/pallet_subspace_extension.rs
sed -i "" -e "s/pallet_messenger_from_domains_extension::WeightInfo/pallet_messenger::extensions::FromDomainWeightInfo/g" \
    ./crates/subspace-runtime/src/weights/pallet_messenger_from_domains_extension.rs
set +x

# These extension weights are written to subspace-runtime-primitives
# TODO: move these extensions to subspace-runtime, and use default weights in test runtimes
SUBSPACE_RUNTIME_PRIMITIVES=(
    "balance_transfer_check_extension"
)
echo "Primitives Pallet list: ${SUBSPACE_RUNTIME_PRIMITIVES[@]}"
for PALLET in "${SUBSPACE_RUNTIME_PRIMITIVES[@]}"; do
  CMD="./target/$PROFILE/subspace-node benchmark pallet \
    --runtime=./target/$PROFILE/wbuild/subspace-runtime/subspace_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./crates/subspace-runtime-primitives/src/weights/$PALLET.rs"
  echo "$CMD"
  $CMD
done

echo "Fixing pallet names in weights for Subspace runtime primitives..."
set -x
sed -i "" -e "s/balance_transfer_check_extension::WeightInfo/crate::extension::WeightInfo/g" \
    ./crates/subspace-runtime-primitives/src/weights/balance_transfer_check_extension.rs
set +x

echo "Generating weights for EVM domain runtime..."
EVM_DOMAIN_RUNTIME_PALLETS=$(cat domains/runtime/evm/src/lib.rs | \
    find_benchmarks | \
    grep -v -e "frame_benchmarking" -e "pallet_evm_tracker"
)
echo "Pallet list: $EVM_DOMAIN_RUNTIME_PALLETS"
for PALLET in $EVM_DOMAIN_RUNTIME_PALLETS; do
  CMD="./target/$PROFILE/subspace-node domain benchmark pallet \
    --runtime=./target/$PROFILE/wbuild/evm-domain-runtime/evm_domain_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./domains/runtime/evm/src/weights/$PALLET.rs"
  echo "$CMD"
  $CMD
done

# These extension weights are written to pallet-evm-tracker
# TODO: move these weights to evm-domain-runtime, and use default weights in test runtimes
# TODO: pallet_evm_tracker CheckNonce extension benchmarks
PALLET="pallet_evm_tracker"
echo "EVM Tracker Pallet name: $PALLET"
CMD="./target/$PROFILE/subspace-node domain benchmark pallet \
  --runtime=./target/$PROFILE/wbuild/evm-domain-runtime/evm_domain_runtime.compact.compressed.wasm \
  $BENCH_SETTINGS \
  --pallet=$PALLET --output=./domains/pallets/evm-tracker/src/weights/$PALLET.rs"
echo "$CMD"
$CMD

echo "Fixing pallet names in weights for $PALLET..."
set -x
sed -i "" -e "s/pallet_evm_tracker::WeightInfo/crate::WeightInfo/g" \
    ./domains/pallets/evm-tracker/src/weights/pallet_evm_tracker.rs
set +x

echo "Generating weights for Auto ID domain runtime..."
AUTO_ID_DOMAIN_RUNTIME_PALLETS=$(cat domains/runtime/auto-id/src/lib.rs | \
    find_benchmarks | \
    grep -v -e "frame_benchmarking"
)
echo "Pallet list: $AUTO_ID_DOMAIN_RUNTIME_PALLETS"
for PALLET in $AUTO_ID_DOMAIN_RUNTIME_PALLETS; do
  CMD="./target/$PROFILE/subspace-node domain benchmark pallet \
    --runtime=./target/$PROFILE/wbuild/auto-id-domain-runtime/auto_id_domain_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./domains/runtime/auto-id/src/weights/$PALLET.rs"
  echo "$CMD"
  $CMD
done

echo "Fixing pallet names in weights for domain runtimes..."
# These replacements work for both EVM and Auto ID domain runtimes
set -x
sed -i "" -e "s/pallet_messenger_from_consensus_extension::WeightInfo/pallet_messenger::extensions::FromConsensusWeightInfo/g" \
    ./domains/runtime/*/src/weights/pallet_messenger_from_consensus_extension.rs
sed -i "" -e "s/pallet_messenger_between_domains_extension::WeightInfo/pallet_messenger::extensions::FromDomainWeightInfo/g" \
    ./domains/runtime/*/src/weights/pallet_messenger_between_domains_extension.rs
set +x

echo
echo "==============================================================================="
echo "Successfully generated benchmark weights for Subspace, EVM and Auto ID runtimes"
echo "==============================================================================="
echo

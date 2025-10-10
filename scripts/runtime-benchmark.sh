#!/usr/bin/env bash

# Environment variables:
#   - PALLETS: (optional) limit benchmarks to specific pallets, separated by spaces
#   - SKIP_BUILDS: (optional) if "true", skips rebuilding binaries; defaults to false.
#   - BENCHMARK_TYPE: (optional) check|full. Full for production weights and check for CI and verification; defaults to full.
#   - VERBOSE: (optional) if "true", will print commands that before executed and their outputs else only commands outputs are printed; defaults to "false".
#
# Script supports generating weights for specific pallets taken from environment variable PALLETS or all the pallets.
# If `PALLETS` is unset or empty, all pallets benchmarks are generated else specified pallet's benchmarks are generated.
# Example usage:
#   PALLETS="pallet_balances pallet_staking" ./scripts/runtime-benchmark.sh

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

PROFILE="production"
FEATURES="runtime-benchmarks"
CORE_BENCH_SETTINGS="--extrinsic=* --wasm-execution=compiled --genesis-builder=none --heap-pages=4096"
ITERATION_SETTINGS="--steps=50 --repeat=20"
# Some benchmarks are quick (or noisy) and need extra iterations for accurate results
EXTRA_ITERATION_SETTINGS="--steps=250 --repeat=100"
# If you're sure the node and runtime binaries are up to date, pass SKIP_BUILDS=true env to skip the rebuilding binaries
SKIP_BUILDS="${SKIP_BUILDS:-false}"
# type of benchmark to run, either full or check
# full[default] will run benchmarks with production settings and is slower, must be used while generating actual production weights
# check will run benchmarks that are faster and is used only in CI or verify benchmarks. Must not be used for generating production weights
BENCHMARK_TYPE="${BENCHMARK_TYPE:-full}"
# verbose mode to print the commands to be executed. Useful when debugging
VERBOSE="${VERBOSE:-false}"
# pallets to generate weights for. If unset or empty, all pallet's weights are generated
PALLETS="${PALLETS:-}"

if [[ "${BENCHMARK_TYPE}" == "check" ]]; then
  # We don't need LTO for checking benchmark code runs correctly, but debug runtimes are too large
  # and fail with a memory limit error.
  PROFILE="release"
  ITERATION_SETTINGS="--steps=2 --repeat=1"
  EXTRA_ITERATION_SETTINGS="--steps=2 --repeat=1"
  MODE="check"
else
  # Default full benchmark mode
  MODE="full"
fi

echo "Benchmarks config:"
echo "  - PALLETS=${PALLETS}"
echo "  - SKIP_BUILDS=${SKIP_BUILDS}"
echo "  - BENCHMARK_TYPE=${BENCHMARK_TYPE}"
echo "  - VERBOSE=${VERBOSE}"

if [[ "${VERBOSE}" == 'true' ]]; then
  set -x
fi

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

# This function searches through a runtime lib.rs file for benchmark definitions
function find_benchmarks () {
  grep '\[[a-z0-9_]*, [A-Za-z0-9:<>]*\]' | cut -d, -f1 | cut -d[ -f2
}

# This function filters the list of pallets based on the PALLETS environment variable
# Takes a list of pallets as arguments (newline or space separated) and returns the filtered list.
# If PALLETS env variable is empty, returns all pallets.
function filter_pallets() {
  local ALL_INPUT=("$@")
  local ALL_PALLETS=()

  # Flatten any newline-separated input into an array
  while IFS= read -r PALLET; do
    [[ -n "$PALLET" ]] && ALL_PALLETS+=("$PALLET")
  done < <(printf '%s\n' "${ALL_INPUT[@]}")

  local FILTERED=()

  # If no filtering specified, return all pallets
  if [[ -z "${PALLETS:-}" ]]; then
    echo "${ALL_PALLETS[@]}"
    return
  fi

  # Parse PALLETS environment variable into an array
  IFS=$' \n' read -r -a PALLETS_LIST <<< "$PALLETS"

  # Perform exact match filtering
  for PALLET in "${ALL_PALLETS[@]}"; do
    for TARGET in "${PALLETS_LIST[@]}"; do
      if [[ "$PALLET" == "$TARGET" ]]; then
        FILTERED+=("$PALLET")
        break
      fi
    done
  done

  echo "${FILTERED[@]}"
}

echo "Current directory: $(pwd)"
if [[ ! -d "./crates/subspace-runtime/src/weights" ]] || [[ ! -d "./domains/runtime/evm/src/weights" ]] || [[ ! -d "./domains/runtime/auto-id/src/weights" ]]; then
  echo "Changing to the root of the repository:"
  cd "$(dirname "$0")/.."
  echo "Current directory: $(pwd)"
  if [[ ! -d "./crates/subspace-runtime/src/weights" ]] || [[ ! -d "./domains/runtime/evm/src/weights" ]] || [[ ! -d "./domains/runtime/auto-id/src/weights" ]]; then
    echo "Missing ./crates/subspace-runtime/src/weights, ./domains/runtime/evm/src/weights or ./domains/runtime/auto-id/src/weights directories"
    echo "This script must be run from the base of an autonomys/subspace repository checkout"
    exit 1
  fi
fi

if [[ "$SKIP_BUILDS" != 'true' ]]; then
  # The node builds all the runtimes, and generating weights will rebuild some runtimes, even though
  # those weights are not used in the benchmarks. So it is faster to build everything upfront.
  echo "Building subspace-node and runtimes with profile: '$PROFILE', features: '$FEATURES', and mode: '$MODE'..."
  cargo build --profile "$PROFILE" --bin subspace-node --features "$FEATURES"
  cargo build --profile "$PROFILE" --package subspace-runtime --features "$FEATURES"
  cargo build --profile "$PROFILE" --package evm-domain-runtime --features "$FEATURES"
  cargo build --profile "$PROFILE" --package auto-id-domain-runtime --features "$FEATURES"
else
  echo "Skipping builds of subspace-node and runtimes"
fi

echo "Generating weights for Subspace runtime..."
BENCH_SETTINGS="$CORE_BENCH_SETTINGS $ITERATION_SETTINGS"
# frame_benchmarking is unused, it contains benchmarks for hashing and sr25519_verification
# TODO: `pallet_democracy` benchmark are broken, need investigation
SUBSPACE_RUNTIME_PALLETS=$(cat ./crates/subspace-runtime/src/lib.rs | \
  find_benchmarks | \
  grep -v -e "frame_benchmarking" -e "balance_transfer_check_extension" -e "pallet_democracy"
)

# Filter using filter_pallets()
SUBSPACE_RUNTIME_PALLETS=($(filter_pallets "${SUBSPACE_RUNTIME_PALLETS[@]}"))

for PALLET in "${SUBSPACE_RUNTIME_PALLETS[@]}"; do
  echo "Generating benchmarks for ${PALLET}"
  ./target/$PROFILE/subspace-node benchmark pallet \
    --runtime=./target/$PROFILE/wbuild/subspace-runtime/subspace_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./crates/subspace-runtime/src/weights/$PALLET.rs
done

echo "Fixing pallet names in weights for Subspace runtime..."
"${SED_IN_PLACE[@]}" -e "s/pallet_subspace_extension::WeightInfo/pallet_subspace::extensions::WeightInfo/g" \
  ./crates/subspace-runtime/src/weights/pallet_subspace_extension.rs || (echo "'$SED_IN_PLACE' failed, please set \$SED_IN_PLACE to a valid sed in-place replacement command" && exit 1)
"${SED_IN_PLACE[@]}" -e "s/pallet_messenger_from_domains_extension::WeightInfo/pallet_messenger::extensions::FromDomainWeightInfo/g" \
  ./crates/subspace-runtime/src/weights/pallet_messenger_from_domains_extension.rs

# These extension weights are written to subspace-runtime-primitives
# TODO: move these extensions to subspace-runtime, and use default weights in test runtimes
SUBSPACE_RUNTIME_PRIMITIVES=(
  "balance_transfer_check_extension"
)
# We need to run extra iterations to get accurate linear values in these benchmarks.
BENCH_SETTINGS="$CORE_BENCH_SETTINGS $EXTRA_ITERATION_SETTINGS"

# Filter using filter_pallets()
SUBSPACE_RUNTIME_PRIMITIVES=($(filter_pallets "${SUBSPACE_RUNTIME_PRIMITIVES[@]}"))
echo "Primitives Pallet list: ${SUBSPACE_RUNTIME_PRIMITIVES[*]}"
for PALLET in "${SUBSPACE_RUNTIME_PRIMITIVES[@]}"; do
  echo "Generating benchmarks for ${PALLET}"
  ./target/$PROFILE/subspace-node benchmark pallet \
    --runtime=./target/$PROFILE/wbuild/subspace-runtime/subspace_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./crates/subspace-runtime-primitives/src/weights/$PALLET.rs
done

echo "Fixing pallet names in weights for Subspace runtime primitives..."
"${SED_IN_PLACE[@]}" -e "s/balance_transfer_check_extension::WeightInfo/crate::extension::WeightInfo/g" \
  ./crates/subspace-runtime-primitives/src/weights/balance_transfer_check_extension.rs

echo "Generating weights for EVM domain runtime..."
BENCH_SETTINGS="$CORE_BENCH_SETTINGS $ITERATION_SETTINGS"
EVM_DOMAIN_RUNTIME_PALLETS=$(cat domains/runtime/evm/src/lib.rs | \
  find_benchmarks | \
  grep -v -e "frame_benchmarking" -e "pallet_evm_tracker"
)

# Filter using filter_pallets()
EVM_DOMAIN_RUNTIME_PALLETS=($(filter_pallets "${EVM_DOMAIN_RUNTIME_PALLETS[@]}"))
echo "Pallet list: ${EVM_DOMAIN_RUNTIME_PALLETS[*]}"
for PALLET in "${EVM_DOMAIN_RUNTIME_PALLETS[@]}"; do
  echo "Generating benchmarks for ${PALLET}"
  ./target/$PROFILE/subspace-node domain benchmark pallet \
    --runtime=./target/$PROFILE/wbuild/evm-domain-runtime/evm_domain_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./domains/runtime/evm/src/weights/$PALLET.rs
done

# These extension weights are written to pallet-evm-tracker
# TODO: move these weights to evm-domain-runtime, and use default weights in test runtimes
# TODO: pallet_evm_tracker CheckNonce extension benchmarks
EVM_RUNTIME_PRIMITIVES=(
  "pallet_evm_tracker"
)
EVM_RUNTIME_PRIMITIVES=($(filter_pallets "${EVM_RUNTIME_PRIMITIVES[@]}"))
echo "EVM Primitives Pallet list: ${EVM_RUNTIME_PRIMITIVES[*]}"
BENCH_SETTINGS="$CORE_BENCH_SETTINGS $ITERATION_SETTINGS"
for PALLET in "${EVM_RUNTIME_PRIMITIVES[@]}"; do
  echo "Generating benchmarks for ${PALLET}"
  ./target/$PROFILE/subspace-node domain benchmark pallet \
    --runtime=./target/$PROFILE/wbuild/evm-domain-runtime/evm_domain_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./domains/pallets/evm-tracker/src/weights/$PALLET.rs
done

echo "Fixing pallet names in weights for EVM primitives pallets..."
"${SED_IN_PLACE[@]}" -e "s/pallet_evm_tracker::WeightInfo/crate::WeightInfo/g" \
  ./domains/pallets/evm-tracker/src/weights/pallet_evm_tracker.rs

echo "Generating weights for Auto ID domain runtime..."
BENCH_SETTINGS="$CORE_BENCH_SETTINGS $ITERATION_SETTINGS"
AUTO_ID_DOMAIN_RUNTIME_PALLETS=$(cat domains/runtime/auto-id/src/lib.rs | \
  find_benchmarks | \
  grep -v -e "frame_benchmarking"
)

# Filter using filter_pallets()
AUTO_ID_DOMAIN_RUNTIME_PALLETS=($(filter_pallets "${AUTO_ID_DOMAIN_RUNTIME_PALLETS[@]}"))
echo "Pallet list: ${AUTO_ID_DOMAIN_RUNTIME_PALLETS[*]}"
for PALLET in "${AUTO_ID_DOMAIN_RUNTIME_PALLETS[@]}"; do
  echo "Generating benchmarks for ${PALLET}"
  ./target/$PROFILE/subspace-node domain benchmark pallet \
    --runtime=./target/$PROFILE/wbuild/auto-id-domain-runtime/auto_id_domain_runtime.compact.compressed.wasm \
    $BENCH_SETTINGS \
    --pallet=$PALLET --output=./domains/runtime/auto-id/src/weights/$PALLET.rs
done

echo "Fixing pallet names in weights for domain runtimes..."
# These replacements work for both EVM and Auto ID domain runtimes
"${SED_IN_PLACE[@]}" -e "s/pallet_messenger_from_consensus_extension::WeightInfo/pallet_messenger::extensions::FromConsensusWeightInfo/g" \
  ./domains/runtime/*/src/weights/pallet_messenger_from_consensus_extension.rs
"${SED_IN_PLACE[@]}" -e "s/pallet_messenger_between_domains_extension::WeightInfo/pallet_messenger::extensions::FromDomainWeightInfo/g" \
  ./domains/runtime/*/src/weights/pallet_messenger_between_domains_extension.rs

echo "Checking that generated weights will compile correctly..."
cargo check --profile "$PROFILE" --bin subspace-node --features "$FEATURES"
cargo check --profile "$PROFILE" --package subspace-runtime --features "$FEATURES"
cargo check --profile "$PROFILE" --package evm-domain-runtime --features "$FEATURES"
cargo check --profile "$PROFILE" --package auto-id-domain-runtime --features "$FEATURES"

# Stop showing executed commands
if [[ "${VERBOSE}" == 'true' ]]; then
  set +x
fi

echo
echo "==============================================================================="
echo "Successfully generated benchmark weights for Subspace, EVM and Auto ID runtimes"
echo "==============================================================================="
echo

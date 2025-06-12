#!/bin/bash -e

cargo build -r --bin subspace-node --features runtime-benchmarks

cargo build -r -p subspace-runtime --features runtime-benchmarks
subspace_runtime_pallets=(
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
for pallet in "${subspace_runtime_pallets[@]}"; do
  cmd="./target/release/subspace-node benchmark pallet \
    --runtime=./target/release/wbuild/subspace-runtime/subspace_runtime.compact.compressed.wasm \
    --genesis-builder=none --steps=50 --repeat=20 --pallet=$pallet --extrinsic=* --wasm-execution=compiled \
    --heap-pages=4096 --output=./crates/subspace-runtime/src/weights/$pallet.rs"
  echo $cmd
  $cmd
done

cargo build -r -p evm-domain-runtime --features runtime-benchmarks
evm_domain_runtime_pallets=(
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
for pallet in "${evm_domain_runtime_pallets[@]}"; do
  cmd="./target/release/subspace-node domain benchmark pallet \
    --runtime=./target/release/wbuild/evm-domain-runtime/evm_domain_runtime.compact.compressed.wasm \
    --genesis-builder=none --steps=50 --repeat=20 --pallet=$pallet --extrinsic=* --wasm-execution=compiled \
    --heap-pages=4096 --output=./domains/runtime/evm/src/weights/$pallet.rs"
  echo $cmd
  $cmd
done

cargo build -r -p auto-id-domain-runtime --features runtime-benchmarks
auto_id_domain_runtime_pallets=(
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
for pallet in "${auto_id_domain_runtime_pallets[@]}"; do
  cmd="./target/release/subspace-node domain benchmark pallet \
    --runtime=./target/release/wbuild/auto-id-domain-runtime/auto_id_domain_runtime.compact.compressed.wasm \
    --genesis-builder=none --steps=50 --repeat=20 --pallet=$pallet --extrinsic=* --wasm-execution=compiled \
    --heap-pages=4096 --output=./domains/runtime/auto-id/src/weights/$pallet.rs"
  echo $cmd
  $cmd
done

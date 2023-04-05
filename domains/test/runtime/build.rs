fn main() {
    subspace_wasm_tools::create_runtime_bundle_inclusion_file(
        "core-payments-domain-runtime",
        "CORE_PAYMENTS_WASM_BUNDLE",
        Some(&sp_domains::DomainId::CORE_PAYMENTS.link_section_name()),
        "core_payments_wasm_bundle.rs",
    );

    subspace_wasm_tools::create_runtime_bundle_inclusion_file(
        "core-eth-relay-runtime",
        "CORE_ETH_RELAY_WASM_BUNDLE",
        Some(&sp_domains::DomainId::CORE_ETH_RELAY.link_section_name()),
        "core_eth_relay_wasm_bundle.rs",
    );

    #[cfg(feature = "std")]
    {
        substrate_wasm_builder::WasmBuilder::new()
            .with_current_project()
            .enable_feature("wasm-builder")
            .export_heap_base()
            .import_memory()
            .build();
    }

    subspace_wasm_tools::export_wasm_bundle_path();
}

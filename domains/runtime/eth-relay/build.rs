fn main() {
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

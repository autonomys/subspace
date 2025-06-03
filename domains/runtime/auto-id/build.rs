fn main() {
    #[cfg(feature = "std")]
    {
        // SAFETY: no concurrent writing or reading here, build scripts are single threaded.
        unsafe { std::env::set_var("WASM_BUILD_TYPE", "release") };
        substrate_wasm_builder::WasmBuilder::new()
            .with_current_project()
            .export_heap_base()
            .import_memory()
            .build();
    }
}

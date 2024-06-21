fn main() {
    #[cfg(feature = "std")]
    {
        // TODO: Workaround for https://github.com/paritytech/polkadot-sdk/issues/3192
        std::env::set_var("CFLAGS", "-mcpu=mvp");
        std::env::set_var("WASM_BUILD_TYPE", "release");
        substrate_wasm_builder::WasmBuilder::new()
            .with_current_project()
            .export_heap_base()
            .import_memory()
            .build();
    }
}

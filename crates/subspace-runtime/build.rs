fn main() {
    #[cfg(feature = "std")]
    {
        #[allow(unused_mut)]
        let mut builder = substrate_wasm_builder::WasmBuilder::new()
            .with_current_project()
            .export_heap_base()
            .import_memory();

        // Enable fn-dsa feature for WASM build if it's enabled for the native build
        #[cfg(feature = "fn-dsa")]
        {
            builder = builder.enable_feature("fn-dsa");
        }

        builder.build();
    }
}

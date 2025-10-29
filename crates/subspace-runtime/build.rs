fn main() {
    #[cfg(feature = "std")]
    {
        #[allow(unused_mut)]
        let mut builder = substrate_wasm_builder::WasmBuilder::new()
            .with_current_project()
            .export_heap_base()
            .import_memory();

        builder.build();
    }
}

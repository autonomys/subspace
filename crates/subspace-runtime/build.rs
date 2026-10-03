fn main() {
    #[cfg(feature = "std")]
    {
        substrate_wasm_builder::WasmBuilder::new()
            .with_current_project()
            .export_heap_base()
            .import_memory()
            // TODO: `-Znext-solver=globally` is a requirement for `generic_const_args` in
            //  `subspace-proof-of-space`, wasm builder doesn't use flags from `.cargo/config.toml`
            .append_to_rust_flags("-Znext-solver=globally -Zmin-recursion-limit=256")
            .build();
    }
}

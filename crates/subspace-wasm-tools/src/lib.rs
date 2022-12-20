use sc_executor_common::error::WasmError;
use sc_executor_common::runtime_blob::RuntimeBlob;
use std::path::PathBuf;
use std::{env, fs};

/// Emits `cargo:WASM_FILE=/path` so that dependent crates can use it in build script using
/// `DEP_PACKAGE_WASM_FILE` environment variable
///
/// This also requires `links` attribute in the `package` section of `Cargo.toml` set to the package
/// name.
pub fn export_wasm_bundle_path() {
    let mut out_dir = PathBuf::from(env::var("OUT_DIR").expect("Always set by cargo"));
    // Removing `build/package-abcd/out` component from
    // `target/debug/build/package-abcd/out`
    out_dir.pop();
    out_dir.pop();
    out_dir.pop();

    let package_name = env::var("CARGO_PKG_NAME").expect("Always set by cargo");
    let wasm_base_file_name = package_name.replace('-', "_");
    let wasm_file_path = out_dir
        .join("wbuild")
        .join(package_name)
        .join(format!("{wasm_base_file_name}.compact.wasm"));

    println!("cargo:WASM_FILE={}", wasm_file_path.display());
}

/// Creates a `target_file_name` in `OUT_DIR` that will contain constant `bundle_const_name` with
/// runtime of `runtime_crate_name` stored in it.
///
/// Must be called before Substrate's WASM builder.
pub fn create_runtime_bundle_inclusion_file(
    runtime_crate_name: &str,
    bundle_const_name: &str,
    maybe_link_section_name: Option<&str>,
    target_file_name: &str,
) {
    // Create a file that will include execution runtime into consensus runtime
    let execution_wasm_bundle_path = env::var("SUBSPACE_WASM_BUNDLE_PATH").unwrap_or_else(|_| {
        env::var(format!(
            "DEP_{}_WASM_FILE",
            runtime_crate_name.replace('-', "_").to_ascii_uppercase()
        ))
        .expect("Must be set by dependency")
    });

    env::set_var("SUBSPACE_WASM_BUNDLE_PATH", &execution_wasm_bundle_path);

    let execution_wasm_bundle_rs_path =
        env::var("OUT_DIR").expect("Set by cargo; qed") + "/" + target_file_name;
    let mut execution_wasm_bundle_rs_contents = format!(
        r#"
            pub const {bundle_const_name}: &[u8] = include_bytes!("{}");
        "#,
        execution_wasm_bundle_path.escape_default()
    );

    if let Some(link_section_name) = maybe_link_section_name {
        let wasm_bundle_content = fs::read(&execution_wasm_bundle_path).unwrap_or_else(|e| {
            panic!("Failed to read wasm bundle from {execution_wasm_bundle_path:?}: {e}",)
        });
        let wasm_bundle_size = wasm_bundle_content.len();
        drop(wasm_bundle_content);

        let link_section_decl = format!(
            r#"
                const _: () = {{
                    #[cfg(not(feature = "std"))]
                    #[link_section = "{link_section_name}"]
                    static SECTION_CONTENTS: [u8; {wasm_bundle_size}] = *include_bytes!("{}");
                }};
            "#,
            execution_wasm_bundle_path.escape_default()
        );

        execution_wasm_bundle_rs_contents.push_str(&link_section_decl);
    }

    fs::write(
        execution_wasm_bundle_rs_path,
        execution_wasm_bundle_rs_contents,
    )
    .unwrap_or_else(|error| {
        panic!("Must be able to write to {target_file_name}: {error}");
    });
}

/// Read the core domain runtime blob file from the system domain runtime blob file.
///
/// The `section_contents_name` should be driven from `DomainId::link_section_name`.
pub fn read_core_domain_runtime_blob(
    system_domain_bundle: &[u8],
    section_contents_name: String,
) -> Result<Vec<u8>, WasmError> {
    let system_runtime_blob = RuntimeBlob::new(system_domain_bundle)?;

    let embedded_runtime_blob = system_runtime_blob
        .custom_section_contents(&section_contents_name)
        .ok_or_else(|| {
            WasmError::Other(format!("Custom section {section_contents_name} not found"))
        })?;

    Ok(embedded_runtime_blob.to_vec())
}

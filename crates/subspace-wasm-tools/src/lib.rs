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
    let execution_wasm_bundle_rs_contents = format!(
        r#"
            pub const {bundle_const_name}: &[u8] = include_bytes!("{}");
        "#,
        execution_wasm_bundle_path.escape_default()
    );

    fs::write(
        execution_wasm_bundle_rs_path,
        execution_wasm_bundle_rs_contents,
    )
    .unwrap_or_else(|error| {
        panic!("Must be able to write to {target_file_name}: {error}");
    });
}

use std::{env, fs};

/// Creates a `target_file_name` in `OUT_DIR` that will contain constant `bundle_const_name` with
/// runtime of `runtime_crate_name` stored in it.
///
/// Must be called before Substrate's WASM builder.
pub fn create_runtime_bundle_inclusion_file(
    target_dir: &str,
    runtime_crate_name: &str,
    bundle_const_name: &str,
    target_file_name: &str,
) {
    // Make correct profile accessible in child processes.
    env::set_var(
        "WBUILD_PROFILE",
        env::var("WBUILD_PROFILE")
            .unwrap_or_else(|_| env::var("PROFILE").expect("Defined by cargo; qed")),
    );

    // Create a file that will include execution runtime into consensus runtime
    let profile = env::var("WBUILD_PROFILE").expect("Set above; qed");
    let execution_wasm_bundle_path = format!(
        "{target_dir}/{profile}/wbuild/{runtime_crate_name}/{}.compact.wasm",
        runtime_crate_name.replace('-', "_")
    );

    let execution_wasm_bundle_rs_path =
        env::var("OUT_DIR").expect("Set by cargo; qed") + "/" + target_file_name;
    let execution_wasm_bundle_rs_contents = format!(
        r#"
            pub const {bundle_const_name}: &[u8] = include_bytes!("{execution_wasm_bundle_path}");
        "#
    );

    fs::write(
        execution_wasm_bundle_rs_path,
        execution_wasm_bundle_rs_contents,
    )
    .unwrap_or_else(|error| {
        panic!("Must be able to write to {target_file_name}: {error}");
    });
}

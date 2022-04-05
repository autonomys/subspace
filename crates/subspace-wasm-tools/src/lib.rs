use std::{env, fs, path::PathBuf};

fn get_relative_target(dir: PathBuf) -> Option<PathBuf> {
    if dir.join("Cargo.lock").is_file() && dir.join("target").is_dir() {
        return Some(dir.join("target"));
    }
    dir.parent()
        .map(ToOwned::to_owned)
        .and_then(get_relative_target)
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
    let target_dir = if let Ok(target_dir) =
        env::var("CARGO_TARGET_DIR").or_else(|_| env::var("WASM_TARGET_DIRECTORY"))
    {
        // Propagate target directory to wasm build
        target_dir.into()
    } else {
        let out_dir = env::var("OUT_DIR").expect("Always set by cargo");
        get_relative_target(out_dir.into())
            .map(|target_dir| get_relative_target(target_dir.clone()).unwrap_or(target_dir))
            .expect("Out dir is always inside the target directory")
    };
    if env::var("WASM_TARGET_DIRECTORY").is_err() {
        env::set_var("WASM_TARGET_DIRECTORY", &target_dir);
    }

    // Make correct profile accessible in child processes.
    env::set_var(
        "WBUILD_PROFILE",
        env::var("WBUILD_PROFILE")
            .unwrap_or_else(|_| env::var("PROFILE").expect("Defined by cargo; qed")),
    );

    // Create a file that will include execution runtime into consensus runtime
    let profile = env::var("WBUILD_PROFILE").expect("Set above; qed");
    let execution_wasm_bundle_path = target_dir
        .join(profile)
        .join("wbuild")
        .join(runtime_crate_name)
        .join(format!(
            "{}.compact.wasm",
            runtime_crate_name.replace('-', "_")
        ));

    let execution_wasm_bundle_rs_path =
        env::var("OUT_DIR").expect("Set by cargo; qed") + "/" + target_file_name;
    let execution_wasm_bundle_rs_contents = format!(
        r#"
            pub const {bundle_const_name}: &[u8] = include_bytes!("{}");
        "#,
        execution_wasm_bundle_path
            .to_string_lossy()
            .escape_default()
    );

    fs::write(
        execution_wasm_bundle_rs_path,
        execution_wasm_bundle_rs_contents,
    )
    .unwrap_or_else(|error| {
        panic!("Must be able to write to {target_file_name}: {error}");
    });
}

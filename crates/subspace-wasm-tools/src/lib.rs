use std::path::{Component, Path, PathBuf};
use std::{env, fs};

fn get_relative_target(dir: &Path) -> Option<PathBuf> {
    if dir.join("Cargo.lock").is_file() && dir.join("target").is_dir() {
        return Some(dir.join("target"));
    }
    dir.parent().and_then(get_relative_target)
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
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("Always set by cargo"));
    let target_dir = env::var("CARGO_TARGET_DIR")
        .or_else(|_| env::var("SUBSPACE_WASM_TARGET_DIRECTORY"))
        .map(Into::into)
        .unwrap_or_else(|_| {
            // Call get `get_relative_target` twice if possible, as wasm target directory is
            // contained in host target directory, and we actually need host one.
            get_relative_target(&out_dir)
                .map(|target_dir| get_relative_target(&target_dir).unwrap_or(target_dir))
                .expect("Out dir is always inside the target directory")
        });

    // Propagate target directory to wasm build
    if env::var("SUBSPACE_WASM_TARGET_DIRECTORY").is_err() {
        env::set_var("SUBSPACE_WASM_TARGET_DIRECTORY", &target_dir);
    }

    // Make correct profile accessible in child processes.
    env::set_var(
        "SUBSPACE_WASM_BUILD_PROFILE",
        env::var("SUBSPACE_WASM_BUILD_PROFILE").unwrap_or_else(|_| {
            // The tricky situation, Cargo doesn't put custom profiles like `production` in
            // `PROFILE` environment variable, so we need to find the actual profile ourselves by
            // extracting the first component of `OUT_DIR` that comes after `CARGO_TARGET_DIR`.
            let mut out_components = out_dir.components();
            let mut target_components = target_dir.components();
            while target_components.next().is_some() {
                out_components.next();
            }

            if let Component::Normal(profile) = out_components
                .next()
                .expect("OUT_DIR has CARGO_TARGET_DIR as prefix")
            {
                profile
                    .to_str()
                    .expect("Profile is always a utf-8 string")
                    .to_string()
            } else {
                unreachable!("OUT_DIR has CARGO_TARGET_DIR as prefix")
            }
        }),
    );

    // Create a file that will include execution runtime into consensus runtime
    let profile = env::var("SUBSPACE_WASM_BUILD_PROFILE").expect("Set above; qed");
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

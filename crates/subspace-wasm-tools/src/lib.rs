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

    env::set_var(
        "SUBSPACE_WASM_BUNDLE_PATH",
        env::var("SUBSPACE_WASM_BUNDLE_PATH").unwrap_or_else(|_| {
            // The tricky situation, Cargo doesn't put custom profiles like `production` in
            // `PROFILE` environment variable, so we need to find the actual profile ourselves by
            // extracting the first component of `OUT_DIR` that comes after `CARGO_TARGET_DIR`.
            let mut out_components = out_dir.components();
            let mut target_components = target_dir.components();
            while target_components.next().is_some() {
                out_components.next();
            }

            let mut path = target_dir;

            let profile = loop {
                if let Component::Normal(profile_or_target) = out_components
                    .next()
                    .expect("OUT_DIR has CARGO_TARGET_DIR as prefix")
                {
                    let profile_or_target = profile_or_target
                        .to_str()
                        .expect("Profile is always a utf-8 string");

                    // Custom target was specified with `--target`
                    if profile_or_target == env::var("TARGET").expect("Always set by cargo") {
                        path = path.join(profile_or_target);
                    } else {
                        break profile_or_target;
                    }
                } else {
                    unreachable!("OUT_DIR has CARGO_TARGET_DIR as prefix")
                }
            };

            path.join(profile)
                .join("wbuild")
                .join(runtime_crate_name)
                .join(format!(
                    "{}.compact.wasm",
                    runtime_crate_name.replace('-', "_")
                ))
                .to_string_lossy()
                .to_string()
        }),
    );

    // Create a file that will include execution runtime into consensus runtime
    let execution_wasm_bundle_path = env::var("SUBSPACE_WASM_BUNDLE_PATH").expect("Set above; qed");

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

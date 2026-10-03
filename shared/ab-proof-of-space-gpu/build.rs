use cargo_gpu_install::install::Install;
use cargo_gpu_install::spirv_builder::{Capability, SpirvBuilderError, SpirvMetadata};
use std::error::Error;
use std::path::PathBuf;
use std::{env, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Always set by Cargo; qed");

    if target_arch == "spirv" {
        return Ok(());
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("Always set by Cargo; qed"));

    // Skip compilation under Miri and rustdoc, it will not be used
    if ["MIRI_SYSROOT", "RUSTDOCFLAGS"]
        .iter()
        .any(|var| env::var(var).is_ok())
    {
        let empty_file = out_dir.join("empty.bin");
        fs::write(&empty_file, [])?;
        println!("cargo::rustc-env=SHADER_PATH={}", empty_file.display());

        return Ok(());
    }

    let cargo_manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("Always set by Cargo; qed");
    let profile = env::var("PROFILE").expect("Always set by Cargo; qed");

    let shader_crate = PathBuf::from(cargo_manifest_dir);

    let backend = Install::from_shader_crate(shader_crate.clone()).run()?;

    // TODO: Workaround for https://github.com/Rust-GPU/rust-gpu/issues/461
    // SAFETY: Single-threaded
    unsafe {
        env::set_var("RUST_MIN_STACK", "16777216");
        // TODO: `-Znext-solver=globally` is a requirement for `generic_const_args`
        env::set_var("RUSTGPU_RUSTFLAGS", "-Znext-solver=globally");
    }

    let mut spirv_builder = backend
        .to_spirv_builder(shader_crate, "spirv-unknown-vulkan1.2")
        .spirv_metadata(if profile == "debug" {
            SpirvMetadata::NameVariables
        } else {
            SpirvMetadata::None
        })
        .release(profile != "debug")
        // TODO: This should not be needed: https://github.com/Rust-GPU/rust-gpu/issues/386
        .capability(Capability::GroupNonUniformArithmetic)
        // TODO: This should not be needed: https://github.com/Rust-GPU/rust-gpu/issues/386
        .capability(Capability::GroupNonUniformBallot)
        // TODO: This should not be needed: https://github.com/Rust-GPU/rust-gpu/issues/386
        .capability(Capability::GroupNonUniformShuffle)
        // Avoid Cargo deadlock, customize target
        .target_dir_path(out_dir.clone());
    spirv_builder.build_script.defaults = true;
    spirv_builder
        .build_script
        .forward_rustc_warnings
        .replace(true);

    println!("cargo::rerun-if-env-changed=CLIPPY_ARGS");
    let path_to_spv = if env::var("CLIPPY_ARGS").is_ok() {
        match spirv_builder.clippy() {
            Ok(compile_result) => compile_result.module.unwrap_single().to_path_buf(),
            Err(SpirvBuilderError::NoArtifactProduced { .. }) => {
                let empty_file = out_dir.join("empty.bin");
                fs::write(&empty_file, [])?;
                empty_file
            }
            Err(error) => {
                return Err(error.into());
            }
        }
    } else {
        spirv_builder.build()?.module.unwrap_single().to_path_buf()
    };

    println!("cargo::rustc-env=SHADER_PATH={}", path_to_spv.display());

    Ok(())
}

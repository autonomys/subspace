// Originally written by Supranational LLC

use std::env;
use std::thread::available_parallelism;

fn main() {
    // TODO: Lift this restriction
    #[cfg(all(feature = "cuda", feature = "rocm"))]
    compile_error!("Both `cuda` and `rocm` features can't be used together at the moment");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();

    if target_os == "windows" && target_env != "msvc" {
        panic!("Only MSVC is supported on Windows");
    }

    if cfg!(feature = "rocm") {
        println!("cargo::rerun-if-env-changed=HIPCC");

        let mut hipcc = cc::Build::new();
        hipcc.compiler(env::var("HIPCC").unwrap_or("hipcc".to_string()));
        hipcc.cpp(true);
        if cfg!(debug_assertions) {
            hipcc.opt_level(2);
        }
        // Architectures: https://llvm.org/docs/AMDGPUUsage.html
        // GCN GFX9 (CDNA)
        hipcc.flag("--offload-arch=gfx908");
        // GCN GFX9 (CDNA 2)
        hipcc.flag("--offload-arch=gfx90a");
        // GCN GFX9 (CDNA 3)
        hipcc.flag("--offload-arch=gfx942");
        // GCN GFX10.1 (RDNA 1) dGPU
        hipcc.flag("--offload-arch=gfx1010,gfx1011,gfx1012");
        // GCN GFX10.1 (RDNA 1) APU
        hipcc.flag("--offload-arch=gfx1013");
        // GCN GFX10.3 (RDNA 2) dGPU
        hipcc.flag("--offload-arch=gfx1030,gfx1031,gfx1032,gfx1034");
        // GCN GFX10.3 (RDNA 2) APU
        hipcc.flag("--offload-arch=gfx1033,gfx1035,gfx1036");
        // GCN GFX11 (RDNA 3) dGPU
        hipcc.flag("--offload-arch=gfx1100,gfx1101,gfx1102");
        // GCN GFX11 (RDNA 3) APU
        hipcc.flag("--offload-arch=gfx1103,gfx1150,gfx1151");
        // Architecture is too new for hipcc 5.7.1 in stock Ubuntu repos
        hipcc.flag_if_supported("--offload-arch=gfx1152");
        // GCN GFX12 (RDNA 4) dGPU
        // Architecture is too new for hipcc 5.7.1 in stock Ubuntu repos
        hipcc.flag_if_supported("--offload-arch=gfx1200,gfx1201");
        // Flag is too new for hipcc in stock Ubuntu repos
        hipcc.flag_if_supported(format!(
            "-parallel-jobs={}",
            available_parallelism().unwrap()
        ));
        // This controls how error strings get handled in the FFI. When defined error strings get
        // returned from the FFI, and Rust must then free them. When not defined error strings are
        // not returned.
        hipcc.define("TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE", None);
        if let Some(include) = env::var_os("DEP_SPPARK_ROOT") {
            hipcc.include(include);
            hipcc.flag("-include").flag("util/cuda2hip.hpp");
        }
        hipcc.file("src/subspace_api.cu").compile("subspace_rocm");

        // Doesn't link otherwise
        println!("cargo::rustc-link-lib=amdhip64");
    }

    if cfg!(feature = "cuda") {
        let mut nvcc = cc::Build::new();
        nvcc.cuda(true);
        nvcc.flag("-arch=sm_70");
        if target_env != "msvc" {
            nvcc.flag("-Xcompiler").flag("-Wno-unused-function");
        }
        // This controls how error strings get handled in the FFI. When defined error strings get
        // returned from the FFI, and Rust must then free them. When not defined error strings are
        // not returned.
        nvcc.define("TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE", None);
        if let Some(include) = env::var_os("DEP_BLST_C_SRC") {
            nvcc.include(include);
        }
        if let Some(include) = env::var_os("DEP_SPPARK_ROOT") {
            nvcc.include(include);
        }
        nvcc.file("src/subspace_api.cu").compile("subspace_cuda");
    }

    println!("cargo::rerun-if-changed=src");
}

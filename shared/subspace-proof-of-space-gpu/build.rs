// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::env;

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
        let mut hipcc = cc::Build::new();
        hipcc.compiler(env::var("HIPCC").unwrap_or("hipcc".to_string()));
        hipcc.cpp(true);
        if cfg!(debug_assertions) {
            hipcc.opt_level(1);
        }
        hipcc.flag("--offload-arch=native,gfx1100,gfx1030,gfx942,gfx90a,gfx908");
        // 6 corresponds to the number of offload-arch
        hipcc.flag("-parallel-jobs=6");
        // This controls how error strings get handled in the FFI. When defined error strings get
        // returned from the FFI, and Rust must then free them. When not defined error strings are
        // not returned.
        hipcc.define("TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE", None);
        if let Some(include) = env::var_os("DEP_SPPARK_ROOT") {
            hipcc.include(include);
            hipcc.flag("-include").flag("util/cuda2hip.hpp");
        }
        hipcc.file("src/subspace_api.cu").compile("subspace_rocm");
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

    println!("cargo::rerun-if-env-changed=CXXFLAGS");
}

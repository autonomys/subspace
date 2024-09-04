// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::env;

fn main() {
    if cfg!(target_os = "windows") && !cfg!(target_env = "msvc") {
        panic!("unsupported compiler");
    }

    match env::var("DEP_SPPARK_TARGET").unwrap_or_default().as_str() {
        "rocm" => {
            let mut hipcc = cc::Build::new();
            hipcc.compiler(env::var("HIPCC").unwrap_or("hipcc".to_string()));
            hipcc.cpp(true);
            if cfg!(debug_assertions) {
                hipcc.opt_level(1);
            }
            hipcc.flag("--offload-arch=native,gfx1100,gfx1030,gfx942,gfx90a,gfx908");
            hipcc.flag("-parallel-jobs=6"); // 6 corresponds to the number of offload-arch
            hipcc.define("TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE", None);
            if let Some(include) = env::var_os("DEP_SPPARK_ROOT") {
                hipcc.include(include);
                hipcc.flag("-include").flag("util/cuda2hip.hpp");
            }
            hipcc.file("src/subspace_api.cu").compile("subspace_rocm");
        },
        "cuda" => {
            let mut nvcc = cc::Build::new();
            nvcc.cuda(true);
            nvcc.flag("-arch=sm_70");
            #[cfg(not(target_env = "msvc"))]
            nvcc.flag("-Xcompiler").flag("-Wno-unused-function");
            nvcc.define("TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE", None);
            if let Some(include) = env::var_os("DEP_BLST_C_SRC") {
                nvcc.include(include);
            }
            if let Some(include) = env::var_os("DEP_SPPARK_ROOT") {
                nvcc.include(include);
            }
            nvcc.file("src/subspace_api.cu").compile("subspace_cuda");
        },
        _ => panic!("unsupported DEP_SPPARK_TARGET"),
    }
    println!("cargo::rerun-if-changed=src");
    println!("cargo::rerun-if-env-changed=CXXFLAGS");
}

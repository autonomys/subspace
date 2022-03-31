#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit to 256.
#![recursion_limit = "256"]

// Skip in regular `no-std` environment, such that we don't cause conflicts of globally exported
// functions
#[cfg(any(feature = "wasm-builder", feature = "std"))]
mod r#impl;

// Skip in regular `no-std` environment, such that we don't cause conflicts of globally exported
// functions
#[cfg(any(feature = "wasm-builder", feature = "std"))]
pub use r#impl::*;

// Make the WASM binary available, except in wasm builder environment.
#[cfg(not(feature = "wasm-builder"))]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

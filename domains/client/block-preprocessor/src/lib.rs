//! This crate provides a preprocessor for the domain block. It is used to construct extrinsics from
//! the primary block and preprocess those extrinsic before passed to the domain runtime.
#![warn(rust_2018_idioms)]

pub mod preprocessor;
pub mod runtime_api;
pub mod runtime_api_full;
pub mod runtime_api_light;
pub mod xdm_verifier;

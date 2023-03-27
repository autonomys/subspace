//! This crate provides a preprocessor for the domain block. It is used to construct extrinsics from
//! the primary block and preprocess those extrinsic before passed to the domain runtime.
#![warn(rust_2018_idioms)]

pub mod preprocessor;
pub mod state_root_extractor;
pub mod xdm_verifier;

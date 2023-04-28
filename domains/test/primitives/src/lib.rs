#![cfg_attr(not(feature = "std"), no_std)]
//! Test primitive crates that expose necessary extensions that are used in tests.

use domain_runtime_primitives::Moment;

sp_api::decl_runtime_apis! {
    /// Api that returns the timestamp
    pub trait TimestampApi {
        /// Api to construct inherent timestamp extrinsic from given time
        fn timestamp() -> Moment;
    }
}

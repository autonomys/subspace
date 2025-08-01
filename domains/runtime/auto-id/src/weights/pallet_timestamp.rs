
//! Autogenerated weights for `pallet_timestamp`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 46.2.0
//! DATE: 2025-07-10, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `protocol-team-testing`, CPU: `AMD Ryzen 5 3600 6-Core Processor`
//! WASM-EXECUTION: `Compiled`, CHAIN: `None`, DB CACHE: 1024

// Executed Command:
// ./target/production/subspace-node
// domain
// benchmark
// pallet
// --runtime=./target/production/wbuild/auto-id-domain-runtime/auto_id_domain_runtime.compact.compressed.wasm
// --extrinsic=*
// --wasm-execution=compiled
// --genesis-builder=none
// --steps=50
// --repeat=20
// --heap-pages=4096
// --pallet=pallet_timestamp
// --output=./domains/runtime/auto-id/src/weights/pallet_timestamp.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_timestamp`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_timestamp::WeightInfo for WeightInfo<T> {
	/// Storage: `Timestamp::Now` (r:1 w:1)
	/// Proof: `Timestamp::Now` (`max_values`: Some(1), `max_size`: Some(8), added: 503, mode: `MaxEncodedLen`)
	fn set() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `1493`
		// Minimum execution time: 3_790_000 picoseconds.
		Weight::from_parts(4_000_000, 0)
			.saturating_add(Weight::from_parts(0, 1493))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	fn on_finalize() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `36`
		//  Estimated: `0`
		// Minimum execution time: 3_600_000 picoseconds.
		Weight::from_parts(3_760_000, 0)
			.saturating_add(Weight::from_parts(0, 0))
	}
}

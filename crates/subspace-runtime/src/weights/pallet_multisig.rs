
//! Autogenerated weights for `pallet_multisig`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 46.2.0
//! DATE: 2025-06-12, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `protocol-team-testing`, CPU: `AMD Ryzen 5 3600 6-Core Processor`
//! WASM-EXECUTION: `Compiled`, CHAIN: `None`, DB CACHE: 1024

// Executed Command:
// ./target/production/subspace-node
// benchmark
// pallet
// --runtime=./target/production/wbuild/subspace-runtime/subspace_runtime.compact.compressed.wasm
// --extrinsic=*
// --wasm-execution=compiled
// --genesis-builder=none
// --steps=50
// --repeat=20
// --heap-pages=4096
// --pallet=pallet_multisig
// --output=./crates/subspace-runtime/src/weights/pallet_multisig.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_multisig`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_multisig::WeightInfo for WeightInfo<T> {
	/// The range of component `z` is `[0, 10000]`.
	fn as_multi_threshold_1(z: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `0`
		//  Estimated: `0`
		// Minimum execution time: 14_070_000 picoseconds.
		Weight::from_parts(14_331_403, 0)
			.saturating_add(Weight::from_parts(0, 0))
			// Standard Error: 1
			.saturating_add(Weight::from_parts(390, 0).saturating_mul(z.into()))
	}
	/// Storage: `Multisig::Multisigs` (r:1 w:1)
	/// Proof: `Multisig::Multisigs` (`max_values`: None, `max_size`: Some(3346), added: 5821, mode: `MaxEncodedLen`)
	/// Storage: `RuntimeConfigs::EnableDynamicCostOfStorage` (r:1 w:0)
	/// Proof: `RuntimeConfigs::EnableDynamicCostOfStorage` (`max_values`: Some(1), `max_size`: Some(1), added: 496, mode: `MaxEncodedLen`)
	/// The range of component `s` is `[2, 100]`.
	/// The range of component `z` is `[0, 10000]`.
	fn as_multi_create(s: u32, z: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `186 + s * (2 ±0)`
		//  Estimated: `6811`
		// Minimum execution time: 46_649_000 picoseconds.
		Weight::from_parts(38_178_367, 0)
			.saturating_add(Weight::from_parts(0, 6811))
			// Standard Error: 506
			.saturating_add(Weight::from_parts(87_994, 0).saturating_mul(s.into()))
			// Standard Error: 4
			.saturating_add(Weight::from_parts(1_672, 0).saturating_mul(z.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Multisig::Multisigs` (r:1 w:1)
	/// Proof: `Multisig::Multisigs` (`max_values`: None, `max_size`: Some(3346), added: 5821, mode: `MaxEncodedLen`)
	/// The range of component `s` is `[3, 100]`.
	/// The range of component `z` is `[0, 10000]`.
	fn as_multi_approve(s: u32, z: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `185`
		//  Estimated: `6811`
		// Minimum execution time: 27_230_000 picoseconds.
		Weight::from_parts(19_320_299, 0)
			.saturating_add(Weight::from_parts(0, 6811))
			// Standard Error: 353
			.saturating_add(Weight::from_parts(82_590, 0).saturating_mul(s.into()))
			// Standard Error: 3
			.saturating_add(Weight::from_parts(1_672, 0).saturating_mul(z.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Multisig::Multisigs` (r:1 w:1)
	/// Proof: `Multisig::Multisigs` (`max_values`: None, `max_size`: Some(3346), added: 5821, mode: `MaxEncodedLen`)
	/// Storage: `System::Account` (r:1 w:1)
	/// Proof: `System::Account` (`max_values`: None, `max_size`: Some(128), added: 2603, mode: `MaxEncodedLen`)
	/// The range of component `s` is `[2, 100]`.
	/// The range of component `z` is `[0, 10000]`.
	fn as_multi_complete(s: u32, z: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `288 + s * (33 ±0)`
		//  Estimated: `6811`
		// Minimum execution time: 49_399_000 picoseconds.
		Weight::from_parts(40_360_502, 0)
			.saturating_add(Weight::from_parts(0, 6811))
			// Standard Error: 637
			.saturating_add(Weight::from_parts(96_206, 0).saturating_mul(s.into()))
			// Standard Error: 6
			.saturating_add(Weight::from_parts(1_664, 0).saturating_mul(z.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	/// Storage: `Multisig::Multisigs` (r:1 w:1)
	/// Proof: `Multisig::Multisigs` (`max_values`: None, `max_size`: Some(3346), added: 5821, mode: `MaxEncodedLen`)
	/// Storage: `RuntimeConfigs::EnableDynamicCostOfStorage` (r:1 w:0)
	/// Proof: `RuntimeConfigs::EnableDynamicCostOfStorage` (`max_values`: Some(1), `max_size`: Some(1), added: 496, mode: `MaxEncodedLen`)
	/// The range of component `s` is `[2, 100]`.
	fn approve_as_multi_create(s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `187 + s * (2 ±0)`
		//  Estimated: `6811`
		// Minimum execution time: 34_809_000 picoseconds.
		Weight::from_parts(36_771_264, 0)
			.saturating_add(Weight::from_parts(0, 6811))
			// Standard Error: 836
			.saturating_add(Weight::from_parts(91_720, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Multisig::Multisigs` (r:1 w:1)
	/// Proof: `Multisig::Multisigs` (`max_values`: None, `max_size`: Some(3346), added: 5821, mode: `MaxEncodedLen`)
	/// The range of component `s` is `[2, 100]`.
	fn approve_as_multi_approve(s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `185`
		//  Estimated: `6811`
		// Minimum execution time: 17_339_000 picoseconds.
		Weight::from_parts(17_942_749, 0)
			.saturating_add(Weight::from_parts(0, 6811))
			// Standard Error: 422
			.saturating_add(Weight::from_parts(83_675, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Multisig::Multisigs` (r:1 w:1)
	/// Proof: `Multisig::Multisigs` (`max_values`: None, `max_size`: Some(3346), added: 5821, mode: `MaxEncodedLen`)
	/// The range of component `s` is `[2, 100]`.
	fn cancel_as_multi(s: u32, ) -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `357 + s * (1 ±0)`
		//  Estimated: `6811`
		// Minimum execution time: 34_039_000 picoseconds.
		Weight::from_parts(35_642_021, 0)
			.saturating_add(Weight::from_parts(0, 6811))
			// Standard Error: 442
			.saturating_add(Weight::from_parts(77_522, 0).saturating_mul(s.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}

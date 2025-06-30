//! Default weights for the Rewards Pallet
//! This file was not auto-generated.

use crate::WeightInfo;
use core::marker::PhantomData;
use frame_support::traits::Get;
use frame_support::weights::Weight;

#[derive(Debug)]
pub struct SubstrateWeight<T>(PhantomData<T>);

impl<T> WeightInfo for SubstrateWeight<T>
where
    T: frame_system::Config,
{
    fn on_initialize() -> Weight {
        // TODO: benchmark this properly on reference hardware
        Weight::from_parts(10_000, 10_000)
            .saturating_add(T::DbWeight::get().reads(4_u64))
            .saturating_add(T::DbWeight::get().writes(4_u64))
    }
}

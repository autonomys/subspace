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
        Weight::from_parts(0, 0)
            .saturating_add(T::DbWeight::get().reads(1_u64))
            .saturating_add(T::DbWeight::get().writes(4_u64))
    }
}

// TODO: generate these weights
use core::marker::PhantomData;
use frame_support::weights::Weight;

/// Weight functions for `pallet_mmr`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_mmr::WeightInfo for WeightInfo<T> {
    fn on_initialize(_c: u32) -> Weight {
        Weight::from_parts(0, 0)
    }
}

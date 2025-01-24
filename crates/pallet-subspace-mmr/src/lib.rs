//! Pallet that provides necessary Leaf data for MMR.

#![cfg_attr(not(feature = "std"), no_std)]

use frame_system::pallet_prelude::BlockNumberFor;
pub use pallet::*;
use sp_core::Get;
use sp_mmr_primitives::{LeafDataProvider, OnNewRoot};
use sp_runtime::traits::{CheckedSub, One};
use sp_subspace_mmr::subspace_mmr_runtime_interface::get_mmr_leaf_data;
use sp_subspace_mmr::{LeafDataV0, MmrLeaf};

#[frame_support::pallet]
mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_support::Parameter;
    use frame_system::pallet_prelude::BlockNumberFor;
    use sp_core::H256;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<Hash: Into<H256> + From<H256>> {
        type MmrRootHash: Parameter + Copy + MaxEncodedLen;

        /// The number of mmr root hashes to store in the runtime. It will be used to verify mmr
        /// proof statelessly and the number of roots stored here represents the number of blocks
        /// for which the mmr proof is valid since it is generated. After that the mmr proof
        /// will be expired and the prover needs to re-generate the proof.
        type MmrRootHashCount: Get<u32>;
    }

    /// Map of block numbers to mmr root hashes.
    #[pallet::storage]
    #[pallet::getter(fn mmr_root_hash)]
    pub type MmrRootHashes<T: Config> =
        StorageMap<_, Twox64Concat, BlockNumberFor<T>, T::MmrRootHash, OptionQuery>;
}

impl<T: Config> OnNewRoot<T::MmrRootHash> for Pallet<T> {
    fn on_new_root(root: &T::MmrRootHash) {
        let block_number = frame_system::Pallet::<T>::block_number();
        <MmrRootHashes<T>>::insert(block_number, *root);
        if let Some(to_prune) = block_number.checked_sub(&T::MmrRootHashCount::get().into()) {
            <MmrRootHashes<T>>::remove(to_prune);
        }
    }
}

impl<T: Config> LeafDataProvider for Pallet<T> {
    type LeafData = MmrLeaf<BlockNumberFor<T>, T::Hash>;

    fn leaf_data() -> Self::LeafData {
        let block_number = frame_system::Pallet::<T>::block_number()
            .checked_sub(&One::one())
            .expect("`block_number` will always be >= 1; qed");
        let block_hash = frame_system::Pallet::<T>::parent_hash();
        let leaf_data = get_mmr_leaf_data(block_hash.into())
            .expect("leaf data for parent hash must always be derived; qed");
        MmrLeaf::V0(LeafDataV0 {
            block_number,
            block_hash,
            state_root: leaf_data.state_root.into(),
            extrinsics_root: leaf_data.extrinsics_root.into(),
        })
    }
}

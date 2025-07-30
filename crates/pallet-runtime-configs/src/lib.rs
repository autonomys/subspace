//! Pallet for tweaking the runtime configs for multiple network.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;

use core::marker::PhantomData;
use frame_system::pallet_prelude::BlockNumberFor;
pub use pallet::*;
use sp_runtime::traits::Get;
use subspace_runtime_primitives::GenesisConfigParams;
pub use weights::WeightInfo;

const DEFAULT_GENESIS_PARAMS: GenesisConfigParams = GenesisConfigParams::production_params();

pub struct DefaultDomainBlockPruning<T>(PhantomData<T>);
impl<T: Config> Get<BlockNumberFor<T>> for DefaultDomainBlockPruning<T> {
    fn get() -> BlockNumberFor<T> {
        BlockNumberFor::<T>::from(DEFAULT_GENESIS_PARAMS.domain_block_pruning_depth)
    }
}

pub struct DefaultDomainStakingWithdrawalPeriod<T>(PhantomData<T>);
impl<T: Config> Get<BlockNumberFor<T>> for DefaultDomainStakingWithdrawalPeriod<T> {
    fn get() -> BlockNumberFor<T> {
        BlockNumberFor::<T>::from(DEFAULT_GENESIS_PARAMS.staking_withdrawal_period)
    }
}

#[frame_support::pallet]
mod pallet {
    use crate::weights::WeightInfo;
    use crate::{
        DEFAULT_GENESIS_PARAMS, DefaultDomainBlockPruning, DefaultDomainStakingWithdrawalPeriod,
    };
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::Zero;
    use subspace_runtime_primitives::CouncilDemocracyConfigParams;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// Whether to enable calls in pallet-domains.
    #[pallet::storage]
    #[pallet::getter(fn enable_domains)]
    pub type EnableDomains<T> = StorageValue<_, bool, ValueQuery>;

    /// Whether to enable dynamic cost of storage.
    #[pallet::storage]
    #[pallet::getter(fn enable_dynamic_cost_of_storage)]
    pub type EnableDynamicCostOfStorage<T> = StorageValue<_, bool, ValueQuery>;

    /// Whether to enable balances transfers.
    #[pallet::storage]
    #[pallet::getter(fn enable_balance_transfers)]
    pub type EnableBalanceTransfers<T> = StorageValue<_, bool, ValueQuery>;

    #[pallet::storage]
    pub type ConfirmationDepthK<T: Config> = StorageValue<_, BlockNumberFor<T>, ValueQuery>;

    #[pallet::storage]
    pub type CouncilDemocracyConfig<T: Config> =
        StorageValue<_, CouncilDemocracyConfigParams<BlockNumberFor<T>>, ValueQuery>;

    /// Domains block pruning depth.
    #[pallet::storage]
    pub type DomainBlockPruningDepth<T: Config> =
        StorageValue<_, BlockNumberFor<T>, ValueQuery, DefaultDomainBlockPruning<T>>;

    /// Domain nominator's staking withdrawal period
    #[pallet::storage]
    pub type StakingWithdrawalPeriod<T: Config> =
        StorageValue<_, BlockNumberFor<T>, ValueQuery, DefaultDomainStakingWithdrawalPeriod<T>>;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        /// Whether to enable domains
        pub enable_domains: bool,
        /// Whether to enable dynamic cost of storage (if `false` cost per byte is equal to 1)
        pub enable_dynamic_cost_of_storage: bool,
        /// Whether to enable balance transfers
        pub enable_balance_transfers: bool,
        /// Confirmation depth k to use in the archiving process
        pub confirmation_depth_k: BlockNumberFor<T>,
        /// Council and democracy config params.
        pub council_democracy_config_params: CouncilDemocracyConfigParams<BlockNumberFor<T>>,
        /// Domain block pruning depth.
        pub domain_block_pruning_depth: BlockNumberFor<T>,
        /// Domain nominator's staking withdrawal period.
        pub staking_withdrawal_period: BlockNumberFor<T>,
    }

    impl<T: Config> Default for GenesisConfig<T> {
        #[inline]
        fn default() -> Self {
            Self {
                enable_domains: false,
                enable_dynamic_cost_of_storage: false,
                enable_balance_transfers: false,
                confirmation_depth_k: BlockNumberFor::<T>::from(
                    DEFAULT_GENESIS_PARAMS.confirmation_depth_k,
                ),
                council_democracy_config_params:
                    CouncilDemocracyConfigParams::<BlockNumberFor<T>>::default(),
                domain_block_pruning_depth: BlockNumberFor::<T>::from(
                    DEFAULT_GENESIS_PARAMS.domain_block_pruning_depth,
                ),
                staking_withdrawal_period: BlockNumberFor::<T>::from(
                    DEFAULT_GENESIS_PARAMS.staking_withdrawal_period,
                ),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            let Self {
                enable_domains,
                enable_dynamic_cost_of_storage,
                enable_balance_transfers,
                confirmation_depth_k,
                council_democracy_config_params,
                domain_block_pruning_depth,
                staking_withdrawal_period,
            } = self;

            assert!(
                !confirmation_depth_k.is_zero(),
                "ConfirmationDepthK can not be zero"
            );

            assert!(
                staking_withdrawal_period >= domain_block_pruning_depth,
                "Stake Withdrawal locking period must be >= Block tree pruning depth"
            );

            <EnableDomains<T>>::put(enable_domains);
            <EnableDynamicCostOfStorage<T>>::put(enable_dynamic_cost_of_storage);
            <EnableBalanceTransfers<T>>::put(enable_balance_transfers);
            <ConfirmationDepthK<T>>::put(confirmation_depth_k);
            CouncilDemocracyConfig::<T>::put(council_democracy_config_params);
            DomainBlockPruningDepth::<T>::put(domain_block_pruning_depth);
            StakingWithdrawalPeriod::<T>::put(staking_withdrawal_period);
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Change enable domains state.
        #[pallet::call_index(0)]
        #[pallet::weight(< T as Config >::WeightInfo::set_enable_domains())]
        pub fn set_enable_domains(origin: OriginFor<T>, enable_domains: bool) -> DispatchResult {
            ensure_root(origin)?;

            EnableDomains::<T>::put(enable_domains);

            Ok(())
        }

        /// Enable or disable dynamic cost of storage.
        #[pallet::call_index(1)]
        #[pallet::weight(< T as Config >::WeightInfo::set_enable_dynamic_cost_of_storage())]
        pub fn set_enable_dynamic_cost_of_storage(
            origin: OriginFor<T>,
            enable_dynamic_cost_of_storage: bool,
        ) -> DispatchResult {
            ensure_root(origin)?;

            EnableDynamicCostOfStorage::<T>::put(enable_dynamic_cost_of_storage);

            Ok(())
        }

        /// Enable or disable balance transfers for all users.
        #[pallet::call_index(2)]
        #[pallet::weight(< T as Config >::WeightInfo::set_enable_balance_transfers())]
        pub fn set_enable_balance_transfers(
            origin: OriginFor<T>,
            enable_balance_transfers: bool,
        ) -> DispatchResult {
            ensure_root(origin)?;

            EnableBalanceTransfers::<T>::put(enable_balance_transfers);

            Ok(())
        }
    }
}

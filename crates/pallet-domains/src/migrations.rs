//! Migration module for pallet-domains
//!
//! TODO: remove this module after it has been deployed to Taurus.

use crate::{Config, Pallet};
use frame_support::migrations::VersionedMigration;
use frame_support::traits::UncheckedOnRuntimeUpgrade;
use frame_support::weights::Weight;

pub type VersionCheckedMigrateDomainsV4ToV5<T> = VersionedMigration<
    4,
    5,
    VersionUncheckedMigrateV4ToV5<T>,
    Pallet<T>,
    <T as frame_system::Config>::DbWeight,
>;

pub struct VersionUncheckedMigrateV4ToV5<T>(sp_std::marker::PhantomData<T>);
impl<T: Config> UncheckedOnRuntimeUpgrade for VersionUncheckedMigrateV4ToV5<T> {
    fn on_runtime_upgrade() -> Weight {
        domain_genesis_receipt::set_domain_genesis_receipt::<T>()
    }
}

mod domain_genesis_receipt {
    use super::Config;
    use crate::{DomainGenesisBlockExecutionReceipt, ExecutionReceiptOf};
    use hexlit::hex;
    use sp_core::{Get, H256};
    use sp_domains::DomainId;
    use sp_runtime::traits::{NumberFor, Zero};
    use sp_runtime::Weight;

    pub(super) fn set_domain_genesis_receipt<T: Config>() -> Weight {
        let taurus_genesis_hash = T::Hash::from(H256::from(hex!(
            "0x295aeafca762a304d92ee1505548695091f6082d3f0aa4d092ac3cd6397a6c5e"
        )));
        let genesis_hash = frame_system::Pallet::<T>::block_hash(NumberFor::<T::Block>::zero());
        if genesis_hash != taurus_genesis_hash {
            return Weight::zero();
        }

        let genesis_state_root = T::DomainHash::from(H256::from(hex!(
            "0x530eae1878202aa0ab5997eadf2b7245ee78f44a35ab25ff84151fab489aa334"
        )));

        let genesis_block_hash = T::DomainHash::from(H256::from(hex!(
            "0x5a367ed131b9d8807f0166651095a9ed51aefa9aaec3152d3eb5cee322220ce6"
        )));

        let domain_0_genesis_er = ExecutionReceiptOf::<T>::genesis(
            genesis_state_root,
            sp_domains::EMPTY_EXTRINSIC_ROOT.into(),
            genesis_block_hash,
        );

        DomainGenesisBlockExecutionReceipt::<T>::insert(DomainId::new(0), domain_0_genesis_er);

        T::DbWeight::get().reads_writes(0, 1)
    }
}

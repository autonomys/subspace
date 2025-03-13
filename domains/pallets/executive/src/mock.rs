// TODO: remove when upstream issue is fixed
#![allow(
    non_camel_case_types,
    reason = "https://github.com/rust-lang/rust-analyzer/issues/16514"
)]

use crate as pallet_executive;
use crate::Config;
use frame_support::dispatch::DispatchInfo;
use frame_support::weights::IdentityFee;
use frame_support::{derive_impl, parameter_types};
use frame_system::mocking::MockUncheckedExtrinsic;
use pallet_balances::AccountData;
use sp_runtime::transaction_validity::TransactionValidityError;
use sp_runtime::BuildStorage;
use subspace_runtime_primitives::DomainEventSegmentSize;

type Block = frame_system::mocking::MockBlock<MockRuntime>;
pub(crate) type Balance = u64;
pub(crate) type AccountId = u64;

frame_support::construct_runtime!(
    pub struct MockRuntime {
        System: frame_system,
        Executive: pallet_executive,
        Balances: pallet_balances,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for MockRuntime {
    type Block = Block;
    type AccountData = AccountData<Balance>;
    type EventSegmentSize = DomainEventSegmentSize;
}

parameter_types! {
    pub const MaxHolds: u32 = 10;
    pub const ExistentialDeposit: Balance = 1;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig as pallet_balances::DefaultConfig)]
impl pallet_balances::Config for MockRuntime {
    type Balance = Balance;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
}

pub struct ExtrinsicStorageFees;
impl crate::ExtrinsicStorageFees<MockRuntime> for ExtrinsicStorageFees {
    fn extract_signer(
        _xt: MockUncheckedExtrinsic<MockRuntime>,
    ) -> (Option<AccountId>, DispatchInfo) {
        (None, DispatchInfo::default())
    }

    fn on_storage_fees_charged(
        _charged_fees: Balance,
        _tx_size: u32,
    ) -> Result<(), TransactionValidityError> {
        Ok(())
    }
}

impl Config for MockRuntime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type Currency = Balances;
    type LengthToFee = IdentityFee<Balance>;
    type ExtrinsicStorageFees = ExtrinsicStorageFees;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<MockRuntime>::default()
        .build_storage()
        .unwrap();

    let mut t: sp_io::TestExternalities = t.into();
    t.execute_with(|| System::set_block_number(1));
    t
}

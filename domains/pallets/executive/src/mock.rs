use crate as pallet_executive;
use crate::Config;
use frame_support::dispatch::DispatchInfo;
use frame_support::parameter_types;
use frame_support::traits::{ConstU16, ConstU32, ConstU64};
use frame_support::weights::IdentityFee;
use frame_system::mocking::MockUncheckedExtrinsic;
use pallet_balances::AccountData;
use sp_core::storage::StateVersion;
use sp_core::H256;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_runtime::BuildStorage;

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

parameter_types! {
    pub const ExtrinsicsRootStateVersion: StateVersion = StateVersion::V0;
}

impl frame_system::Config for MockRuntime {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Nonce = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = Block;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
    type ExtrinsicsRootStateVersion = ExtrinsicsRootStateVersion;
}

parameter_types! {
    pub const MaxHolds: u32 = 10;
    pub const ExistentialDeposit: Balance = 1;
}

impl pallet_balances::Config for MockRuntime {
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 8];
    type Balance = Balance;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type WeightInfo = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type RuntimeHoldReason = ();
    type MaxHolds = MaxHolds;
}

pub struct ExtrinsicStorageFees;
impl crate::ExtrinsicStorageFees<MockRuntime> for ExtrinsicStorageFees {
    fn extract_signer(
        _xt: MockUncheckedExtrinsic<MockRuntime>,
    ) -> (Option<AccountId>, DispatchInfo) {
        (None, DispatchInfo::default())
    }

    fn on_storage_fees_charged(_charged_fees: Balance) {}
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

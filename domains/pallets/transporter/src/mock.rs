use crate as pallet_transporter;
use crate::Config;
use frame_support::parameter_types;
use frame_support::traits::{ConstU16, ConstU32, ConstU64};
use pallet_balances::AccountData;
use sp_core::H256;
use sp_domains::DomainId;
use sp_messenger::endpoint::{EndpointId, EndpointRequest, Sender};
use sp_runtime::testing::Header;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_runtime::DispatchError;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<MockRuntime>;
type Block = frame_system::mocking::MockBlock<MockRuntime>;
pub(crate) type Balance = u64;
pub(crate) type AccountId = u64;

frame_support::construct_runtime!(
    pub struct MockRuntime where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        Balances: pallet_balances::{Pallet, Call, Config<T>, Storage, Event<T>},
        Transporter: pallet_transporter::{Pallet, Call, Storage, Event<T>},
    }
);

impl frame_system::Config for MockRuntime {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
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
}

parameter_types! {
    pub const ExistentialDeposit: u64 = 1;
}

impl pallet_balances::Config for MockRuntime {
    type AccountStore = System;
    type Balance = Balance;
    type DustRemoval = ();
    type RuntimeEvent = RuntimeEvent;
    type ExistentialDeposit = ExistentialDeposit;
    type MaxLocks = ();
    type MaxReserves = ();
    type ReserveIdentifier = ();
    type WeightInfo = ();
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type HoldIdentifier = ();
    type MaxHolds = ();
}

parameter_types! {
    pub const SelfDomainId: DomainId = DomainId::new(1);
    pub const SelfEndpointId: EndpointId = 100;
}

#[derive(Debug)]
pub struct MockMessenger {}
impl Sender<AccountId> for MockMessenger {
    type MessageId = u64;

    fn send_message(
        _sender: &AccountId,
        _dst_domain_id: DomainId,
        _req: EndpointRequest,
    ) -> Result<Self::MessageId, DispatchError> {
        Ok(0)
    }
}

impl Config for MockRuntime {
    type RuntimeEvent = RuntimeEvent;
    type SelfDomainId = SelfDomainId;
    type SelfEndpointId = SelfEndpointId;
    type Currency = Balances;
    type Sender = MockMessenger;
}

pub const USER_ACCOUNT: AccountId = 1;
pub const USER_INITIAL_BALANCE: Balance = 1000;

pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::default()
        .build_storage::<MockRuntime>()
        .unwrap();

    pallet_balances::GenesisConfig::<MockRuntime> {
        balances: vec![(USER_ACCOUNT, USER_INITIAL_BALANCE)],
    }
    .assimilate_storage(&mut t)
    .unwrap();

    let mut t: sp_io::TestExternalities = t.into();
    t.execute_with(|| System::set_block_number(1));
    t
}

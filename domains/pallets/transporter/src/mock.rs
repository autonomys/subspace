use crate as pallet_transporter;
use crate::{Config, TryConvertBack};
use codec::{Decode, Encode};
use domain_runtime_primitives::MultiAccountId;
use frame_support::parameter_types;
use frame_support::traits::{ConstU16, ConstU32, ConstU64};
use pallet_balances::AccountData;
use sp_core::storage::StateVersion;
use sp_core::H256;
use sp_messenger::endpoint::{EndpointId, EndpointRequest, Sender};
use sp_messenger::messages::ChainId;
use sp_runtime::traits::{BlakeTwo256, Convert, IdentityLookup};
use sp_runtime::{BuildStorage, DispatchError};

type Block = frame_system::mocking::MockBlock<MockRuntime>;
pub(crate) type Balance = u64;
pub(crate) type AccountId = u64;

frame_support::construct_runtime!(
    pub struct MockRuntime {
        System: frame_system,
        Balances: pallet_balances,
        Transporter: pallet_transporter,
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
    type RuntimeHoldReason = ();
    type MaxHolds = ();
}

parameter_types! {
    pub SelfChainId: ChainId = 1.into();
    pub const SelfEndpointId: EndpointId = 100;
}

#[derive(Debug)]
pub struct MockMessenger {}

impl Sender<AccountId> for MockMessenger {
    type MessageId = u64;

    fn send_message(
        _sender: &AccountId,
        _dst_chain_id: ChainId,
        _req: EndpointRequest,
    ) -> Result<Self::MessageId, DispatchError> {
        Ok(0)
    }

    #[cfg(feature = "runtime-benchmarks")]
    fn unchecked_open_channel(_dst_chain_id: ChainId) -> Result<(), DispatchError> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct MockAccountIdConverter;

impl Convert<AccountId, MultiAccountId> for MockAccountIdConverter {
    fn convert(account_id: AccountId) -> MultiAccountId {
        MultiAccountId::Raw(account_id.encode())
    }
}

impl TryConvertBack<AccountId, MultiAccountId> for MockAccountIdConverter {
    fn try_convert_back(multi_account_id: MultiAccountId) -> Option<AccountId> {
        match multi_account_id {
            MultiAccountId::Raw(data) => AccountId::decode(&mut data.as_slice()).ok(),
            _ => None,
        }
    }
}

impl Config for MockRuntime {
    type RuntimeEvent = RuntimeEvent;
    type SelfChainId = SelfChainId;
    type SelfEndpointId = SelfEndpointId;
    type Currency = Balances;
    type Sender = MockMessenger;
    type AccountIdConverter = MockAccountIdConverter;
    type WeightInfo = ();
}

pub const USER_ACCOUNT: AccountId = 1;
pub const USER_INITIAL_BALANCE: Balance = 1000;

pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<MockRuntime>::default()
        .build_storage()
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

use crate as pallet_transporter;
use crate::{Config, TryConvertBack};
use codec::{Decode, Encode};
use domain_runtime_primitives::MultiAccountId;
use frame_support::{derive_impl, parameter_types};
use frame_system::DefaultConfig;
use pallet_balances::AccountData;
use sp_messenger::endpoint::{EndpointId, EndpointRequest, Sender};
use sp_messenger::messages::ChainId;
use sp_runtime::traits::{Convert, IdentityLookup};
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

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for MockRuntime {
    type Block = Block;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type AccountData = AccountData<Balance>;
}

parameter_types! {
    pub const ExistentialDeposit: u64 = 1;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig as pallet_balances::DefaultConfig)]
impl pallet_balances::Config for MockRuntime {
    type AccountStore = System;
    type Balance = Balance;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
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

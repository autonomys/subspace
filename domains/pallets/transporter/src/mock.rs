use crate as pallet_transporter;
use crate::{Config, TryConvertBack};
use domain_runtime_primitives::{HoldIdentifier, MultiAccountId};
use frame_support::pallet_prelude::{MaxEncodedLen, TypeInfo};
use frame_support::traits::VariantCount;
use frame_support::{derive_impl, parameter_types};
use pallet_balances::AccountData;
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode};
use sp_core::U256;
use sp_domains::DomainId;
use sp_messenger::endpoint::{Endpoint, EndpointHandler, EndpointId, EndpointRequest, Sender};
use sp_messenger::messages::{ChainId, MessageId};
use sp_runtime::traits::{Convert, IdentityLookup};
use sp_runtime::{BuildStorage, DispatchError, Perbill};
use subspace_runtime_primitives::DomainEventSegmentSize;

type Block = frame_system::mocking::MockBlock<MockRuntime>;
pub(crate) type Balance = u64;
pub(crate) type AccountId = u64;

frame_support::construct_runtime!(
    pub struct MockRuntime {
        System: frame_system,
        Balances: pallet_balances,
        Transporter: pallet_transporter,
        Messenger: pallet_messenger,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for MockRuntime {
    type Block = Block;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type AccountData = AccountData<Balance>;
    type EventSegmentSize = DomainEventSegmentSize;
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
    type RuntimeHoldReason = MockHoldIdentifier;
}

parameter_types! {
    pub SelfChainId: ChainId = 1.into();
    pub const SelfEndpointId: EndpointId = 100;
    pub const ChannelReserveFee: Balance = 10;
    pub const ChannelInitReservePortion: Perbill = Perbill::from_percent(20);
    pub TransactionWeightFee: Balance = 100_000;
    pub const MaxOutgoingMessages: u32 = 25;
    pub const FeeMultiplier: u32 = 1;
}

#[derive(
    PartialEq,
    Eq,
    Clone,
    Encode,
    Decode,
    TypeInfo,
    MaxEncodedLen,
    Ord,
    PartialOrd,
    Copy,
    Debug,
    DecodeWithMemTracking,
)]
pub enum MockHoldIdentifier {
    Messenger(HoldIdentifier),
}

impl VariantCount for MockHoldIdentifier {
    const VARIANT_COUNT: u32 = 1u32;
}

#[derive(Debug)]
pub struct DomainRegistration;
impl sp_messenger::DomainRegistration for DomainRegistration {
    fn is_domain_registered(_domain_id: DomainId) -> bool {
        true
    }
}

impl pallet_messenger::HoldIdentifier<MockRuntime> for MockHoldIdentifier {
    fn messenger_channel() -> Self {
        MockHoldIdentifier::Messenger(HoldIdentifier::MessengerChannel)
    }
}

impl pallet_messenger::Config for MockRuntime {
    type RuntimeEvent = RuntimeEvent;
    type SelfChainId = SelfChainId;
    type Currency = Balances;
    type WeightInfo = ();
    type WeightToFee = frame_support::weights::ConstantMultiplier<u64, TransactionWeightFee>;
    type OnXDMRewards = ();
    type MmrHash = sp_core::H256;
    type MmrProofVerifier = ();
    type StorageKeys = ();
    type DomainOwner = ();
    type ChannelReserveFee = ChannelReserveFee;
    type ChannelInitReservePortion = ChannelInitReservePortion;
    type HoldIdentifier = MockHoldIdentifier;
    type DomainRegistration = DomainRegistration;
    type MaxOutgoingMessages = MaxOutgoingMessages;
    type ExtensionWeightInfo =
        pallet_messenger::extensions::weights::SubstrateWeight<MockRuntime, (), ()>;
    /// function to fetch endpoint response handler by Endpoint.
    fn get_endpoint_handler(_endpoint: &Endpoint) -> Option<Box<dyn EndpointHandler<MessageId>>> {
        #[cfg(feature = "runtime-benchmarks")]
        return Some(Box::new(crate::EndpointHandler::<MockRuntime>(
            core::marker::PhantomData,
        )));

        #[cfg(not(feature = "runtime-benchmarks"))]
        None
    }

    type MessengerOrigin = pallet_messenger::EnsureMessengerOrigin;
    type AdjustedWeightToFee =
        frame_support::weights::ConstantMultiplier<u64, TransactionWeightFee>;
    type FeeMultiplier = FeeMultiplier;
    type NoteChainTransfer = Transporter;
}

#[derive(Debug)]
pub struct MockMessenger {}

impl Sender<AccountId> for MockMessenger {
    type MessageId = MessageId;

    fn send_message(
        _sender: &AccountId,
        _dst_chain_id: ChainId,
        _req: EndpointRequest,
    ) -> Result<Self::MessageId, DispatchError> {
        Ok((U256::zero(), U256::zero()))
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

parameter_types! {
    pub const MinimumTransfer: Balance = 1;
}

impl Config for MockRuntime {
    type RuntimeEvent = RuntimeEvent;
    type SelfChainId = SelfChainId;
    type SelfEndpointId = SelfEndpointId;
    type Currency = Balances;
    #[cfg(not(feature = "runtime-benchmarks"))]
    type Sender = MockMessenger;
    #[cfg(feature = "runtime-benchmarks")]
    type Sender = Messenger;
    type AccountIdConverter = MockAccountIdConverter;
    type WeightInfo = ();
    type MinimumTransfer = MinimumTransfer;
}

pub const USER_ACCOUNT: AccountId = 1;
pub const USER_INITIAL_BALANCE: Balance = 1000;

pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut t = frame_system::GenesisConfig::<MockRuntime>::default()
        .build_storage()
        .unwrap();

    pallet_balances::GenesisConfig::<MockRuntime> {
        balances: vec![(USER_ACCOUNT, USER_INITIAL_BALANCE)],
        dev_accounts: None,
    }
    .assimilate_storage(&mut t)
    .unwrap();

    let mut t: sp_io::TestExternalities = t.into();
    t.execute_with(|| System::set_block_number(1));
    t
}

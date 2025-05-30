//! Mock runtime for benchmarks.

use crate as pallet_evm_tracker;
use crate::traits::{MaybeIntoEthCall, MaybeIntoEvmCall};
use crate::EthereumAccountId;
use frame_support::{derive_impl, parameter_types};
use frame_system::pallet_prelude::RuntimeCallFor;
use pallet_balances::AccountData;
use pallet_ethereum::PostLogContent;
use pallet_evm::config_preludes::FindAuthorTruncated;
use pallet_evm::{
    EVMCurrencyAdapter, EnsureAddressNever, EnsureAddressRoot, IdentityAddressMapping,
};
use sp_evm_tracker::{BlockGasLimit, GasLimitPovSizeRatio, WeightPerGas};
use sp_runtime::traits::{ConstU32, IdentityLookup};
use subspace_runtime_primitives::utility::{MaybeNestedCall, MaybeUtilityCall};
use subspace_runtime_primitives::{DomainEventSegmentSize, SHANNON};

type Block = frame_system::mocking::MockBlock<MockRuntime>;
pub(crate) type Balance = u128;
pub(crate) type AccountId = EthereumAccountId;

frame_support::construct_runtime!(
    pub struct MockRuntime {
        System: frame_system,
        Balances: pallet_balances,
        Timestamp: pallet_timestamp,

        // for nested calls
        Utility: pallet_utility,

        // evm stuff
        Ethereum: pallet_ethereum,
        EVM: pallet_evm,
        EVMNoncetracker: pallet_evm_tracker,
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
    type RuntimeHoldReason = ();
}

impl pallet_timestamp::Config for MockRuntime {
    type Moment = u128;
    type OnTimestampSet = ();
    type MinimumPeriod = ();
    type WeightInfo = ();
}

impl pallet_utility::Config for MockRuntime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type PalletsOrigin = OriginCaller;
    type WeightInfo = pallet_utility::weights::SubstrateWeight<Self>;
}

impl MaybeUtilityCall<MockRuntime> for RuntimeCall {
    /// If this call is a `pallet_utility::Call<MockRuntime>` call, returns the inner call.
    fn maybe_utility_call(&self) -> Option<&pallet_utility::Call<MockRuntime>> {
        match self {
            RuntimeCall::Utility(call) => Some(call),
            _ => None,
        }
    }
}

impl MaybeNestedCall<MockRuntime> for RuntimeCall {
    /// If this call is a nested runtime call, returns the inner call(s).
    ///
    /// Ignored calls (such as `pallet_utility::Call::__Ignore`) should be yielded themsevles, but
    /// their contents should not be yielded.
    fn maybe_nested_call(&self) -> Option<Vec<&RuntimeCallFor<MockRuntime>>> {
        // We currently ignore privileged calls, because privileged users can already change
        // runtime code. Domain sudo `RuntimeCall`s also have to pass inherent validation.
        self.maybe_nested_utility_calls()
    }
}

parameter_types! {
    pub const PostOnlyBlockHash: PostLogContent = PostLogContent::OnlyBlockHash;
}

impl pallet_ethereum::Config for MockRuntime {
    type RuntimeEvent = RuntimeEvent;
    type StateRoot = pallet_ethereum::IntermediateStateRoot<Self::Version>;
    type PostLogContent = PostOnlyBlockHash;
    type ExtraDataLength = ConstU32<30>;
}

impl MaybeIntoEthCall<MockRuntime> for RuntimeCall {
    /// If this call is a `pallet_ethereum::Call<MockRuntime>` call, returns the inner call.
    fn maybe_into_eth_call(&self) -> Option<&pallet_ethereum::Call<MockRuntime>> {
        match self {
            RuntimeCall::Ethereum(call) => Some(call),
            _ => None,
        }
    }
}

parameter_types! {
    pub const OperationalFeeMultiplier: u8 = 5;
    pub const DomainChainByteFee: Balance = 100_000 * SHANNON;
    pub TransactionWeightFee: Balance = 100_000 * SHANNON;
}

impl pallet_evm::Config for MockRuntime {
    type AccountProvider = pallet_evm::FrameSystemAccountProvider<Self>;
    type FeeCalculator = ();
    type GasWeightMapping = pallet_evm::FixedGasWeightMapping<Self>;
    type WeightPerGas = WeightPerGas;
    type BlockHashMapping = pallet_ethereum::EthereumBlockHashMapping<Self>;
    type CallOrigin = EnsureAddressRoot<AccountId>;
    type WithdrawOrigin = EnsureAddressNever<AccountId>;
    type AddressMapping = IdentityAddressMapping;
    type Currency = Balances;
    type RuntimeEvent = RuntimeEvent;
    type PrecompilesType = ();
    type PrecompilesValue = ();
    type ChainId = ();
    type BlockGasLimit = BlockGasLimit;
    type Runner = pallet_evm::runner::stack::Runner<Self>;
    type OnChargeTransaction = EVMCurrencyAdapter<Balances, ()>;
    type OnCreate = ();
    type FindAuthor = FindAuthorTruncated;
    type GasLimitPovSizeRatio = GasLimitPovSizeRatio;
    type GasLimitStorageGrowthRatio = ();
    type Timestamp = Timestamp;
    type WeightInfo = pallet_evm::weights::SubstrateWeight<Self>;
}

impl MaybeIntoEvmCall<MockRuntime> for RuntimeCall {
    /// If this call is a `pallet_evm::Call<MockRuntime>` call, returns the inner call.
    fn maybe_into_evm_call(&self) -> Option<&pallet_evm::Call<MockRuntime>> {
        match self {
            RuntimeCall::EVM(call) => Some(call),
            _ => None,
        }
    }
}

impl pallet_evm_tracker::Config for MockRuntime {}

#[cfg(test)]
pub fn new_test_ext() -> sp_io::TestExternalities {
    use sp_runtime::BuildStorage;

    let t = frame_system::GenesisConfig::<MockRuntime>::default()
        .build_storage()
        .unwrap();

    let mut t: sp_io::TestExternalities = t.into();
    t.execute_with(|| System::set_block_number(1));
    t
}

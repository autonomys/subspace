use crate::{ChannelId, Channels, Config, InboxResponses, Nonce, Outbox, StateRootOf};
use frame_support::storage::generator::StorageDoubleMap;
use frame_support::weights::Weight;
use sp_core::storage::StorageKey;
use sp_messenger::endpoint::{EndpointHandler, EndpointRequest, EndpointResponse};
use sp_messenger::messages::ChainId;
use sp_runtime::traits::BlakeTwo256;
use sp_runtime::DispatchResult;
use sp_state_machine::backend::Backend;
use sp_state_machine::{prove_read, InMemoryBackend};
use sp_trie::StorageProof;

pub(crate) type Balance = u64;
pub(crate) type AccountId = u64;

pub type TestExternalities = sp_state_machine::TestExternalities<BlakeTwo256>;

macro_rules! impl_runtime {
    ($runtime:ty, $chain_id:expr) => {
        #[cfg(not(feature = "runtime-benchmarks"))]
        use crate::mock::MockEndpoint;
        use crate::mock::{AccountId, Balance, MessageId, TestExternalities};
        use codec::{Decode, Encode};
        use domain_runtime_primitives::{MultiAccountId, TryConvertBack, HoldIdentifier};
        #[cfg(not(feature = "runtime-benchmarks"))]
        use frame_support::pallet_prelude::*;
        use frame_support::{derive_impl, parameter_types};
        use pallet_balances::AccountData;
        use sp_core::H256;
        use sp_messenger::endpoint::{Endpoint, EndpointHandler, EndpointId};
        use sp_messenger::messages::{ChainId, FeeModel};
        use sp_runtime::traits::Convert;
        use sp_runtime::BuildStorage;
        use scale_info::TypeInfo;
        use codec::MaxEncodedLen;
        use frame_support::traits::VariantCount;
        use core::mem;
        use sp_runtime::Perbill;
        use sp_domains::DomainId;

        type Block = frame_system::mocking::MockBlock<Runtime>;

        frame_support::construct_runtime!(
            pub struct Runtime {
                System: frame_system,
                Messenger: crate exclude_parts{ Inherent },
                Balances: pallet_balances,
                Transporter: pallet_transporter,
            }
        );

        #[derive_impl(frame_system::config_preludes::TestDefaultConfig )]
        impl frame_system::Config for $runtime {
            type Block = Block;
            type AccountData = AccountData<Balance>;
        }

        parameter_types! {
            pub SelfChainId: ChainId = $chain_id.into();
            pub const ChannelReserveFee: Balance = 10;
            pub const ChannelInitReservePortion: Perbill = Perbill::from_percent(20);
            pub const ChannelFeeModel: FeeModel<Balance> = FeeModel{relay_fee: 1};
        }

        #[derive(
            PartialEq, Eq, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Ord, PartialOrd, Copy, Debug,
        )]
        pub enum MockHoldIdentifer {
            Messenger(HoldIdentifier)
        }

        impl VariantCount for MockHoldIdentifer {
            const VARIANT_COUNT: u32 = mem::variant_count::<HoldIdentifier>() as u32;
        }

        impl crate::HoldIdentifier<$runtime> for MockHoldIdentifer {
            fn messenger_channel() -> Self {
                MockHoldIdentifer::Messenger(HoldIdentifier::MessengerChannel)
            }
        }

        pub struct DomainRegistration;
        impl sp_messenger::DomainRegistration for DomainRegistration {
            fn is_domain_registered(_domain_id: DomainId) -> bool {
                true
            }
        }

        impl crate::Config for $runtime {
            type RuntimeEvent = RuntimeEvent;
            type SelfChainId = SelfChainId;
            type Currency = Balances;
            type WeightInfo = ();
            type WeightToFee = frame_support::weights::IdentityFee<u64>;
            type OnXDMRewards = ();
            type MmrHash = H256;
            type MmrProofVerifier = ();
            type StorageKeys = ();
            type DomainOwner = ();
            type ChannelReserveFee = ChannelReserveFee;
            type ChannelInitReservePortion = ChannelInitReservePortion;
            type HoldIdentifier = MockHoldIdentifer;
            type DomainRegistration = DomainRegistration;
            type ChannelFeeModel = ChannelFeeModel;
            /// function to fetch endpoint response handler by Endpoint.
            fn get_endpoint_handler(
                #[allow(unused_variables)] endpoint: &Endpoint,
            ) -> Option<Box<dyn EndpointHandler<MessageId>>> {
                // Return a dummy handler for benchmark to observe the outer weight when processing cross chain
                // message (i.e. updating the `next_nonce` of the channel, assigning msg to the relayer, etc.)
                #[cfg(feature = "runtime-benchmarks")]
                {
                    return Some(Box::new(sp_messenger::endpoint::BenchmarkEndpointHandler));
                }

                #[cfg(not(feature = "runtime-benchmarks"))]
                match endpoint {
                    Endpoint::Id(id) => match id {
                        100 => Some(Box::new(pallet_transporter::EndpointHandler(
                            PhantomData::<$runtime>,
                        ))),
                        _ => Some(Box::new(MockEndpoint {})),
                    },
                }
            }
        }

        parameter_types! {
            pub const MaxHolds: u32 = 10;
            pub const ExistentialDeposit: u64 = 1;
        }

        #[derive_impl(pallet_balances::config_preludes::TestDefaultConfig as pallet_balances::DefaultConfig)]
        impl pallet_balances::Config for $runtime {
            type AccountStore = System;
            type Balance = Balance;
            type DustRemoval = ();
            type ExistentialDeposit = ExistentialDeposit;
            type RuntimeHoldReason = MockHoldIdentifer;
        }

        parameter_types! {
            pub const TransporterEndpointId: EndpointId = 100;
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

        impl pallet_transporter::Config for $runtime {
            type RuntimeEvent = RuntimeEvent;
            type SelfChainId = SelfChainId;
            type SelfEndpointId = TransporterEndpointId;
            type Currency = Balances;
            type Sender = Messenger;
            type AccountIdConverter = MockAccountIdConverter;
            type WeightInfo = ();
        }

        pub const USER_ACCOUNT: AccountId = 1;
        pub const USER_INITIAL_BALANCE: Balance = 500000000;

        pub fn new_test_ext() -> TestExternalities {
            let mut t = frame_system::GenesisConfig::<Runtime>::default()
                .build_storage()
                .unwrap();

            pallet_balances::GenesisConfig::<$runtime> {
                balances: vec![(USER_ACCOUNT, USER_INITIAL_BALANCE)],
            }
            .assimilate_storage(&mut t)
            .unwrap();

            let mut t: TestExternalities = t.into();
            t.execute_with(|| System::set_block_number(1));
            t
        }
    };
}

pub(crate) type MessageId = (ChannelId, Nonce);

pub struct MockEndpoint {}

impl EndpointHandler<MessageId> for MockEndpoint {
    fn message(
        &self,
        _src_chain_id: ChainId,
        _message_id: MessageId,
        req: EndpointRequest,
    ) -> EndpointResponse {
        let req = req.payload;
        assert_eq!(req, vec![1, 2, 3, 4]);
        Ok(vec![5, 6, 7, 8])
    }

    fn message_weight(&self) -> Weight {
        Weight::zero()
    }

    fn message_response(
        &self,
        _dst_chain_id: ChainId,
        _message_id: MessageId,
        _req: EndpointRequest,
        resp: EndpointResponse,
    ) -> DispatchResult {
        let resp = resp.unwrap();
        assert_eq!(resp, vec![5, 6, 7, 8]);
        Ok(())
    }

    fn message_response_weight(&self) -> Weight {
        Weight::zero()
    }
}

pub(crate) mod chain_a {
    impl_runtime!(Runtime, ChainId::Domain(1.into()));
}

pub(crate) mod chain_b {
    impl_runtime!(Runtime, ChainId::Domain(2.into()));
}

pub(crate) mod consensus_chain {
    impl_runtime!(Runtime, ChainId::Consensus);
}

fn storage_proof_for_key<T: Config>(
    backend: InMemoryBackend<T::Hashing>,
    key: StorageKey,
) -> (StateRootOf<T>, StorageProof) {
    let state_version = sp_runtime::StateVersion::default();
    let root = backend.storage_root(std::iter::empty(), state_version).0;
    let proof = StorageProof::new(prove_read(backend, &[key]).unwrap().iter_nodes().cloned());
    (root, proof)
}

pub(crate) fn storage_proof_of_channels<T: Config>(
    backend: InMemoryBackend<T::Hashing>,
    chain_id: ChainId,
    channel_id: ChannelId,
) -> (StateRootOf<T>, StorageKey, StorageProof) {
    let key = Channels::<T>::storage_double_map_final_key(chain_id, channel_id);
    let storage_key = StorageKey(key);
    let (root, proof) = storage_proof_for_key::<T>(backend, storage_key.clone());
    (root, storage_key, proof)
}

pub(crate) fn storage_proof_of_outbox_messages<T: Config>(
    backend: InMemoryBackend<T::Hashing>,
    chain_id: ChainId,
    channel_id: ChannelId,
    nonce: Nonce,
) -> (StateRootOf<T>, StorageKey, StorageProof) {
    let key = Outbox::<T>::hashed_key_for((chain_id, channel_id, nonce));
    let storage_key = StorageKey(key);
    let (root, proof) = storage_proof_for_key::<T>(backend, storage_key.clone());
    (root, storage_key, proof)
}

pub(crate) fn storage_proof_of_inbox_message_responses<T: Config>(
    backend: InMemoryBackend<T::Hashing>,
    chain_id: ChainId,
    channel_id: ChannelId,
    nonce: Nonce,
) -> (StateRootOf<T>, StorageKey, StorageProof) {
    let key = InboxResponses::<T>::hashed_key_for((chain_id, channel_id, nonce));
    let storage_key = StorageKey(key);
    let (root, proof) = storage_proof_for_key::<T>(backend, storage_key.clone());
    (root, storage_key, proof)
}

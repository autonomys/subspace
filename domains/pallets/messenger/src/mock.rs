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
    ($runtime:ty, $chain_id:literal) => {
        use crate::mock::{AccountId, Balance, MessageId, MockEndpoint, TestExternalities};
        use codec::{Decode, Encode};
        use domain_runtime_primitives::{MultiAccountId, TryConvertBack};
        use frame_support::pallet_prelude::*;
        use frame_support::parameter_types;
        use pallet_balances::AccountData;
        use sp_core::H256;
        use sp_messenger::endpoint::{Endpoint, EndpointHandler, EndpointId};
        use sp_messenger::messages::ChainId;
        use sp_runtime::traits::{
            BlakeTwo256, ConstU16, ConstU32, ConstU64, Convert, IdentityLookup,
        };
        use sp_runtime::BuildStorage;

        type Block = frame_system::mocking::MockBlock<Runtime>;

        frame_support::construct_runtime!(
            pub struct Runtime {
                System: frame_system,
                Messenger: crate,
                Balances: pallet_balances,
                Transporter: pallet_transporter,
            }
        );

        impl frame_system::Config for $runtime {
            type BaseCallFilter = frame_support::traits::Everything;
            type BlockWeights = ();
            type BlockLength = ();
            type DbWeight = ();
            type RuntimeOrigin = RuntimeOrigin;
            type RuntimeCall = RuntimeCall;
            type Nonce = u64;
            type Hash = H256;
            type Hashing = BlakeTwo256;
            type AccountId = u64;
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
        }

        parameter_types! {
            pub const ExistentialDeposit: u64 = 1;
        }

        parameter_types! {
            pub const ConfirmedStateRootsBound: u32 = 2;
            pub const RelayerConfirmationDepth: u64 = 2;
        }

        parameter_types! {
            pub SelfChainId: ChainId = $chain_id.into();
        }

        impl crate::Config for $runtime {
            type RuntimeEvent = RuntimeEvent;
            type SelfChainId = SelfChainId;
            type Currency = Balances;
            type ConfirmationDepth = RelayerConfirmationDepth;
            type DomainInfo = ();
            type WeightInfo = ();
            type WeightToFee = frame_support::weights::IdentityFee<u64>;
            type OnXDMRewards = ();
            /// function to fetch endpoint response handler by Endpoint.
            fn get_endpoint_handler(
                endpoint: &Endpoint,
            ) -> Option<Box<dyn EndpointHandler<MessageId>>> {
                // Return a dummy handler for benchmark to observe the outer weight when processing cross chain
                // message (i.e. updating the `next_nonce` of the channel, assigning msg to the relayer, etc.)
                #[cfg(feature = "runtime-benchmarks")]
                {
                    return Some(Box::new(sp_messenger::endpoint::BenchmarkEndpointHandler));
                }
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

        impl pallet_balances::Config for $runtime {
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
        pub const USER_INITIAL_BALANCE: Balance = 1000;

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
    impl_runtime!(Runtime, 1);
}

pub(crate) mod chain_b {
    impl_runtime!(Runtime, 2);
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

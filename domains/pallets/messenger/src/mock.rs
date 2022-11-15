use crate::{ChannelId, Channels, Config, InboxResponses, Nonce, Outbox, StateRootOf};
use frame_support::storage::generator::StorageDoubleMap;
use sp_core::storage::StorageKey;
use sp_domains::DomainId;
use sp_messenger::endpoint::{EndpointHandler, EndpointRequest, EndpointResponse};
use sp_runtime::traits::BlakeTwo256;
use sp_runtime::DispatchResult;
use sp_state_machine::backend::Backend;
use sp_state_machine::{prove_read, InMemoryBackend};
use sp_trie::StorageProof;

pub(crate) type Balance = u64;
pub(crate) type AccountId = u64;

pub type TestExternalities = sp_state_machine::TestExternalities<BlakeTwo256>;

macro_rules! impl_runtime {
    ($runtime:ty, $domain_id:literal) => {
        use crate::mock::{TestExternalities, MockEndpoint, MessageId, Balance, AccountId};
        use sp_domains::DomainId;
        use frame_support::parameter_types;
        use frame_support::pallet_prelude::PhantomData;
        use sp_core::H256;
        use sp_runtime::testing::Header;
        use sp_runtime::traits::{BlakeTwo256, ConstU16, ConstU32, ConstU64, IdentityLookup};
        use sp_std::vec::Vec;
        use sp_messenger::endpoint::{EndpointHandler, Endpoint, EndpointId};
        use pallet_balances::AccountData;
        use frame_support::assert_ok;
        use crate::relayer::RelayerId;

        type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Runtime>;
        type Block = frame_system::mocking::MockBlock<Runtime>;

        frame_support::construct_runtime!(
            pub struct Runtime where
                Block = Block,
                NodeBlock = Block,
                UncheckedExtrinsic = UncheckedExtrinsic,
            {
                System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
                DomainTracker: pallet_domain_tracker::{Pallet, Call, Storage, Event<T>},
                Messenger: crate::{Pallet, Call, Event<T>},
                Balances: pallet_balances::{Pallet, Call, Config<T>, Storage, Event<T>},
                Transporter: pallet_transporter::{Pallet, Call, Storage, Event<T>},
            }
        );


        impl frame_system::Config for $runtime {
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
            type AccountId = u64;
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

        parameter_types! {
            pub const StateRootsBound: u32 = 2;
        }

        impl pallet_domain_tracker::Config for $runtime {
            type RuntimeEvent = RuntimeEvent;
            type StateRootsBound = StateRootsBound;
        }

        parameter_types! {
            pub const SelfDomainId: DomainId = DomainId::new($domain_id);
            pub const MaximumRelayers: u32 = 10;
            pub const RelayerDeposit: Balance = 500;
        }

        impl crate::Config for $runtime {
            type RuntimeEvent = RuntimeEvent;
            type SelfDomainId = SelfDomainId;
            type DomainTracker = DomainTracker;
            type MaximumRelayers = MaximumRelayers;
            type Currency = Balances;
            type RelayerDeposit = RelayerDeposit;
            /// function to fetch endpoint response handler by Endpoint.
            fn get_endpoint_response_handler(
                endpoint: &Endpoint,
            ) -> Option<Box<dyn EndpointHandler<MessageId>>>{
                match endpoint {
                    Endpoint::Id(id) => match id {
                        100 => Some(Box::new(pallet_transporter::EndpointHandler(PhantomData::<$runtime>))),
                        _=> Some(Box::new(MockEndpoint{}))
                    }
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
        }

        parameter_types! {
            pub const TransporterEndpointId: EndpointId = 100;
        }

        impl pallet_transporter::Config for $runtime {
            type RuntimeEvent = RuntimeEvent;
            type SelfDomainId = SelfDomainId;
            type SelfEndpointId = TransporterEndpointId;
            type Currency = Balances;
            type Sender = Messenger;
        }

        pub const USER_ACCOUNT: AccountId = 1;
        pub const USER_INITIAL_BALANCE: Balance = 1000;
        pub const RELAYER_OWNER_ACCOUNT: AccountId = 200;
        pub const RELAYER_BALANCE: Balance = 1000;
        pub const RELAYER_ID: RelayerId<$runtime> = 300;

        pub fn new_test_ext() -> TestExternalities {
           let mut t = frame_system::GenesisConfig::default()
                    .build_storage::<Runtime>()
                    .unwrap();

           pallet_balances::GenesisConfig::<$runtime> {
                balances: vec![
                    (USER_ACCOUNT, USER_INITIAL_BALANCE),
                    (RELAYER_OWNER_ACCOUNT, RELAYER_BALANCE),
                ],
           }
            .assimilate_storage(&mut t)
            .unwrap();

           let mut t: TestExternalities = t.into();
           t.execute_with(|| System::set_block_number(1));

           // add a relayer to messenger
           t.execute_with(|| {
               let res = Messenger::join_relayer_set(RuntimeOrigin::signed(RELAYER_OWNER_ACCOUNT), RELAYER_ID);
               assert_ok!(res);
           });
           t
        }
    };
}

pub(crate) type MessageId = (ChannelId, Nonce);

pub struct MockEndpoint {}
impl EndpointHandler<MessageId> for MockEndpoint {
    fn message(
        &self,
        _src_domain_id: DomainId,
        _message_id: MessageId,
        req: EndpointRequest,
    ) -> EndpointResponse {
        let req = req.payload;
        assert_eq!(req, vec![1, 2, 3, 4]);
        Ok(vec![5, 6, 7, 8])
    }

    fn message_response(
        &self,
        _dst_domain_id: DomainId,
        _message_id: MessageId,
        _req: EndpointRequest,
        resp: EndpointResponse,
    ) -> DispatchResult {
        let resp = resp.unwrap();
        assert_eq!(resp, vec![5, 6, 7, 8]);
        Ok(())
    }
}

pub(crate) mod domain_a {
    impl_runtime!(Runtime, 1);
}

pub(crate) mod domain_b {
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
    domain_id: DomainId,
    channel_id: ChannelId,
) -> (StateRootOf<T>, StorageKey, StorageProof) {
    let key = Channels::<T>::storage_double_map_final_key(domain_id, channel_id);
    let storage_key = StorageKey(key);
    let (root, proof) = storage_proof_for_key::<T>(backend, storage_key.clone());
    (root, storage_key, proof)
}

pub(crate) fn storage_proof_of_outbox_messages<T: Config>(
    backend: InMemoryBackend<T::Hashing>,
    domain_id: DomainId,
    channel_id: ChannelId,
    nonce: Nonce,
) -> (StateRootOf<T>, StorageKey, StorageProof) {
    let key = Outbox::<T>::hashed_key_for((domain_id, channel_id, nonce));
    let storage_key = StorageKey(key);
    let (root, proof) = storage_proof_for_key::<T>(backend, storage_key.clone());
    (root, storage_key, proof)
}

pub(crate) fn storage_proof_of_inbox_message_responses<T: Config>(
    backend: InMemoryBackend<T::Hashing>,
    domain_id: DomainId,
    channel_id: ChannelId,
    nonce: Nonce,
) -> (StateRootOf<T>, StorageKey, StorageProof) {
    let key = InboxResponses::<T>::hashed_key_for((domain_id, channel_id, nonce));
    let storage_key = StorageKey(key);
    let (root, proof) = storage_proof_for_key::<T>(backend, storage_key.clone());
    (root, storage_key, proof)
}

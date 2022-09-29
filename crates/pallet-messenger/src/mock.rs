use crate::{ChannelId, Channels};
use frame_support::parameter_types;
use frame_support::storage::generator::StorageDoubleMap;
use frame_support::traits::{ConstU16, ConstU32, ConstU64};
use sp_core::storage::StorageKey;
use sp_core::H256;
use sp_runtime::testing::Header;
use sp_runtime::traits::{BlakeTwo256, IdentityLookup};
use sp_state_machine::backend::Backend;
use sp_state_machine::{prove_read, InMemoryBackend};
use sp_std::vec::Vec;
use sp_trie::StorageProof;

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub struct Test where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
        SystemDomainTracker: mock_system_domain_tracker::{Pallet, Storage},
        Messenger: crate::{Pallet, Call, Event<T>}
    }
);

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type Origin = Origin;
    type Call = Call;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = u64;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = Event;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
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

pub(crate) type DomainId = u64;

#[frame_support::pallet]
mod mock_system_domain_tracker {
    use frame_support::pallet_prelude::*;
    use sp_core::H256;
    use sp_messenger::SystemDomainTracker;

    #[pallet::config]
    pub trait Config: frame_system::Config {}

    /// Pallet messenger used to communicate between domains and other blockchains.
    #[pallet::pallet]
    #[pallet::generate_store(pub (super) trait Store)]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub(super) type StateRoot<T: Config> = StorageValue<_, H256, ValueQuery>;

    impl<T: Config> SystemDomainTracker<H256> for Pallet<T> {
        fn latest_state_roots() -> Vec<H256> {
            vec![StateRoot::<T>::get()]
        }
    }
}

impl mock_system_domain_tracker::Config for Test {}

impl crate::Config for Test {
    type Event = Event;
    type DomainId = DomainId;
    type SystemDomainTracker = SystemDomainTracker;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::default()
        .build_storage::<Test>()
        .unwrap();

    let mut t: sp_io::TestExternalities = t.into();
    t.execute_with(|| System::set_block_number(1));
    t
}

fn storage_proof_for_key(
    backend: InMemoryBackend<sp_core::Blake2Hasher>,
    key: StorageKey,
) -> (H256, StorageProof) {
    let state_version = sp_runtime::StateVersion::default();
    let root = backend.storage_root(std::iter::empty(), state_version).0;
    let proof = StorageProof::new(prove_read(backend, &[key]).unwrap().iter_nodes());
    (root, proof)
}

pub(crate) fn storage_proof_of_channels(
    backend: InMemoryBackend<sp_core::Blake2Hasher>,
    domain_id: DomainId,
    channel_id: ChannelId,
) -> (H256, StorageKey, StorageProof) {
    let key = Channels::<Test>::storage_double_map_final_key(domain_id, channel_id);
    let storage_key = StorageKey(key);
    let (root, proof) = storage_proof_for_key(backend, storage_key.clone());
    (root, storage_key, proof)
}

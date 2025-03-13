use crate::{self as pallet_domain_id};
use frame_support::derive_impl;
use sp_runtime::BuildStorage;
use subspace_runtime_primitives::DomainEventSegmentSize;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub struct Test {
        System: frame_system = 0,
        SelfDomainId: pallet_domain_id = 1,
    }
);

impl pallet_domain_id::Config for Test {}

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type EventSegmentSize = DomainEventSegmentSize;
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    t.into()
}

#[test]
fn test_domain_id_storage_key() {
    new_test_ext().execute_with(|| {
        assert_eq!(
            pallet_domain_id::SelfDomainId::<Test>::hashed_key().to_vec(),
            sp_domains::self_domain_id_storage_key().0
        );
    });
}

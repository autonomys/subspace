use frame_support::derive_impl;
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub struct Test {
        System: frame_system,
        ObjectStore: crate,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

impl crate::Config for Test {
    type RuntimeEvent = RuntimeEvent;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let t = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();

    let mut t: sp_io::TestExternalities = t.into();

    t.execute_with(|| System::set_block_number(1));

    t
}

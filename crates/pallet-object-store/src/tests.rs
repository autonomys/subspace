use crate::mock::{new_test_ext, ObjectStore, RuntimeEvent, RuntimeOrigin, System, Test};
use frame_support::assert_ok;
use subspace_core_primitives::crypto;

const ACCOUNT_ID: u64 = 100;

#[test]
fn can_do_put() {
    new_test_ext().execute_with(|| {
        let object = vec![1, 2, 3, 4, 5];
        let object_id = crypto::blake3_hash(&object);
        let object_size = object.len() as u32;

        assert_ok!(ObjectStore::put(RuntimeOrigin::signed(ACCOUNT_ID), object));

        System::assert_last_event(RuntimeEvent::ObjectStore(
            crate::Event::<Test>::ObjectSubmitted {
                who: ACCOUNT_ID,
                object_id,
                object_size,
            },
        ));
    });
}

use crate::mock::{new_test_ext, Event, ObjectStore, Origin, System, Test};
use frame_support::assert_ok;
use subspace_core_primitives::crypto;

const ACCOUNT_ID: u64 = 100;

#[test]
fn can_do_put() {
    new_test_ext().execute_with(|| {
        let object = vec![1, 2, 3, 4, 5];
        let object_id = crypto::sha256_hash(&object);
        let object_size = object.len() as u32;

        assert_ok!(ObjectStore::put(Origin::signed(ACCOUNT_ID), object));

        System::assert_last_event(Event::ObjectStore(crate::Event::<Test>::DataSubmitted {
            who: ACCOUNT_ID,
            object_id,
            object_size,
        }));
    });
}

use crate::mock::{new_test_ext, Event, Origin, System, Test};
use frame_support::assert_ok;

#[test]
fn basic_test() {
    new_test_ext().execute_with(|| println!("works"));
}

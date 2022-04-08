use crate::{
    mock::{new_test_ext, Event, Feeds, Origin, System, Test},
    Error, Object, TotalObjectsAndSize,
};
use frame_support::{assert_noop, assert_ok};

const FEED_ID: u64 = 0;
const OWNER: u64 = 100;
const NOT_OWNER: u64 = 101;

#[test]
fn create_feed() {
    new_test_ext().execute_with(|| {
        assert_ok!(Feeds::create(Origin::signed(OWNER), (), None));

        assert_eq!(Feeds::totals(0), TotalObjectsAndSize::default());

        System::assert_last_event(Event::Feeds(crate::Event::<Test>::FeedCreated {
            feed_id: FEED_ID,
            who: OWNER,
        }));
        assert_eq!(Feeds::next_feed_id(), 1);
        assert_eq!(Feeds::feeds(OWNER).unwrap().to_vec(), vec![FEED_ID]);
    });
}

#[test]
fn can_do_put() {
    new_test_ext().execute_with(|| {
        let object: Object = vec![1, 2, 3, 4, 5];
        let object_size = object.len() as u64;
        // create feed before putting any data
        assert_ok!(Feeds::create(Origin::signed(OWNER), (), None));

        assert_ok!(Feeds::put(Origin::signed(OWNER), FEED_ID, object.clone()));

        // check Metadata hashmap for updated metadata
        assert_eq!(Feeds::metadata(FEED_ID), Some(vec![]));

        // check Totals hashmap
        assert_eq!(
            Feeds::totals(FEED_ID),
            TotalObjectsAndSize {
                count: 1,
                size: object_size,
            }
        );

        System::assert_last_event(Event::Feeds(crate::Event::<Test>::ObjectSubmitted {
            metadata: vec![],
            who: OWNER,
            object_size,
        }));

        // only owner can put
        assert_noop!(
            Feeds::put(Origin::signed(NOT_OWNER), FEED_ID, object),
            Error::<Test>::NotFeedOwner
        );
    });
}

#[test]
fn cannot_do_put_without_creating_feed() {
    new_test_ext().execute_with(|| {
        let object: Object = vec![1, 2, 3, 4, 5];
        assert_noop!(
            Feeds::put(Origin::signed(OWNER), FEED_ID, object),
            Error::<Test>::UnknownFeedId
        );

        assert_eq!(System::events().len(), 0);
    });
}

#[test]
fn can_close_open_feed() {
    new_test_ext().execute_with(|| {
        let object: Object = vec![1, 2, 3, 4, 5];
        // create feed before putting any data
        assert_ok!(Feeds::create(Origin::signed(OWNER), (), None));

        assert_ok!(Feeds::put(Origin::signed(OWNER), FEED_ID, object.clone()));

        // only owner can close
        assert_noop!(
            Feeds::close(Origin::signed(NOT_OWNER), FEED_ID),
            Error::<Test>::NotFeedOwner
        );

        assert_ok!(Feeds::close(Origin::signed(OWNER), FEED_ID));

        System::assert_last_event(Event::Feeds(crate::Event::<Test>::FeedClosed {
            feed_id: FEED_ID,
            who: OWNER,
        }));

        // cannot put a closed feed
        assert_noop!(
            Feeds::put(Origin::signed(OWNER), FEED_ID, object),
            Error::<Test>::FeedClosed
        );
    });
}

#[test]
fn cannot_close_invalid_feed() {
    new_test_ext().execute_with(|| {
        let feed_id = 10; // invalid
        assert_noop!(
            Feeds::close(Origin::signed(OWNER), feed_id),
            Error::<Test>::UnknownFeedId
        );
    });
}

#[test]
fn can_update_existing_feed() {
    new_test_ext().execute_with(|| {
        assert_ok!(Feeds::create(Origin::signed(OWNER), (), None));
        // only owner can update
        assert_noop!(
            Feeds::update(Origin::signed(NOT_OWNER), FEED_ID, (), None),
            Error::<Test>::NotFeedOwner
        );

        assert_ok!(Feeds::update(Origin::signed(OWNER), FEED_ID, (), None));
        System::assert_last_event(Event::Feeds(crate::Event::<Test>::FeedUpdated {
            feed_id: FEED_ID,
            who: OWNER,
        }));
    });
}

#[test]
fn cannot_update_unknown_feed() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Feeds::update(Origin::signed(OWNER), FEED_ID, (), None),
            Error::<Test>::UnknownFeedId
        );
    });
}

#[test]
fn transfer_feed_ownership() {
    new_test_ext().execute_with(|| {
        assert_ok!(Feeds::create(Origin::signed(OWNER), (), None));
        assert_eq!(Feeds::feeds(OWNER).unwrap().to_vec(), vec![FEED_ID]);

        let new_owner = 102u64;
        // only owner can transfer
        assert_noop!(
            Feeds::transfer(Origin::signed(NOT_OWNER), FEED_ID, new_owner),
            Error::<Test>::NotFeedOwner
        );
        assert_ok!(Feeds::transfer(Origin::signed(OWNER), FEED_ID, new_owner));
        assert_eq!(Feeds::feeds(OWNER), None);
        assert_eq!(Feeds::feeds(new_owner).unwrap().to_vec(), vec![FEED_ID]);
    });
}

#[test]
fn cannot_create_after_max_feeds() {
    new_test_ext().execute_with(|| {
        assert_ok!(Feeds::create(Origin::signed(OWNER), (), None));
        assert_eq!(Feeds::feeds(OWNER).unwrap().to_vec(), vec![FEED_ID]);

        // mock limits one feed per user
        assert_noop!(
            Feeds::create(Origin::signed(OWNER), (), None),
            Error::<Test>::MaxFeedsReached
        );
    });
}

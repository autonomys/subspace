use crate::{
    mock::{new_test_ext, Event, Feeds, Origin, System, Test},
    Error, FeedConfigs, Metadata, Object, TotalObjectsAndSize, Totals,
};
use frame_support::{assert_noop, assert_ok};

const FEED_ID: u64 = 0;
const ACCOUNT_ID: u64 = 100;

#[test]
fn create_feed() {
    new_test_ext().execute_with(|| {
        assert_ok!(Feeds::create(Origin::signed(ACCOUNT_ID), (), None));

        assert_eq!(Feeds::totals(0), TotalObjectsAndSize::default());

        System::assert_last_event(Event::Feeds(crate::Event::<Test>::FeedCreated {
            feed_id: FEED_ID,
            who: ACCOUNT_ID,
        }));
        assert_eq!(Feeds::next_feed_id(), 1)
    });
}

#[test]
fn can_do_put() {
    new_test_ext().execute_with(|| {
        let object: Object = vec![1, 2, 3, 4, 5];
        let object_size = object.len() as u64;
        // create feed before putting any data
        assert_ok!(Feeds::create(Origin::signed(ACCOUNT_ID), (), None));

        assert_ok!(Feeds::put(Origin::signed(ACCOUNT_ID), FEED_ID, object));

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
            who: ACCOUNT_ID,
            object_size,
        }));
    });
}

#[test]
fn cannot_do_put_without_creating_feed() {
    new_test_ext().execute_with(|| {
        let object: Object = vec![1, 2, 3, 4, 5];
        assert_noop!(
            Feeds::put(Origin::signed(ACCOUNT_ID), FEED_ID, object),
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
        assert_ok!(Feeds::create(Origin::signed(ACCOUNT_ID), (), None));

        assert_ok!(Feeds::put(
            Origin::signed(ACCOUNT_ID),
            FEED_ID,
            object.clone()
        ));

        assert_ok!(Feeds::close(Origin::signed(ACCOUNT_ID), FEED_ID));

        System::assert_last_event(Event::Feeds(crate::Event::<Test>::FeedClosed {
            feed_id: FEED_ID,
            who: ACCOUNT_ID,
        }));

        // cannot put a closed feed
        assert_noop!(
            Feeds::put(Origin::signed(ACCOUNT_ID), FEED_ID, object),
            Error::<Test>::FeedClosed
        );
    });
}

#[test]
fn cannot_close_invalid_feed() {
    new_test_ext().execute_with(|| {
        let feed_id = 10; // invalid
        assert_noop!(
            Feeds::close(Origin::signed(ACCOUNT_ID), feed_id),
            Error::<Test>::UnknownFeedId
        );
    });
}

#[test]
fn delete_feed() {
    new_test_ext().execute_with(|| {
        assert_ok!(Feeds::create(Origin::signed(ACCOUNT_ID), (), None));

        assert!(FeedConfigs::<Test>::contains_key(FEED_ID));
        assert!(Totals::<Test>::contains_key(FEED_ID));

        assert_ok!(Feeds::delete(Origin::signed(ACCOUNT_ID), FEED_ID));
        assert!(!FeedConfigs::<Test>::contains_key(FEED_ID));
        assert!(!Metadata::<Test>::contains_key(FEED_ID));
        assert!(!Totals::<Test>::contains_key(FEED_ID));
    });
}

#[test]
fn can_update_existing_feed() {
    new_test_ext().execute_with(|| {
        assert_ok!(Feeds::create(Origin::signed(ACCOUNT_ID), (), None));
        assert_ok!(Feeds::update(Origin::signed(ACCOUNT_ID), FEED_ID, (), None));
        System::assert_last_event(Event::Feeds(crate::Event::<Test>::FeedUpdated {
            feed_id: FEED_ID,
            who: ACCOUNT_ID,
        }));
    });
}

#[test]
fn cannot_update_unknown_feed() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Feeds::update(Origin::signed(ACCOUNT_ID), FEED_ID, (), None),
            Error::<Test>::UnknownFeedId
        );
    });
}

use crate::{mock::*, Error, FeedId, ObjectMetadata, PutDataObject, TotalObjectsAndSize};
use frame_support::{assert_noop, assert_ok};

const FEED_ID: FeedId = 0;
const ACCOUNT_ID: u64 = 100;

#[test]
fn can_create_feed() {
    new_test_ext().execute_with(|| {
        // current feed id is 0 by default
        assert_eq!(Feeds::current_feed_id(), FEED_ID);
        assert_ok!(Feeds::create(Origin::signed(ACCOUNT_ID)));
        // current feed id value should be incremented after feed is created
        assert_eq!(Feeds::current_feed_id(), 1);

        assert_eq!(Feeds::totals(0), TotalObjectsAndSize::default());

        System::assert_last_event(Event::Feeds(crate::Event::<Test>::FeedCreated(
            FEED_ID, ACCOUNT_ID,
        )));
    });
}

#[test]
fn can_do_put() {
    new_test_ext().execute_with(|| {
        let data_object: PutDataObject = vec![1, 2, 3, 4, 5];
        let object_size = data_object.len() as u64;
        let object_metadata: ObjectMetadata = vec![6, 7, 8, 9, 10];
        // create feed before putting any data
        assert_eq!(Feeds::current_feed_id(), FEED_ID);

        assert_ok!(Feeds::put(
            Origin::signed(ACCOUNT_ID),
            FEED_ID,
            data_object.clone(),
            object_metadata.clone()
        ));

        // check Metadata hashmap for updated metadata
        assert_eq!(Feeds::metadata(FEED_ID), Some(object_metadata.clone()));

        // check Totals hashmap
        assert_eq!(
            Feeds::totals(FEED_ID),
            TotalObjectsAndSize {
                count: 1,
                size: object_size,
            }
        );

        System::assert_last_event(Event::Feeds(crate::Event::<Test>::DataSubmitted(
            object_metadata,
            ACCOUNT_ID,
            object_size,
        )));
    });
}

#[test]
fn cannot_do_put_with_wrong_feed_id() {
    new_test_ext().execute_with(|| {
        // don't care about actual data and metadata, because call is supposed to fail
        let data_object: PutDataObject = PutDataObject::default();
        let object_metadata: ObjectMetadata = ObjectMetadata::default();
        let wrong_feed_id = 178;

        assert_noop!(
            Feeds::put(
                Origin::signed(ACCOUNT_ID),
                wrong_feed_id,
                data_object,
                object_metadata
            ),
            Error::<Test>::UnknownFeedId
        );

        assert_eq!(System::events().len(), 0);
    });
}

use crate::{
    mock::{new_test_ext, ContentEnum, Event, FeedProcessorKind, Feeds, Origin, System, Test},
    Call as FeedsCall, Error, Object, TotalObjectsAndSize,
};
use codec::{Decode, Encode};
use frame_support::{assert_noop, assert_ok};
use subspace_core_primitives::crypto;

const FEED_ID: u64 = 0;
const OWNER: u64 = 100;
const NOT_OWNER: u64 = 101;

#[test]
fn create_feed() {
    new_test_ext().execute_with(|| {
        assert_ok!(Feeds::create(
            Origin::signed(OWNER),
            Default::default(),
            None
        ));

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
        assert_ok!(Feeds::create(
            Origin::signed(OWNER),
            Default::default(),
            None
        ));

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
        assert_ok!(Feeds::create(
            Origin::signed(OWNER),
            Default::default(),
            None
        ));

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
        assert_ok!(Feeds::create(
            Origin::signed(OWNER),
            Default::default(),
            None
        ));
        // only owner can update
        assert_noop!(
            Feeds::update(Origin::signed(NOT_OWNER), FEED_ID, Default::default(), None),
            Error::<Test>::NotFeedOwner
        );

        assert_ok!(Feeds::update(
            Origin::signed(OWNER),
            FEED_ID,
            Default::default(),
            None
        ));
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
            Feeds::update(Origin::signed(OWNER), FEED_ID, Default::default(), None),
            Error::<Test>::UnknownFeedId
        );
    });
}

#[test]
fn transfer_feed_ownership() {
    new_test_ext().execute_with(|| {
        assert_ok!(Feeds::create(
            Origin::signed(OWNER),
            Default::default(),
            None
        ));
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
        assert_ok!(Feeds::create(
            Origin::signed(OWNER),
            Default::default(),
            None
        ));
        assert_eq!(Feeds::feeds(OWNER).unwrap().to_vec(), vec![FEED_ID]);

        // mock limits one feed per user
        assert_noop!(
            Feeds::create(Origin::signed(OWNER), Default::default(), None),
            Error::<Test>::MaxFeedsReached
        );
    });
}

fn create_content_feed(object: Object, kind: FeedProcessorKind, contents: Vec<Vec<u8>>) {
    new_test_ext().execute_with(|| {
        assert_ok!(Feeds::create(Origin::signed(OWNER), kind, None));

        let call = FeedsCall::<Test>::put {
            feed_id: FEED_ID,
            object: object.clone(),
        };
        let mappings = call.extract_call_objects();
        assert_eq!(mappings.len(), contents.len());
        let encoded_call = call.encode();
        contents.into_iter().enumerate().for_each(|(i, content)| {
            assert_eq!(
                Vec::<u8>::decode(
                    &mut encoded_call[mappings[i].offset as usize..]
                        .to_vec()
                        .as_slice()
                )
                .unwrap(),
                content
            );

            assert_eq!(mappings[i].key, crypto::sha256_hash(&content));
        })
    });
}

fn create_custom_content_feed(
    object: Object,
    feed_processor_kind: FeedProcessorKind,
    keys: Vec<Vec<u8>>,
    contents: Vec<Vec<u8>>,
) {
    new_test_ext().execute_with(|| {
        assert_ok!(Feeds::create(
            Origin::signed(OWNER),
            feed_processor_kind,
            None
        ));

        let call = FeedsCall::<Test>::put {
            feed_id: FEED_ID,
            object: object.clone(),
        };
        let mappings = call.extract_call_objects();
        assert_eq!(mappings.len(), keys.len());

        // keys should match
        keys.into_iter().enumerate().for_each(|(i, key)| {
            // key should match the feed name spaced key
            assert_eq!(
                mappings[i].key,
                crypto::sha256_hash_pair(FEED_ID.encode(), key.as_slice())
            );
        });

        // contents should match
        let encoded_call = call.encode();
        contents.into_iter().enumerate().for_each(|(i, content)| {
            assert_eq!(
                Vec::<u8>::decode(
                    &mut encoded_call[mappings[i].offset as usize..]
                        .to_vec()
                        .as_slice()
                )
                .unwrap(),
                content
            );
        })
    });
}

#[test]
fn create_full_object_feed() {
    let object: Object = (1..255).collect();
    create_content_feed(object.clone(), FeedProcessorKind::Content, vec![object])
}

#[test]
fn create_full_object_feed_with_key_override() {
    let object: Object = (1..255).collect();
    let key = vec![5, 4, 3, 2, 1];
    create_custom_content_feed(
        object.clone(),
        FeedProcessorKind::Custom(key.clone()),
        vec![key],
        vec![object],
    );
}

#[test]
fn create_content_within_object_feed() {
    let content_a = (1..128).collect::<Vec<u8>>();
    let object = ContentEnum::ContentA(content_a.clone()).encode();
    create_content_feed(object, FeedProcessorKind::ContentWithin, vec![content_a]);

    let content_b = (129..255).collect::<Vec<u8>>();
    let object = ContentEnum::ContentB(content_b.clone()).encode();
    create_content_feed(object, FeedProcessorKind::ContentWithin, vec![content_b])
}

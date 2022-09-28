use crate::mock::{new_test_ext, DomainId, Event, Messenger, Origin, System, Test};
use crate::verification::{StorageProofVerifier, VerificationError};
use crate::{Channel, ChannelId, ChannelState, Channels, Error, InitiateChannelParams, U256};
use frame_support::{assert_err, assert_ok};
use sp_core::storage::StorageKey;
use sp_core::Blake2Hasher;

fn create_channel(domain_id: DomainId, channel_id: ChannelId) {
    assert_ok!(Messenger::initiate_channel(
        Origin::root(),
        domain_id,
        InitiateChannelParams {
            max_outgoing_messages: 100,
        },
    ));

    System::assert_last_event(Event::Messenger(crate::Event::<Test>::ChannelInitiated {
        domain_id,
        channel_id,
    }));
    assert_eq!(
        Messenger::next_channel_id(domain_id),
        channel_id.checked_add(U256::one()).unwrap()
    );

    let channel = Messenger::channels(domain_id, channel_id).unwrap();
    assert_eq!(channel.state, ChannelState::Initiated);
}

#[test]
fn test_initiate_channel() {
    new_test_ext().execute_with(|| {
        let domain_id = 0;
        let channel_id = U256::zero();
        create_channel(domain_id, channel_id)
    });
}

#[test]
fn test_close_missing_channel() {
    new_test_ext().execute_with(|| {
        let domain_id = 0;
        let channel_id = U256::zero();
        assert_err!(
            Messenger::close_channel(Origin::root(), domain_id, channel_id,),
            Error::<Test>::MissingChannel
        );
    });
}

#[test]
fn test_close_not_open_channel() {
    new_test_ext().execute_with(|| {
        let domain_id = 0;
        let channel_id = U256::zero();
        create_channel(domain_id, channel_id);
        assert_err!(
            Messenger::close_channel(Origin::root(), domain_id, channel_id,),
            Error::<Test>::InvalidChannelState
        );
    });
}

#[test]
fn test_close_open_channel() {
    new_test_ext().execute_with(|| {
        let domain_id = 0;
        let channel_id = U256::zero();
        create_channel(domain_id, channel_id);
        assert_ok!(Messenger::open_channel(domain_id, channel_id));

        let channel = Messenger::channels(domain_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Open);
        System::assert_last_event(Event::Messenger(crate::Event::<Test>::ChannelOpen {
            domain_id,
            channel_id,
        }));

        assert_ok!(Messenger::close_channel(
            Origin::root(),
            domain_id,
            channel_id,
        ));

        let channel = Messenger::channels(domain_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Closed);
        System::assert_last_event(Event::Messenger(crate::Event::<Test>::ChannelClosed {
            domain_id,
            channel_id,
        }));
    });
}

#[test]
fn test_storage_proof_verification_invalid() {
    let mut t = new_test_ext();
    let domain_id = 0;
    let channel_id = U256::zero();
    t.execute_with(|| {
        create_channel(domain_id, channel_id);
        assert_ok!(Messenger::open_channel(domain_id, channel_id));
    });

    let (_, _, storage_proof) =
        crate::mock::storage_proof_of_channels(t.as_backend(), domain_id, channel_id);
    let res: Result<Channel, VerificationError> =
        StorageProofVerifier::<Blake2Hasher>::verify_and_get_value(
            Default::default(),
            storage_proof,
            StorageKey(vec![]),
        );
    assert_err!(res, VerificationError::InvalidProof);
}

#[test]
fn test_storage_proof_verification_missing_value() {
    let mut t = new_test_ext();
    let domain_id = 0;
    let channel_id = U256::zero();
    t.execute_with(|| {
        create_channel(domain_id, channel_id);
        assert_ok!(Messenger::open_channel(domain_id, channel_id));
    });

    let (state_root, storage_key, storage_proof) =
        crate::mock::storage_proof_of_channels(t.as_backend(), domain_id, U256::one());
    let res: Result<Channel, VerificationError> =
        StorageProofVerifier::<Blake2Hasher>::verify_and_get_value(
            state_root,
            storage_proof,
            storage_key,
        );
    assert_err!(res, VerificationError::MissingValue);
}

#[test]
fn test_storage_proof_verification() {
    let mut t = new_test_ext();
    let domain_id = 0;
    let channel_id = U256::zero();
    let mut expected_channel = None;
    t.execute_with(|| {
        create_channel(domain_id, channel_id);
        assert_ok!(Messenger::open_channel(domain_id, channel_id));
        expected_channel = Channels::<Test>::get(domain_id, channel_id);
    });

    let (state_root, storage_key, storage_proof) =
        crate::mock::storage_proof_of_channels(t.as_backend(), domain_id, channel_id);
    let res: Result<Channel, VerificationError> =
        StorageProofVerifier::<Blake2Hasher>::verify_and_get_value(
            state_root,
            storage_proof,
            storage_key,
        );

    assert!(res.is_ok());
    assert_eq!(res.unwrap(), expected_channel.unwrap())
}

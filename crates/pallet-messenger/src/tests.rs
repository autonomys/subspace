use crate::messages::{Payload, ProtocolMessageRequest, RequestResponse, VersionedPayload};
use crate::mock::domain_a::{
    new_test_ext as new_domain_a_ext, Event, Messenger, Origin, Runtime, System,
};
use crate::mock::DomainId;
use crate::verification::{Proof, StorageProofVerifier, VerificationError};
use crate::{
    Channel, ChannelId, ChannelState, Channels, Error, InitiateChannelParams, Nonce, Outbox, U256,
};
use frame_support::{assert_err, assert_ok};
use sp_core::storage::StorageKey;
use sp_core::Blake2Hasher;

fn create_channel(domain_id: DomainId, channel_id: ChannelId) {
    let params = InitiateChannelParams {
        max_outgoing_messages: 100,
    };
    assert_ok!(Messenger::initiate_channel(
        Origin::root(),
        domain_id,
        params,
    ));

    System::assert_has_event(Event::Messenger(
        crate::Event::<Runtime>::ChannelInitiated {
            domain_id,
            channel_id,
        },
    ));
    assert_eq!(
        Messenger::next_channel_id(domain_id),
        channel_id.checked_add(U256::one()).unwrap()
    );

    let channel = Messenger::channels(domain_id, channel_id).unwrap();
    assert_eq!(channel.state, ChannelState::Initiated);
    assert_eq!(channel.next_inbox_nonce, Nonce::zero());
    assert_eq!(channel.next_outbox_nonce, Nonce::one());
    assert_eq!(channel.latest_response_received_message_nonce, None);
    assert_eq!(Outbox::<Runtime>::count(), 1);
    let msg = Outbox::<Runtime>::get((domain_id, channel_id, Nonce::zero())).unwrap();
    assert_eq!(msg.dst_domain_id, domain_id);
    assert_eq!(msg.channel_id, channel_id);
    assert_eq!(
        msg.payload,
        VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(
            ProtocolMessageRequest::ChannelOpen(params)
        )))
    );

    System::assert_last_event(Event::Messenger(crate::Event::<Runtime>::OutboxMessage {
        domain_id,
        channel_id,
        nonce: Nonce::zero(),
    }));
}

#[test]
fn test_initiate_channel() {
    new_domain_a_ext().execute_with(|| {
        let domain_id = 1;
        let channel_id = U256::zero();
        create_channel(domain_id, channel_id)
    });
}

#[test]
fn test_close_missing_channel() {
    new_domain_a_ext().execute_with(|| {
        let domain_id = 1;
        let channel_id = U256::zero();
        assert_err!(
            Messenger::close_channel(Origin::root(), domain_id, channel_id,),
            Error::<Runtime>::MissingChannel
        );
    });
}

#[test]
fn test_close_not_open_channel() {
    new_domain_a_ext().execute_with(|| {
        let domain_id = 1;
        let channel_id = U256::zero();
        create_channel(domain_id, channel_id);
        assert_err!(
            Messenger::close_channel(Origin::root(), domain_id, channel_id,),
            Error::<Runtime>::InvalidChannelState
        );
    });
}

#[test]
fn test_close_open_channel() {
    new_domain_a_ext().execute_with(|| {
        let domain_id = 1;
        let channel_id = U256::zero();
        create_channel(domain_id, channel_id);
        assert_ok!(Messenger::do_open_channel(domain_id, channel_id));

        let channel = Messenger::channels(domain_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Open);
        System::assert_has_event(Event::Messenger(crate::Event::<Runtime>::ChannelOpen {
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
        System::assert_has_event(Event::Messenger(crate::Event::<Runtime>::ChannelClosed {
            domain_id,
            channel_id,
        }));

        let msg = Outbox::<Runtime>::get((domain_id, channel_id, Nonce::one())).unwrap();
        assert_eq!(msg.dst_domain_id, domain_id);
        assert_eq!(msg.channel_id, channel_id);
        assert_eq!(
            msg.payload,
            VersionedPayload::V0(Payload::Protocol(RequestResponse::Request(
                ProtocolMessageRequest::ChannelClose
            )))
        );

        System::assert_last_event(Event::Messenger(crate::Event::<Runtime>::OutboxMessage {
            domain_id,
            channel_id,
            nonce: Nonce::one(),
        }));
    });
}

#[test]
fn test_storage_proof_verification_invalid() {
    let mut t = new_domain_a_ext();
    let domain_id = 1;
    let channel_id = U256::zero();
    t.execute_with(|| {
        create_channel(domain_id, channel_id);
        assert_ok!(Messenger::do_open_channel(domain_id, channel_id));
    });

    let (_, _, storage_proof) =
        crate::mock::storage_proof_of_channels::<Runtime>(t.as_backend(), domain_id, channel_id);
    let proof = Proof {
        state_root: Default::default(),
        message_proof: storage_proof,
    };
    let res: Result<Channel, VerificationError> =
        StorageProofVerifier::<Blake2Hasher>::verify_and_get_value(proof, StorageKey(vec![]));
    assert_err!(res, VerificationError::InvalidProof);
}

#[test]
fn test_storage_proof_verification_missing_value() {
    let mut t = new_domain_a_ext();
    let domain_id = 1;
    let channel_id = U256::zero();
    t.execute_with(|| {
        create_channel(domain_id, channel_id);
        assert_ok!(Messenger::do_open_channel(domain_id, channel_id));
    });

    let (state_root, storage_key, storage_proof) =
        crate::mock::storage_proof_of_channels::<Runtime>(t.as_backend(), domain_id, U256::one());
    let proof = Proof {
        state_root,
        message_proof: storage_proof,
    };
    let res: Result<Channel, VerificationError> =
        StorageProofVerifier::<Blake2Hasher>::verify_and_get_value(proof, storage_key);
    assert_err!(res, VerificationError::MissingValue);
}

#[test]
fn test_storage_proof_verification() {
    let mut t = new_domain_a_ext();
    let domain_id = 1;
    let channel_id = U256::zero();
    let mut expected_channel = None;
    t.execute_with(|| {
        create_channel(domain_id, channel_id);
        assert_ok!(Messenger::do_open_channel(domain_id, channel_id));
        expected_channel = Channels::<Runtime>::get(domain_id, channel_id);
    });

    let (state_root, storage_key, storage_proof) =
        crate::mock::storage_proof_of_channels::<Runtime>(t.as_backend(), domain_id, channel_id);
    let proof = Proof {
        state_root,
        message_proof: storage_proof,
    };
    let res: Result<Channel, VerificationError> =
        StorageProofVerifier::<Blake2Hasher>::verify_and_get_value(proof, storage_key);

    assert!(res.is_ok());
    assert_eq!(res.unwrap(), expected_channel.unwrap())
}

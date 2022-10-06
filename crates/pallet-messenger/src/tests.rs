use crate::messages::{
    CrossDomainMessage, Message, Payload, ProtocolMessageRequest, ProtocolMessageResponse,
    RequestResponse, VersionedPayload,
};
use crate::mock::domain_a::{
    new_test_ext as new_domain_a_ext, Event, Messenger, Origin, Runtime, System,
};
use crate::mock::{
    domain_a, domain_b, storage_proof_of_inbox_message_responses, storage_proof_of_outbox_messages,
    DomainId, TestExternalities,
};
use crate::verification::{Proof, StorageProofVerifier, VerificationError};
use crate::{
    Channel, ChannelId, ChannelState, Channels, Error, InitiateChannelParams, Nonce, Outbox, U256,
};
use frame_support::{assert_err, assert_ok};
use sp_core::storage::StorageKey;
use sp_core::Blake2Hasher;
use sp_runtime::traits::ValidateUnsigned;
use sp_runtime::transaction_validity::TransactionSource;

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

fn close_channel(domain_id: DomainId, channel_id: ChannelId) {
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

        // open channel
        assert_ok!(Messenger::do_open_channel(domain_id, channel_id));
        let channel = Messenger::channels(domain_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Open);
        System::assert_has_event(Event::Messenger(crate::Event::<Runtime>::ChannelOpen {
            domain_id,
            channel_id,
        }));

        // close channel
        close_channel(domain_id, channel_id)
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

fn open_channel_between_domains(
    domain_a_test_ext: &mut TestExternalities,
    domain_b_test_ext: &mut TestExternalities,
) -> ChannelId {
    let domain_a_id = domain_a::SelfDomainId::get();
    let domain_b_id = domain_b::SelfDomainId::get();

    // initiate channel open on domain_a
    let channel_id = domain_a_test_ext.execute_with(|| -> ChannelId {
        let channel_id = U256::zero();
        create_channel(domain_b_id, channel_id);
        channel_id
    });

    channel_relay_request_and_response(
        domain_a_test_ext,
        domain_b_test_ext,
        channel_id,
        Nonce::zero(),
    );

    // check channel state be open on domain_b
    domain_b_test_ext.execute_with(|| {
        let channel = domain_b::Messenger::channels(domain_a_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Open);
        domain_b::System::assert_has_event(domain_b::Event::Messenger(crate::Event::<
            domain_b::Runtime,
        >::ChannelInitiated {
            domain_id: domain_a_id,
            channel_id,
        }));
        domain_b::System::assert_has_event(domain_b::Event::Messenger(crate::Event::<
            domain_b::Runtime,
        >::ChannelOpen {
            domain_id: domain_a_id,
            channel_id,
        }));
    });

    // check channel state be open on domain_a
    domain_a_test_ext.execute_with(|| {
        let channel = domain_a::Messenger::channels(domain_b_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Open);
        assert_eq!(
            channel.latest_response_received_message_nonce,
            Some(Nonce::zero())
        );
        assert_eq!(channel.next_inbox_nonce, Nonce::zero());
        assert_eq!(channel.next_outbox_nonce, Nonce::one());
        domain_a::System::assert_has_event(domain_a::Event::Messenger(crate::Event::<
            domain_a::Runtime,
        >::ChannelOpen {
            domain_id: domain_b_id,
            channel_id,
        }));
    });

    channel_id
}

fn close_channel_between_domains(
    domain_a_test_ext: &mut TestExternalities,
    domain_b_test_ext: &mut TestExternalities,
    channel_id: ChannelId,
) {
    let domain_a_id = domain_a::SelfDomainId::get();
    let domain_b_id = domain_b::SelfDomainId::get();

    // initiate channel close on domain_a
    domain_a_test_ext.execute_with(|| {
        close_channel(domain_b_id, channel_id);
    });

    channel_relay_request_and_response(
        domain_a_test_ext,
        domain_b_test_ext,
        channel_id,
        Nonce::one(),
    );

    // check channel state be close on domain_b
    domain_b_test_ext.execute_with(|| {
        let channel = domain_b::Messenger::channels(domain_a_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Closed);
        domain_b::System::assert_has_event(domain_b::Event::Messenger(crate::Event::<
            domain_b::Runtime,
        >::ChannelClosed {
            domain_id: domain_a_id,
            channel_id,
        }));
    });

    // check channel state be closed on domain_a
    domain_a_test_ext.execute_with(|| {
        let channel = domain_a::Messenger::channels(domain_b_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Closed);
        assert_eq!(
            channel.latest_response_received_message_nonce,
            Some(Nonce::one())
        );
        assert_eq!(channel.next_inbox_nonce, Nonce::zero());
        assert_eq!(
            channel.next_outbox_nonce,
            Nonce::one().checked_add(Nonce::one()).unwrap()
        );
        domain_a::System::assert_has_event(domain_a::Event::Messenger(crate::Event::<
            domain_a::Runtime,
        >::ChannelClosed {
            domain_id: domain_b_id,
            channel_id,
        }));
    })
}

fn channel_relay_request_and_response(
    domain_a_test_ext: &mut TestExternalities,
    domain_b_test_ext: &mut TestExternalities,
    channel_id: ChannelId,
    nonce: Nonce,
) {
    let domain_a_id = domain_a::SelfDomainId::get();
    let domain_b_id = domain_b::SelfDomainId::get();

    // relay message to domain_b
    let (state_root, _key, message_proof) = storage_proof_of_outbox_messages::<domain_a::Runtime>(
        domain_a_test_ext.as_backend(),
        domain_b_id,
        channel_id,
        nonce,
    );

    let xdm = CrossDomainMessage {
        src_domain_id: domain_a_id,
        dst_domain_id: domain_b_id,
        channel_id,
        nonce,
        proof: Proof {
            state_root,
            message_proof,
        },
    };
    domain_b_test_ext.execute_with(|| {
        // set state root
        domain_b::SystemDomainTracker::set_state_root(xdm.proof.state_root);

        // validate the message
        let pre_check = crate::Pallet::<domain_b::Runtime>::validate_unsigned(
            TransactionSource::Local,
            &crate::Call::relay_message { msg: xdm.clone() },
        );
        assert_ok!(pre_check);

        // process inbox message
        let result = domain_b::Messenger::relay_message(domain_b::Origin::none(), xdm);
        assert_ok!(result);

        domain_b::System::assert_has_event(domain_b::Event::Messenger(crate::Event::<
            domain_b::Runtime,
        >::InboxMessageResponse {
            domain_id: domain_a_id,
            channel_id,
            nonce,
        }));

        let response =
            domain_b::Messenger::inbox_responses((domain_a_id, channel_id, nonce)).unwrap();
        assert_eq!(
            response,
            Message {
                src_domain_id: domain_b_id,
                dst_domain_id: domain_a_id,
                channel_id,
                nonce,
                payload: VersionedPayload::V0(Payload::Protocol(RequestResponse::Response(
                    ProtocolMessageResponse(Ok(()))
                )))
            }
        );
        assert_eq!(
            domain_a::Messenger::inbox((domain_b_id, channel_id, nonce)),
            None
        );
    });

    // relay message response to domain_a
    let (state_root, _key, message_proof) =
        storage_proof_of_inbox_message_responses::<domain_b::Runtime>(
            domain_b_test_ext.as_backend(),
            domain_a_id,
            channel_id,
            nonce,
        );

    let xdm = CrossDomainMessage {
        src_domain_id: domain_b_id,
        dst_domain_id: domain_a_id,
        channel_id,
        nonce,
        proof: Proof {
            state_root,
            message_proof,
        },
    };
    domain_a_test_ext.execute_with(|| {
        domain_a::SystemDomainTracker::set_state_root(xdm.proof.state_root);

        // validate message response
        let pre_check = crate::Pallet::<domain_a::Runtime>::validate_unsigned(
            TransactionSource::Local,
            &crate::Call::relay_message_response { msg: xdm.clone() },
        );
        assert_ok!(pre_check);

        // process outbox message response
        let result = domain_a::Messenger::relay_message_response(domain_a::Origin::none(), xdm);
        assert_ok!(result);

        // outbox message and message response should not exists
        assert_eq!(
            domain_a::Messenger::outbox((domain_b_id, channel_id, nonce)),
            None
        );
        assert_eq!(
            domain_a::Messenger::outbox_responses((domain_b_id, channel_id, nonce)),
            None
        );
    })
}

#[test]
fn test_open_channel_between_domains() {
    let mut domain_a_test_ext = domain_a::new_test_ext();
    let mut domain_b_test_ext = domain_b::new_test_ext();
    // open channel between domain_a and domain_b
    // domain_a initiates the channel open
    open_channel_between_domains(&mut domain_a_test_ext, &mut domain_b_test_ext);
}

#[test]
fn test_close_channel_between_domains() {
    let mut domain_a_test_ext = domain_a::new_test_ext();
    let mut domain_b_test_ext = domain_b::new_test_ext();
    // open channel between domain_a and domain_b
    // domain_a initiates the channel open
    let channel_id = open_channel_between_domains(&mut domain_a_test_ext, &mut domain_b_test_ext);

    // close open channel
    close_channel_between_domains(&mut domain_a_test_ext, &mut domain_b_test_ext, channel_id)
}

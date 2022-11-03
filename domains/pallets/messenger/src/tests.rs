use crate::mock::domain_a::{
    new_test_ext as new_domain_a_ext, Event, Messenger, Origin, RelayerDeposit, Runtime, System,
    RELAYER_ID,
};
use crate::mock::{
    domain_a, domain_b, storage_proof_of_inbox_message_responses, storage_proof_of_outbox_messages,
    AccountId, Balance, DomainId, TestExternalities,
};
use crate::relayer::RelayerInfo;
use crate::verification::{StorageProofVerifier, VerificationError};
use crate::{
    Channel, ChannelId, ChannelState, Channels, Error, FeeModel, Inbox, InboxResponses, Nonce,
    Outbox, OutboxMessageResult, OutboxResponses, U256,
};
use frame_support::traits::Currency;
use frame_support::{assert_err, assert_ok};
use pallet_transporter::Location;
use sp_core::storage::StorageKey;
use sp_core::Blake2Hasher;
use sp_messenger::endpoint::{Endpoint, EndpointPayload, EndpointRequest, Sender};
use sp_messenger::messages::{
    CrossDomainMessage, ExecutionFee, InitiateChannelParams, Payload, Proof,
    ProtocolMessageRequest, RequestResponse, VersionedPayload,
};
use sp_runtime::traits::ValidateUnsigned;

fn create_channel(domain_id: DomainId, channel_id: ChannelId, fee_model: FeeModel<Balance>) {
    let params = InitiateChannelParams {
        max_outgoing_messages: 100,
        fee_model,
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
        relayer_id: RELAYER_ID,
    }));

    // check outbox relayer storage key generation
    let messages_with_keys = domain_a::Messenger::relayer_assigned_messages(domain_a::RELAYER_ID);
    assert_eq!(messages_with_keys.outbox.len(), 1);
    assert_eq!(messages_with_keys.inbox_responses.len(), 0);
    let expected_key =
        Outbox::<domain_a::Runtime>::hashed_key_for((domain_id, channel_id, Nonce::zero()));
    assert_eq!(
        messages_with_keys.outbox[0].storage_key,
        StorageKey(expected_key)
    );
}

fn close_channel(domain_id: DomainId, channel_id: ChannelId, last_delivered_nonce: Option<Nonce>) {
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
        msg.last_delivered_message_response_nonce,
        last_delivered_nonce
    );
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
        relayer_id: RELAYER_ID,
    }));
}

#[test]
fn test_initiate_channel() {
    new_domain_a_ext().execute_with(|| {
        let domain_id = 2;
        let channel_id = U256::zero();
        create_channel(domain_id, channel_id, Default::default())
    });
}

#[test]
fn test_close_missing_channel() {
    new_domain_a_ext().execute_with(|| {
        let domain_id = 2;
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
        let domain_id = 2;
        let channel_id = U256::zero();
        create_channel(domain_id, channel_id, Default::default());
        assert_err!(
            Messenger::close_channel(Origin::root(), domain_id, channel_id,),
            Error::<Runtime>::InvalidChannelState
        );
    });
}

#[test]
fn test_close_open_channel() {
    new_domain_a_ext().execute_with(|| {
        let domain_id = 2;
        let channel_id = U256::zero();
        create_channel(domain_id, channel_id, Default::default());

        // open channel
        assert_ok!(Messenger::do_open_channel(domain_id, channel_id));
        let channel = Messenger::channels(domain_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Open);
        System::assert_has_event(Event::Messenger(crate::Event::<Runtime>::ChannelOpen {
            domain_id,
            channel_id,
        }));

        // close channel
        close_channel(domain_id, channel_id, None)
    });
}

#[test]
fn test_storage_proof_verification_invalid() {
    let mut t = new_domain_a_ext();
    let domain_id = 2;
    let channel_id = U256::zero();
    t.execute_with(|| {
        create_channel(domain_id, channel_id, Default::default());
        assert_ok!(Messenger::do_open_channel(domain_id, channel_id));
    });

    let (_, _, storage_proof) =
        crate::mock::storage_proof_of_channels::<Runtime>(t.as_backend(), domain_id, channel_id);
    let proof = Proof {
        state_root: Default::default(),
        core_domain_proof: None,
        message_proof: storage_proof,
    };
    let res: Result<Channel<Balance>, VerificationError> =
        StorageProofVerifier::<Blake2Hasher>::verify_and_get_value(
            &proof.state_root,
            proof.message_proof,
            StorageKey(vec![]),
        );
    assert_err!(res, VerificationError::InvalidProof);
}

#[test]
fn test_storage_proof_verification_missing_value() {
    let mut t = new_domain_a_ext();
    let domain_id = 2;
    let channel_id = U256::zero();
    t.execute_with(|| {
        create_channel(domain_id, channel_id, Default::default());
        assert_ok!(Messenger::do_open_channel(domain_id, channel_id));
    });

    let (state_root, storage_key, storage_proof) =
        crate::mock::storage_proof_of_channels::<Runtime>(t.as_backend(), domain_id, U256::one());
    let proof = Proof {
        state_root,
        core_domain_proof: None,
        message_proof: storage_proof,
    };
    let res: Result<Channel<Balance>, VerificationError> =
        StorageProofVerifier::<Blake2Hasher>::verify_and_get_value(
            &proof.state_root,
            proof.message_proof,
            storage_key,
        );
    assert_err!(res, VerificationError::MissingValue);
}

#[test]
fn test_storage_proof_verification() {
    let mut t = new_domain_a_ext();
    let domain_id = 2;
    let channel_id = U256::zero();
    let mut expected_channel = None;
    t.execute_with(|| {
        create_channel(domain_id, channel_id, Default::default());
        assert_ok!(Messenger::do_open_channel(domain_id, channel_id));
        expected_channel = Channels::<Runtime>::get(domain_id, channel_id);
    });

    let (state_root, storage_key, storage_proof) =
        crate::mock::storage_proof_of_channels::<Runtime>(t.as_backend(), domain_id, channel_id);
    let proof = Proof {
        state_root,
        core_domain_proof: None,
        message_proof: storage_proof,
    };
    let res: Result<Channel<Balance>, VerificationError> =
        StorageProofVerifier::<Blake2Hasher>::verify_and_get_value(
            &proof.state_root,
            proof.message_proof,
            storage_key,
        );

    assert!(res.is_ok());
    assert_eq!(res.unwrap(), expected_channel.unwrap())
}

fn open_channel_between_domains(
    domain_a_test_ext: &mut TestExternalities,
    domain_b_test_ext: &mut TestExternalities,
    fee_model: FeeModel<Balance>,
) -> ChannelId {
    let domain_a_id = domain_a::SelfDomainId::get();
    let domain_b_id = domain_b::SelfDomainId::get();

    // initiate channel open on domain_a
    let channel_id = domain_a_test_ext.execute_with(|| -> ChannelId {
        let channel_id = U256::zero();
        create_channel(domain_b_id, channel_id, fee_model);
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

        // check inbox response storage key generation
        let messages_with_keys =
            domain_b::Messenger::relayer_assigned_messages(domain_b::RELAYER_ID);
        assert_eq!(messages_with_keys.outbox.len(), 0);
        assert_eq!(messages_with_keys.inbox_responses.len(), 1);
        let expected_key = InboxResponses::<domain_b::Runtime>::hashed_key_for((
            domain_a_id,
            channel_id,
            Nonce::zero(),
        ));
        assert_eq!(
            messages_with_keys.inbox_responses[0].storage_key,
            StorageKey(expected_key)
        );
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

fn send_message_between_domains(
    sender: &AccountId,
    domain_a_test_ext: &mut TestExternalities,
    domain_b_test_ext: &mut TestExternalities,
    msg: EndpointPayload,
    channel_id: ChannelId,
) {
    let domain_b_id = domain_b::SelfDomainId::get();

    // send message form outbox
    domain_a_test_ext.execute_with(|| {
        let resp = <domain_a::Messenger as Sender<AccountId, DomainId>>::send_message(
            sender,
            domain_b_id,
            EndpointRequest {
                src_endpoint: Endpoint::Id(0),
                dst_endpoint: Endpoint::Id(0),
                payload: msg,
            },
        );
        assert_ok!(resp);
        domain_a::System::assert_last_event(Event::Messenger(
            crate::Event::<Runtime>::OutboxMessage {
                domain_id: domain_b_id,
                channel_id,
                nonce: Nonce::one(),
                relayer_id: RELAYER_ID,
            },
        ));
    });

    channel_relay_request_and_response(
        domain_a_test_ext,
        domain_b_test_ext,
        channel_id,
        Nonce::one(),
    );

    // check state on domain_b
    domain_b_test_ext.execute_with(|| {
        // Outbox, Outbox responses, Inbox, InboxResponses must be empty
        assert_eq!(Outbox::<domain_b::Runtime>::count(), 0);
        assert_eq!(OutboxResponses::<domain_b::Runtime>::count(), 0);
        assert_eq!(Inbox::<domain_b::Runtime>::count(), 0);

        // latest inbox message response is cleared on next message
        assert_eq!(InboxResponses::<domain_b::Runtime>::count(), 1);
    });

    // check state on domain_a
    domain_a_test_ext.execute_with(|| {
        // Outbox, Outbox responses, Inbox, InboxResponses must be empty
        assert_eq!(Outbox::<domain_a::Runtime>::count(), 0);
        assert_eq!(OutboxResponses::<domain_a::Runtime>::count(), 0);
        assert_eq!(Inbox::<domain_a::Runtime>::count(), 0);
        assert_eq!(InboxResponses::<domain_a::Runtime>::count(), 0);

        let channel = domain_a::Messenger::channels(domain_b_id, channel_id).unwrap();
        assert_eq!(
            channel.latest_response_received_message_nonce,
            Some(Nonce::one())
        );
    });
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
        close_channel(domain_b_id, channel_id, Some(Nonce::zero()));
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

        assert_eq!(channel.latest_response_received_message_nonce, None);
        assert_eq!(
            channel.next_inbox_nonce,
            Nonce::one().checked_add(Nonce::one()).unwrap()
        );
        assert_eq!(channel.next_outbox_nonce, Nonce::zero());

        // Outbox, Outbox responses, Inbox, InboxResponses must be empty
        assert_eq!(Outbox::<domain_b::Runtime>::count(), 0);
        assert_eq!(OutboxResponses::<domain_b::Runtime>::count(), 0);
        assert_eq!(Inbox::<domain_b::Runtime>::count(), 0);

        // latest inbox message response is cleared on next message
        assert_eq!(InboxResponses::<domain_b::Runtime>::count(), 1);
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

        // Outbox, Outbox responses, Inbox, InboxResponses must be empty
        assert_eq!(Outbox::<domain_a::Runtime>::count(), 0);
        assert_eq!(OutboxResponses::<domain_a::Runtime>::count(), 0);
        assert_eq!(Inbox::<domain_a::Runtime>::count(), 0);
        assert_eq!(InboxResponses::<domain_a::Runtime>::count(), 0);
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
            core_domain_proof: None,
            message_proof,
        },
    };
    domain_b_test_ext.execute_with(|| {
        // set state root
        domain_b::DomainTracker::do_update_state_root(xdm.proof.state_root);

        // validate the message
        let pre_check =
            crate::Pallet::<domain_b::Runtime>::pre_dispatch(&crate::Call::relay_message {
                msg: xdm.clone(),
            });
        assert_ok!(pre_check);

        // process inbox message
        let result = domain_b::Messenger::relay_message(domain_b::Origin::none(), xdm);
        assert_ok!(result);

        domain_b::System::assert_has_event(domain_b::Event::Messenger(crate::Event::<
            domain_b::Runtime,
        >::InboxMessage {
            domain_id: domain_a_id,
            channel_id,
            nonce,
        }));

        domain_b::System::assert_has_event(domain_b::Event::Messenger(crate::Event::<
            domain_b::Runtime,
        >::InboxMessageResponse {
            domain_id: domain_a_id,
            channel_id,
            nonce,
            relayer_id: domain_b::RELAYER_ID,
        }));

        let response =
            domain_b::Messenger::inbox_responses((domain_a_id, channel_id, nonce)).unwrap();
        assert_eq!(response.src_domain_id, domain_b_id);
        assert_eq!(response.dst_domain_id, domain_a_id);
        assert_eq!(response.channel_id, channel_id);
        assert_eq!(response.nonce, nonce);
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
            core_domain_proof: None,
            message_proof,
        },
    };
    domain_a_test_ext.execute_with(|| {
        domain_a::DomainTracker::do_update_state_root(xdm.proof.state_root);

        // validate message response
        let pre_check = crate::Pallet::<domain_a::Runtime>::pre_dispatch(
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

        domain_a::System::assert_has_event(domain_a::Event::Messenger(crate::Event::<
            domain_a::Runtime,
        >::OutboxMessageResult {
            domain_id: domain_b_id,
            channel_id,
            nonce,
            result: OutboxMessageResult::Ok,
        }));
    })
}

#[test]
fn test_open_channel_between_domains() {
    let mut domain_a_test_ext = domain_a::new_test_ext();
    let mut domain_b_test_ext = domain_b::new_test_ext();
    // open channel between domain_a and domain_b
    // domain_a initiates the channel open
    open_channel_between_domains(
        &mut domain_a_test_ext,
        &mut domain_b_test_ext,
        Default::default(),
    );
}

#[test]
fn test_close_channel_between_domains() {
    let mut domain_a_test_ext = domain_a::new_test_ext();
    let mut domain_b_test_ext = domain_b::new_test_ext();
    // open channel between domain_a and domain_b
    // domain_a initiates the channel open
    let channel_id = open_channel_between_domains(
        &mut domain_a_test_ext,
        &mut domain_b_test_ext,
        Default::default(),
    );

    // close open channel
    close_channel_between_domains(&mut domain_a_test_ext, &mut domain_b_test_ext, channel_id)
}

#[test]
fn test_send_message_between_domains() {
    let mut domain_a_test_ext = domain_a::new_test_ext();
    let mut domain_b_test_ext = domain_b::new_test_ext();
    // open channel between domain_a and domain_b
    // domain_a initiates the channel open
    let channel_id = open_channel_between_domains(
        &mut domain_a_test_ext,
        &mut domain_b_test_ext,
        Default::default(),
    );

    // send message
    send_message_between_domains(
        &0,
        &mut domain_a_test_ext,
        &mut domain_b_test_ext,
        vec![1, 2, 3, 4],
        channel_id,
    )
}

fn initiate_transfer_on_domain(domain_a_ext: &mut TestExternalities) {
    // this account should have 1000 balance on each domain
    let account_id = 1;
    domain_a_ext.execute_with(|| {
        let res = domain_a::Transporter::transfer(
            domain_a::Origin::signed(account_id),
            Location {
                domain_id: domain_b::SelfDomainId::get(),
                account_id,
            },
            500,
        );
        assert_ok!(res);
        domain_a::System::assert_has_event(domain_a::Event::Transporter(
            pallet_transporter::Event::<domain_a::Runtime>::OutgoingTransferInitiated {
                domain_id: domain_b::SelfDomainId::get(),
                message_id: (U256::zero(), U256::one()),
            },
        ));
        domain_a::System::assert_has_event(domain_a::Event::Messenger(crate::Event::<
            domain_a::Runtime,
        >::OutboxMessage {
            domain_id: domain_b::SelfDomainId::get(),
            channel_id: U256::zero(),
            nonce: U256::one(),
            relayer_id: RELAYER_ID,
        }));
        let fee_model = domain_b::Messenger::channels(domain_b::SelfDomainId::get(), U256::zero())
            .unwrap_or_default()
            .fee;
        let fees = fee_model.inbox_fee.relayer_pool_fee
            + fee_model.inbox_fee.compute_fee
            + fee_model.outbox_fee.compute_fee
            + fee_model.outbox_fee.relayer_pool_fee;

        assert_eq!(domain_a::Balances::free_balance(&account_id), 500 - fees);
        // source domain take 2 fees and dst_domain takes 2
        assert_eq!(
            domain_a::Balances::free_balance(&domain_a::Messenger::messenger_account_id()),
            fee_model.outbox_fee.compute_fee + fee_model.outbox_fee.relayer_pool_fee
        );
        assert!(domain_a::Transporter::outgoing_transfers(
            domain_b::SelfDomainId::get(),
            (U256::zero(), U256::one())
        )
        .is_some())
    })
}

fn verify_transfer_on_domain(
    domain_a_ext: &mut TestExternalities,
    domain_b_ext: &mut TestExternalities,
) {
    // this account should have 496 balance with 1 fee left
    // domain a should have
    //   a successful event
    //   reduced balance
    //   empty state
    let account_id = 1;
    domain_a_ext.execute_with(|| {
        domain_a::System::assert_has_event(domain_a::Event::Transporter(
            pallet_transporter::Event::<domain_a::Runtime>::OutgoingTransferSuccessful {
                domain_id: domain_b::SelfDomainId::get(),
                message_id: (U256::zero(), U256::one()),
            },
        ));
        domain_a::System::assert_has_event(domain_a::Event::Messenger(crate::Event::<
            domain_a::Runtime,
        >::OutboxMessageResponse {
            domain_id: domain_b::SelfDomainId::get(),
            channel_id: U256::zero(),
            nonce: U256::one(),
        }));
        assert_eq!(domain_a::Balances::free_balance(&account_id), 496);
        assert_eq!(
            domain_a::Balances::free_balance(&domain_a::Messenger::messenger_account_id()),
            1
        );
        let relayer_a_balance = domain_a::Balances::free_balance(domain_a::RELAYER_ID);
        assert_eq!(relayer_a_balance, 1);
        assert!(domain_a::Transporter::outgoing_transfers(
            domain_b::SelfDomainId::get(),
            (U256::zero(), U256::one())
        )
        .is_none())
    });

    // domain a should have
    //   a successful event incoming event
    //   increased balance
    domain_b_ext.execute_with(|| {
        domain_b::System::assert_has_event(domain_b::Event::Transporter(
            pallet_transporter::Event::<domain_b::Runtime>::IncomingTransferSuccessful {
                domain_id: domain_a::SelfDomainId::get(),
                message_id: (U256::zero(), U256::one()),
            },
        ));
        domain_b::System::assert_has_event(domain_b::Event::Messenger(crate::Event::<
            domain_b::Runtime,
        >::InboxMessageResponse {
            domain_id: domain_a::SelfDomainId::get(),
            channel_id: U256::zero(),
            nonce: U256::one(),
            relayer_id: domain_b::RELAYER_ID,
        }));
        assert_eq!(domain_b::Balances::free_balance(&account_id), 1500);
        assert_eq!(
            domain_b::Balances::free_balance(&domain_b::Messenger::messenger_account_id()),
            1
        );
        let relayer_b_balance = domain_b::Balances::free_balance(domain_b::RELAYER_ID);
        assert_eq!(relayer_b_balance, 1);
    })
}

#[test]
fn test_transport_funds_between_domains() {
    let mut domain_a_test_ext = domain_a::new_test_ext();
    let mut domain_b_test_ext = domain_b::new_test_ext();
    // pre check
    let relayer_a_balance = domain_a_test_ext
        .execute_with(|| -> Balance { domain_a::Balances::free_balance(domain_a::RELAYER_ID) });
    let relayer_b_balance = domain_b_test_ext
        .execute_with(|| -> Balance { domain_b::Balances::free_balance(domain_b::RELAYER_ID) });
    assert_eq!(relayer_a_balance, 0);
    assert_eq!(relayer_b_balance, 0);

    // open channel between domain_a and domain_b
    // domain_a initiates the channel open
    let channel_id = open_channel_between_domains(
        &mut domain_a_test_ext,
        &mut domain_b_test_ext,
        FeeModel {
            outbox_fee: ExecutionFee {
                relayer_pool_fee: 1,
                compute_fee: 1,
            },
            inbox_fee: ExecutionFee {
                relayer_pool_fee: 1,
                compute_fee: 1,
            },
        },
    );

    // initiate transfer
    initiate_transfer_on_domain(&mut domain_a_test_ext);

    // relay message
    channel_relay_request_and_response(
        &mut domain_a_test_ext,
        &mut domain_b_test_ext,
        channel_id,
        Nonce::one(),
    );

    // post check
    verify_transfer_on_domain(&mut domain_a_test_ext, &mut domain_b_test_ext)
}

#[test]
fn test_transport_funds_between_domains_failed_low_balance() {
    let mut domain_a_test_ext = domain_a::new_test_ext();
    let mut domain_b_test_ext = domain_b::new_test_ext();
    // open channel between domain_a and domain_b
    // domain_a initiates the channel open
    open_channel_between_domains(
        &mut domain_a_test_ext,
        &mut domain_b_test_ext,
        Default::default(),
    );

    // initiate transfer
    let account_id = 100;
    domain_a_test_ext.execute_with(|| {
        let res = domain_a::Transporter::transfer(
            domain_a::Origin::signed(account_id),
            Location {
                domain_id: domain_b::SelfDomainId::get(),
                account_id,
            },
            500,
        );
        assert_err!(
            res,
            pallet_transporter::Error::<domain_a::Runtime>::LowBalance
        );
    });
}

#[test]
fn test_transport_funds_between_domains_failed_no_open_channel() {
    let mut domain_a_test_ext = domain_a::new_test_ext();

    // initiate transfer
    let account_id = 1;
    domain_a_test_ext.execute_with(|| {
        let res = domain_a::Transporter::transfer(
            domain_a::Origin::signed(account_id),
            Location {
                domain_id: domain_b::SelfDomainId::get(),
                account_id,
            },
            500,
        );
        assert_err!(res, crate::Error::<domain_a::Runtime>::NoOpenChannel);
    });
}

#[test]
fn test_join_relayer_low_balance() {
    let mut domain_a_test_ext = domain_a::new_test_ext();
    // account with no balance
    let account_id = 2;
    let relayer_id = 100;

    domain_a_test_ext.execute_with(|| {
        let res =
            domain_a::Messenger::join_relayer_set(domain_a::Origin::signed(account_id), relayer_id);
        assert_err!(
            res,
            pallet_balances::Error::<domain_a::Runtime>::InsufficientBalance
        );
    });
}

#[test]
fn test_join_relayer_set() {
    let mut domain_a_test_ext = domain_a::new_test_ext();
    // account with balance
    let account_id = 1;
    let relayer_id = 100;

    domain_a_test_ext.execute_with(|| {
        assert_eq!(domain_a::Balances::free_balance(&account_id), 1000);
        let res =
            domain_a::Messenger::join_relayer_set(domain_a::Origin::signed(account_id), relayer_id);
        assert_ok!(res);
        assert_eq!(
            domain_a::Messenger::relayers_info(relayer_id).unwrap(),
            RelayerInfo {
                owner: account_id,
                deposit_reserved: RelayerDeposit::get()
            }
        );
        assert_eq!(domain_a::Balances::free_balance(&account_id), 500);

        // cannot rejoin again
        let res =
            domain_a::Messenger::join_relayer_set(domain_a::Origin::signed(account_id), relayer_id);
        assert_err!(res, crate::Error::<domain_a::Runtime>::AlreadyRelayer);

        // get relayer, idx should increment
        let assigned_relayer_id = domain_a::Messenger::next_relayer().unwrap();
        assert_eq!(assigned_relayer_id, RELAYER_ID);
        assert_eq!(domain_a::Messenger::next_relayer_idx(), 1);

        // get next relayer, idx should go beyond bound
        let assigned_relayer_id = domain_a::Messenger::next_relayer().unwrap();
        assert_eq!(assigned_relayer_id, relayer_id);
        assert_eq!(domain_a::Messenger::next_relayer_idx(), 2);

        // get relayer should be back within bound and not skipped
        let assigned_relayer_id = domain_a::Messenger::next_relayer().unwrap();
        assert_eq!(assigned_relayer_id, RELAYER_ID);
        assert_eq!(domain_a::Messenger::next_relayer_idx(), 1);
    });
}

#[test]
fn test_exit_relayer_set() {
    let mut domain_a_test_ext = domain_a::new_test_ext();
    // account with balance
    let account_id = 1;
    let relayer_id_1 = 100;
    let relayer_id_2 = 101;
    let relayer_id_3 = 102;

    domain_a_test_ext.execute_with(|| {
        domain_a::Balances::make_free_balance_be(&account_id, 2000);
        assert_eq!(domain_a::Balances::free_balance(&account_id), 2000);
        for relayer in [relayer_id_1, relayer_id_2, relayer_id_3] {
            let res = domain_a::Messenger::join_relayer_set(
                domain_a::Origin::signed(account_id),
                relayer,
            );
            assert_ok!(res);
            assert_eq!(
                domain_a::Messenger::relayers_info(relayer).unwrap(),
                RelayerInfo {
                    owner: account_id,
                    deposit_reserved: RelayerDeposit::get()
                }
            );
        }
        assert_eq!(domain_a::Balances::free_balance(&account_id), 500);

        let assigned_relayer_id = domain_a::Messenger::next_relayer().unwrap();
        assert_eq!(assigned_relayer_id, RELAYER_ID);
        assert_eq!(domain_a::Messenger::next_relayer_idx(), 1);

        let assigned_relayer_id = domain_a::Messenger::next_relayer().unwrap();
        assert_eq!(assigned_relayer_id, relayer_id_1);
        assert_eq!(domain_a::Messenger::next_relayer_idx(), 2);

        // relayer_1 exits
        let res = domain_a::Messenger::exit_relayer_set(
            domain_a::Origin::signed(account_id),
            relayer_id_1,
        );
        assert_ok!(res);
        assert_eq!(domain_a::Messenger::next_relayer_idx(), 1);

        // relayer_3 exits
        let res = domain_a::Messenger::exit_relayer_set(
            domain_a::Origin::signed(account_id),
            relayer_id_3,
        );
        assert_ok!(res);
        assert_eq!(domain_a::Messenger::next_relayer_idx(), 1);
        let assigned_relayer_id = domain_a::Messenger::next_relayer().unwrap();
        assert_eq!(assigned_relayer_id, relayer_id_2);
    });
}

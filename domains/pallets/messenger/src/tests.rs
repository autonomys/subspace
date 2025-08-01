use crate::mock::chain_a::{
    Messenger, Runtime, RuntimeEvent, RuntimeOrigin, System, USER_ACCOUNT,
    new_test_ext as new_chain_a_ext,
};
use crate::mock::{
    AccountId, Balance, TestExternalities, chain_a, chain_b, consensus_chain,
    storage_proof_of_inbox_message_responses, storage_proof_of_outbox_messages,
};
use crate::pallet::OutboxMessageCount;
use crate::{
    ChainAllowlist, ChainAllowlistUpdate, Channel, ChannelId, ChannelState, Channels,
    CloseChannelBy, Error, Inbox, InboxFee, InboxResponses, Nonce, Outbox, OutboxMessageResult,
    OutboxResponses, Pallet, U256,
};
use frame_support::traits::fungible::Inspect;
use frame_support::traits::tokens::{Fortitude, Preservation};
use frame_support::{assert_err, assert_ok};
use pallet_transporter::Location;
use sp_core::storage::StorageKey;
use sp_core::{Blake2Hasher, H256};
use sp_domains::DomainAllowlistUpdates;
use sp_domains::proof_provider_and_verifier::{StorageProofVerifier, VerificationError};
use sp_messenger::endpoint::{Endpoint, EndpointPayload, EndpointRequest, Sender};
use sp_messenger::messages::{
    BlockMessagesQuery, ChainId, ChannelOpenParamsV1, CrossDomainMessage, MessageWeightTag,
    PayloadV1, Proof, ProtocolMessageRequest, RequestResponse, VersionedPayload,
};
use sp_mmr_primitives::{EncodableOpaqueLeaf, LeafProof as MmrProof};
use sp_runtime::traits::{Convert, Zero};
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
use sp_trie::StorageProof;
use std::collections::BTreeSet;

fn create_channel(chain_id: ChainId, channel_id: ChannelId) {
    let list = BTreeSet::from([chain_id]);
    ChainAllowlist::<chain_a::Runtime>::put(list);
    assert_ok!(Messenger::initiate_channel(
        RuntimeOrigin::signed(USER_ACCOUNT),
        chain_id,
    ));

    System::assert_has_event(RuntimeEvent::Messenger(
        crate::Event::<Runtime>::ChannelInitiated {
            chain_id,
            channel_id,
        },
    ));
    assert_eq!(
        Messenger::next_channel_id(chain_id),
        channel_id.checked_add(U256::one()).unwrap()
    );

    let channel = Messenger::channels(chain_id, channel_id).unwrap();
    assert_eq!(channel.state, ChannelState::Initiated);
    assert_eq!(channel.next_inbox_nonce, Nonce::zero());
    assert_eq!(channel.next_outbox_nonce, Nonce::one());
    assert_eq!(channel.latest_response_received_message_nonce, None);
    assert_eq!(
        OutboxMessageCount::<Runtime>::get((chain_id, channel_id)),
        1
    );
    let msg = Outbox::<Runtime>::get((chain_id, channel_id, Nonce::zero())).unwrap();
    assert_eq!(msg.dst_chain_id, chain_id);
    assert_eq!(msg.channel_id, channel_id);
    assert_eq!(
        msg.payload,
        VersionedPayload::V1(PayloadV1::Protocol(RequestResponse::Request(
            ProtocolMessageRequest::ChannelOpen(ChannelOpenParamsV1 {
                max_outgoing_messages: 25,
            })
        )))
    );

    System::assert_last_event(RuntimeEvent::Messenger(
        crate::Event::<Runtime>::OutboxMessage {
            chain_id,
            channel_id,
            nonce: Nonce::zero(),
        },
    ));

    // check outbox relayer storage key generation
    let query = BlockMessagesQuery {
        chain_id,
        channel_id,
        outbox_from: Nonce::zero(),
        inbox_responses_from: Nonce::zero(),
    };
    let messages_with_keys = chain_a::Messenger::get_block_messages(query);
    assert_eq!(messages_with_keys.outbox.len(), 1);
    assert_eq!(messages_with_keys.inbox_responses.len(), 0);
    let expected_key =
        Outbox::<chain_a::Runtime>::hashed_key_for((chain_id, channel_id, Nonce::zero()));
    assert_eq!(messages_with_keys.outbox[0].storage_key, expected_key);
}

fn default_consensus_proof() -> ConsensusChainMmrLeafProof<u64, H256, H256> {
    ConsensusChainMmrLeafProof {
        consensus_block_number: Default::default(),
        consensus_block_hash: Default::default(),
        opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
        proof: MmrProof {
            leaf_indices: vec![],
            leaf_count: 0,
            items: vec![],
        },
    }
}

fn close_channel(chain_id: ChainId, channel_id: ChannelId, last_delivered_nonce: Option<Nonce>) {
    assert_ok!(Messenger::close_channel(
        RuntimeOrigin::root(),
        chain_id,
        channel_id,
    ));

    let channel = Messenger::channels(chain_id, channel_id).unwrap();
    assert_eq!(channel.state, ChannelState::Closed);
    System::assert_has_event(RuntimeEvent::Messenger(
        crate::Event::<Runtime>::ChannelClosed {
            chain_id,
            channel_id,
        },
    ));

    let msg = Outbox::<Runtime>::get((chain_id, channel_id, Nonce::one())).unwrap();
    assert_eq!(msg.dst_chain_id, chain_id);
    assert_eq!(msg.channel_id, channel_id);
    assert_eq!(
        msg.last_delivered_message_response_nonce,
        last_delivered_nonce
    );
    assert_eq!(
        msg.payload,
        VersionedPayload::V1(PayloadV1::Protocol(RequestResponse::Request(
            ProtocolMessageRequest::ChannelClose
        )))
    );

    System::assert_last_event(RuntimeEvent::Messenger(
        crate::Event::<Runtime>::OutboxMessage {
            chain_id,
            channel_id,
            nonce: Nonce::one(),
        },
    ));
}

#[test]
fn test_initiate_channel() {
    new_chain_a_ext().execute_with(|| {
        let chain_id = 2.into();
        let channel_id = U256::zero();
        create_channel(chain_id, channel_id)
    });
}

#[test]
fn test_close_missing_channel() {
    new_chain_a_ext().execute_with(|| {
        let chain_id = 2.into();
        let channel_id = U256::zero();
        assert_err!(
            Messenger::close_channel(RuntimeOrigin::root(), chain_id, channel_id,),
            Error::<Runtime>::MissingChannel
        );
    });
}

#[test]
fn test_close_open_channel() {
    new_chain_a_ext().execute_with(|| {
        let chain_id = 2.into();
        let channel_id = U256::zero();
        create_channel(chain_id, channel_id);

        // open channel
        assert_ok!(Messenger::do_open_channel(chain_id, channel_id));
        let channel = Messenger::channels(chain_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Open);
        System::assert_has_event(RuntimeEvent::Messenger(
            crate::Event::<Runtime>::ChannelOpen {
                chain_id,
                channel_id,
            },
        ));

        // close channel
        close_channel(chain_id, channel_id, None)
    });
}

#[test]
fn test_storage_proof_verification_invalid() {
    let mut t = new_chain_a_ext();
    let chain_id = 2.into();
    let channel_id = U256::zero();
    t.execute_with(|| {
        create_channel(chain_id, channel_id);
        assert_ok!(Messenger::do_open_channel(chain_id, channel_id));
    });

    let (_, storage_key, storage_proof) =
        crate::mock::storage_proof_of_channels::<Runtime>(t.as_backend(), chain_id, channel_id);
    let res: Result<Channel<Balance, AccountId>, VerificationError> =
        StorageProofVerifier::<Blake2Hasher>::get_decoded_value(
            &H256::zero(),
            storage_proof,
            storage_key,
        );
    assert_err!(res, VerificationError::InvalidProof);
}

#[test]
fn test_storage_proof_verification_missing_value() {
    let mut t = new_chain_a_ext();
    let chain_id = 2.into();
    let channel_id = U256::zero();
    t.execute_with(|| {
        create_channel(chain_id, channel_id);
        assert_ok!(Messenger::do_open_channel(chain_id, channel_id));
    });

    let (state_root, _, storage_proof) =
        crate::mock::storage_proof_of_channels::<Runtime>(t.as_backend(), chain_id, U256::one());
    let res: Result<Channel<Balance, AccountId>, VerificationError> =
        StorageProofVerifier::<Blake2Hasher>::get_decoded_value(
            &state_root,
            storage_proof,
            StorageKey(vec![]),
        );
    assert_err!(res, VerificationError::MissingValue);
}

#[test]
fn test_storage_proof_verification() {
    let mut t = new_chain_a_ext();
    let chain_id = 2.into();
    let channel_id = U256::zero();
    let mut expected_channel = None;
    t.execute_with(|| {
        create_channel(chain_id, channel_id);
        assert_ok!(Messenger::do_open_channel(chain_id, channel_id));
        expected_channel = Channels::<Runtime>::get(chain_id, channel_id);
    });

    let (state_root, storage_key, storage_proof) =
        crate::mock::storage_proof_of_channels::<Runtime>(t.as_backend(), chain_id, channel_id);
    let res: Result<Channel<Balance, AccountId>, VerificationError> =
        StorageProofVerifier::<Blake2Hasher>::get_decoded_value(
            &state_root,
            storage_proof,
            storage_key,
        );

    assert!(res.is_ok());
    assert_eq!(res.unwrap(), expected_channel.unwrap())
}

fn open_channel_between_chains(
    chain_a_test_ext: &mut TestExternalities,
    chain_b_test_ext: &mut TestExternalities,
) -> ChannelId {
    let chain_a_id = chain_a::SelfChainId::get();
    let chain_b_id = chain_b::SelfChainId::get();

    // initiate channel open on chain_a
    let channel_id = chain_a_test_ext.execute_with(|| -> ChannelId {
        let channel_id = U256::zero();
        create_channel(chain_b_id, channel_id);
        channel_id
    });

    channel_relay_request_and_response(
        chain_a_test_ext,
        chain_b_test_ext,
        channel_id,
        Nonce::zero(),
        true,
        MessageWeightTag::ProtocolChannelOpen,
        None,
        true,
    );

    // check channel state be open on chain_b
    chain_b_test_ext.execute_with(|| {
        let channel = chain_b::Messenger::channels(chain_a_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Open);
        chain_b::System::assert_has_event(chain_b::RuntimeEvent::Messenger(crate::Event::<
            chain_b::Runtime,
        >::ChannelInitiated {
            chain_id: chain_a_id,
            channel_id,
        }));
        chain_b::System::assert_has_event(chain_b::RuntimeEvent::Messenger(crate::Event::<
            chain_b::Runtime,
        >::ChannelOpen {
            chain_id: chain_a_id,
            channel_id,
        }));

        // check inbox response storage key generation
        let query = BlockMessagesQuery {
            chain_id: chain_a_id,
            channel_id,
            outbox_from: Nonce::zero(),
            inbox_responses_from: Nonce::zero(),
        };
        let messages_with_keys = chain_b::Messenger::get_block_messages(query);
        assert_eq!(messages_with_keys.outbox.len(), 0);
        assert_eq!(messages_with_keys.inbox_responses.len(), 1);
        let expected_key = InboxResponses::<chain_b::Runtime>::hashed_key_for((
            chain_a_id,
            channel_id,
            Nonce::zero(),
        ));
        assert_eq!(
            messages_with_keys.inbox_responses[0].storage_key,
            expected_key
        );
    });

    // check channel state be open on chain_a
    chain_a_test_ext.execute_with(|| {
        let channel = chain_a::Messenger::channels(chain_b_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Open);
        assert_eq!(channel.next_inbox_nonce, Nonce::zero());
        assert_eq!(channel.next_outbox_nonce, Nonce::one());
        chain_a::System::assert_has_event(chain_a::RuntimeEvent::Messenger(crate::Event::<
            chain_a::Runtime,
        >::ChannelOpen {
            chain_id: chain_b_id,
            channel_id,
        }));
    });

    channel_id
}

fn send_message_between_chains(
    sender: &AccountId,
    chain_a_test_ext: &mut TestExternalities,
    chain_b_test_ext: &mut TestExternalities,
    msg: EndpointPayload,
    channel_id: ChannelId,
) {
    let chain_a_id = chain_a::SelfChainId::get();
    let chain_b_id = chain_b::SelfChainId::get();

    // send message form outbox
    chain_a_test_ext.execute_with(|| {
        let resp = <chain_a::Messenger as Sender<AccountId>>::send_message(
            sender,
            chain_b_id,
            EndpointRequest {
                src_endpoint: Endpoint::Id(0),
                dst_endpoint: Endpoint::Id(0),
                payload: msg,
            },
        );
        assert_ok!(resp);
    });

    channel_relay_request_and_response(
        chain_a_test_ext,
        chain_b_test_ext,
        channel_id,
        Nonce::one(),
        false,
        Default::default(),
        Some(Endpoint::Id(0)),
        true,
    );

    // check state on chain_b
    chain_b_test_ext.execute_with(|| {
        // Outbox, Outbox responses, Inbox, InboxResponses must be empty
        assert_eq!(
            OutboxMessageCount::<chain_b::Runtime>::get((chain_a_id, channel_id)),
            0
        );
        assert!(OutboxResponses::<chain_b::Runtime>::get().is_none());
        assert!(Inbox::<chain_b::Runtime>::get().is_none());

        // latest inbox message response is cleared on next message
        assert!(InboxResponses::<chain_b::Runtime>::contains_key((
            chain_a_id,
            channel_id,
            Nonce::one()
        )),);
    });

    // check state on chain_a
    chain_a_test_ext.execute_with(|| {
        // Outbox, Outbox responses, Inbox, InboxResponses must be empty
        assert_eq!(
            OutboxMessageCount::<chain_a::Runtime>::get((chain_b_id, channel_id)),
            0
        );
        assert!(OutboxResponses::<chain_a::Runtime>::get().is_none());
        assert!(Inbox::<chain_a::Runtime>::get().is_none());
        assert!(!InboxResponses::<chain_a::Runtime>::contains_key((
            chain_b_id,
            channel_id,
            Nonce::one()
        )));
    });
}

fn close_channel_between_chains(
    chain_a_test_ext: &mut TestExternalities,
    chain_b_test_ext: &mut TestExternalities,
    channel_id: ChannelId,
) {
    let chain_a_id = chain_a::SelfChainId::get();
    let chain_b_id = chain_b::SelfChainId::get();

    // initiate channel close on chain_a
    chain_a_test_ext.execute_with(|| {
        close_channel(chain_b_id, channel_id, None);
    });

    channel_relay_request_and_response(
        chain_a_test_ext,
        chain_b_test_ext,
        channel_id,
        Nonce::one(),
        true,
        MessageWeightTag::ProtocolChannelClose,
        None,
        true,
    );

    // check channel state be close on chain_b
    chain_b_test_ext.execute_with(|| {
        let channel = chain_b::Messenger::channels(chain_a_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Closed);
        chain_b::System::assert_has_event(chain_b::RuntimeEvent::Messenger(crate::Event::<
            chain_b::Runtime,
        >::ChannelClosed {
            chain_id: chain_a_id,
            channel_id,
        }));

        assert_eq!(channel.next_outbox_nonce, Nonce::zero());

        // Outbox, Outbox responses, Inbox, InboxResponses must be empty
        assert_eq!(
            OutboxMessageCount::<chain_b::Runtime>::get((chain_a_id, channel_id)),
            0
        );
        assert!(OutboxResponses::<chain_b::Runtime>::get().is_none());
        assert!(Inbox::<chain_b::Runtime>::get().is_none());

        // latest inbox message response is cleared on next message
        assert!(InboxResponses::<chain_b::Runtime>::contains_key((
            chain_a_id,
            channel_id,
            Nonce::one()
        )));
    });

    // check channel state be closed on chain_a
    chain_a_test_ext.execute_with(|| {
        let channel = chain_a::Messenger::channels(chain_b_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Closed);
        assert_eq!(channel.next_inbox_nonce, Nonce::zero());
        assert_eq!(
            channel.next_outbox_nonce,
            Nonce::one().checked_add(Nonce::one()).unwrap()
        );
        chain_a::System::assert_has_event(chain_a::RuntimeEvent::Messenger(crate::Event::<
            chain_a::Runtime,
        >::ChannelClosed {
            chain_id: chain_b_id,
            channel_id,
        }));

        // Outbox, Outbox responses, Inbox, InboxResponses must be empty
        assert_eq!(
            OutboxMessageCount::<chain_a::Runtime>::get((chain_b_id, channel_id)),
            0
        );
        assert!(OutboxResponses::<chain_a::Runtime>::get().is_none());
        assert!(Inbox::<chain_a::Runtime>::get().is_none());
        assert!(!InboxResponses::<chain_a::Runtime>::contains_key((
            chain_b_id,
            channel_id,
            Nonce::one()
        )));
    })
}

fn force_toggle_channel_state<Runtime: crate::Config>(
    dst_chain_id: ChainId,
    channel_id: ChannelId,
    toggle: bool,
    add_to_allow_list: bool,
) {
    let init_params = ChannelOpenParamsV1 {
        max_outgoing_messages: 100,
    };

    let channel = Pallet::<Runtime>::channels(dst_chain_id, channel_id).unwrap_or_else(|| {
        let list = BTreeSet::from([dst_chain_id]);
        if add_to_allow_list {
            ChainAllowlist::<Runtime>::put(list);
        }
        Pallet::<Runtime>::do_init_channel(
            dst_chain_id,
            init_params,
            None,
            add_to_allow_list,
            Zero::zero(),
        )
        .unwrap();
        Pallet::<Runtime>::channels(dst_chain_id, channel_id).unwrap()
    });

    if !toggle {
        return;
    }

    if channel.state == ChannelState::Initiated {
        Pallet::<Runtime>::do_open_channel(dst_chain_id, channel_id).unwrap();
    }

    if channel.state == ChannelState::Open {
        Pallet::<Runtime>::do_close_channel(dst_chain_id, channel_id, CloseChannelBy::Sudo)
            .unwrap();
    }
}

#[allow(clippy::too_many_arguments)]
fn channel_relay_request_and_response(
    chain_a_test_ext: &mut TestExternalities,
    chain_b_test_ext: &mut TestExternalities,
    channel_id: ChannelId,
    nonce: Nonce,
    toggle_channel_state: bool,
    weight_tag: MessageWeightTag,
    maybe_endpoint: Option<Endpoint>,
    add_to_allowlist: bool,
) {
    let chain_a_id = chain_a::SelfChainId::get();
    let chain_b_id = chain_b::SelfChainId::get();

    // relay message to chain_b
    let msg = chain_a_test_ext
        .execute_with(|| Outbox::<chain_a::Runtime>::get((chain_b_id, channel_id, nonce)).unwrap());
    let (_state_root, _key, message_proof) = storage_proof_of_outbox_messages::<chain_a::Runtime>(
        chain_a_test_ext.as_backend(),
        chain_b_id,
        channel_id,
        nonce,
    );

    let xdm = CrossDomainMessage {
        src_chain_id: chain_a_id,
        dst_chain_id: chain_b_id,
        channel_id,
        nonce,
        proof: Proof::Domain {
            consensus_chain_mmr_proof: default_consensus_proof(),
            domain_proof: StorageProof::empty(),
            message_proof,
        },
        weight_tag: maybe_endpoint
            .clone()
            .map(MessageWeightTag::EndpointRequest)
            .unwrap_or(weight_tag.clone()),
    };
    chain_b_test_ext.execute_with(|| {
        force_toggle_channel_state::<chain_b::Runtime>(
            chain_a_id,
            channel_id,
            toggle_channel_state,
            add_to_allowlist,
        );
        Inbox::<chain_b::Runtime>::set(Some(msg));

        // process inbox message
        let result =
            chain_b::Messenger::relay_message(crate::RawOrigin::ValidatedUnsigned.into(), xdm);
        assert_ok!(result);

        chain_b::System::assert_has_event(chain_b::RuntimeEvent::Messenger(crate::Event::<
            chain_b::Runtime,
        >::InboxMessageResponse {
            chain_id: chain_a_id,
            channel_id,
            nonce,
        }));

        let response =
            chain_b::Messenger::inbox_responses((chain_a_id, channel_id, nonce)).unwrap();
        assert_eq!(response.src_chain_id, chain_b_id);
        assert_eq!(response.dst_chain_id, chain_a_id);
        assert_eq!(response.channel_id, channel_id);
        assert_eq!(response.nonce, nonce);
        assert_eq!(chain_a::Messenger::inbox(), None);
    });

    // relay message response to chain_a
    let (_state_root, _key, message_proof) =
        storage_proof_of_inbox_message_responses::<chain_b::Runtime>(
            chain_b_test_ext.as_backend(),
            chain_a_id,
            channel_id,
            nonce,
        );

    let msg = chain_b_test_ext.execute_with(|| {
        InboxResponses::<chain_b::Runtime>::get((chain_a_id, channel_id, nonce)).unwrap()
    });

    let xdm = CrossDomainMessage {
        src_chain_id: chain_b_id,
        dst_chain_id: chain_a_id,
        channel_id,
        nonce,
        proof: Proof::Consensus {
            consensus_chain_mmr_proof: default_consensus_proof(),
            message_proof,
        },
        weight_tag: maybe_endpoint
            .clone()
            .map(MessageWeightTag::EndpointResponse)
            .unwrap_or(weight_tag),
    };
    chain_a_test_ext.execute_with(|| {
        force_toggle_channel_state::<chain_a::Runtime>(
            chain_b_id,
            channel_id,
            toggle_channel_state,
            true,
        );
        OutboxResponses::<chain_a::Runtime>::set(Some(msg));

        // process outbox message response
        let result = chain_a::Messenger::relay_message_response(
            crate::RawOrigin::ValidatedUnsigned.into(),
            xdm,
        );
        assert_ok!(result);

        // outbox message and message response should not exists
        assert_eq!(
            chain_a::Messenger::outbox((chain_b_id, channel_id, nonce)),
            None
        );
        assert_eq!(chain_a::Messenger::outbox_responses(), None);

        chain_a::System::assert_has_event(chain_a::RuntimeEvent::Messenger(crate::Event::<
            chain_a::Runtime,
        >::OutboxMessageResult {
            chain_id: chain_b_id,
            channel_id,
            nonce,
            result: OutboxMessageResult::Ok,
        }));
    })
}

#[test]
fn test_open_channel_between_chains() {
    let mut chain_a_test_ext = chain_a::new_test_ext();
    let mut chain_b_test_ext = chain_b::new_test_ext();
    // open channel between chain_a and chain_b
    // chain_a initiates the channel open
    open_channel_between_chains(&mut chain_a_test_ext, &mut chain_b_test_ext);
}

#[test]
fn test_close_channel_between_chains() {
    let mut chain_a_test_ext = chain_a::new_test_ext();
    let mut chain_b_test_ext = chain_b::new_test_ext();
    // open channel between chain_a and chain_b
    // chain_a initiates the channel open
    let channel_id = open_channel_between_chains(&mut chain_a_test_ext, &mut chain_b_test_ext);

    // close open channel
    close_channel_between_chains(&mut chain_a_test_ext, &mut chain_b_test_ext, channel_id)
}

#[test]
fn close_init_channels_between_chains() {
    let mut chain_a_test_ext = chain_a::new_test_ext();
    let mut chain_b_test_ext = chain_b::new_test_ext();

    let chain_a_id = chain_a::SelfChainId::get();
    let chain_b_id = chain_b::SelfChainId::get();

    let pre_user_account_balance = chain_a_test_ext.execute_with(|| {
        chain_a::Balances::reducible_balance(
            &USER_ACCOUNT,
            Preservation::Protect,
            Fortitude::Polite,
        )
    });

    // initiate channel open on chain_a
    let channel_id = chain_a_test_ext.execute_with(|| -> ChannelId {
        let channel_id = U256::zero();
        create_channel(chain_b_id, channel_id);
        channel_id
    });

    chain_a_test_ext.execute_with(|| {
        let channel = Channels::<chain_a::Runtime>::get(chain_b_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Initiated)
    });

    let post_channel_init_balance = chain_a_test_ext.execute_with(|| {
        chain_a::Balances::reducible_balance(
            &USER_ACCOUNT,
            Preservation::Protect,
            Fortitude::Polite,
        )
    });

    assert_eq!(
        post_channel_init_balance,
        pre_user_account_balance - chain_a::ChannelReserveFee::get()
    );

    channel_relay_request_and_response(
        &mut chain_a_test_ext,
        &mut chain_b_test_ext,
        channel_id,
        Nonce::zero(),
        false,
        MessageWeightTag::ProtocolChannelOpen,
        None,
        false,
    );

    chain_a_test_ext.execute_with(|| {
        let channel = Channels::<chain_a::Runtime>::get(chain_b_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Initiated)
    });

    chain_b_test_ext.execute_with(|| {
        let channel = Channels::<chain_b::Runtime>::get(chain_a_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Initiated)
    });

    // close channel
    chain_a_test_ext.execute_with(|| close_channel(chain_b_id, channel_id, None));

    chain_a_test_ext.execute_with(|| {
        let channel = Channels::<chain_a::Runtime>::get(chain_b_id, channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Closed)
    });

    let post_channel_close_balance = chain_a_test_ext.execute_with(|| {
        chain_a::Balances::reducible_balance(
            &USER_ACCOUNT,
            Preservation::Protect,
            Fortitude::Polite,
        )
    });

    // user will only get 80% of reserve since 20% is taken by the protocol
    let protocol_fee =
        chain_a::ChannelInitReservePortion::get() * chain_a::ChannelReserveFee::get();
    assert_eq!(
        post_channel_close_balance,
        pre_user_account_balance - protocol_fee
    );
}

#[test]
fn test_update_consensus_channel_allowlist() {
    let mut consensus_chain_test_ext = consensus_chain::new_test_ext();
    let channel_id = U256::zero();
    // open channel between chain_a and chain_b
    consensus_chain_test_ext.execute_with(|| {
        Channels::<consensus_chain::Runtime>::set(
            chain_b::SelfChainId::get(),
            channel_id,
            Some(Channel {
                channel_id,
                state: ChannelState::Open,
                next_inbox_nonce: Default::default(),
                next_outbox_nonce: Default::default(),
                latest_response_received_message_nonce: None,
                max_outgoing_messages: 10,
                maybe_owner: None,
                channel_reserve_fee: Default::default(),
            }),
        );
    });

    let chain_allowlist = ChainAllowlistUpdate::Remove(chain_b::SelfChainId::get());
    consensus_chain_test_ext.execute_with(|| {
        let channel =
            Channels::<consensus_chain::Runtime>::get(chain_b::SelfChainId::get(), channel_id)
                .unwrap();
        assert_eq!(channel.state, ChannelState::Open);

        Pallet::<consensus_chain::Runtime>::update_consensus_chain_allowlist(
            consensus_chain::RuntimeOrigin::root(),
            chain_allowlist,
        )
        .unwrap();
    });
}

#[test]
fn test_update_domain_channel_allowlist() {
    let mut chain_a_test_ext = chain_a::new_test_ext();
    let mut chain_b_test_ext = chain_b::new_test_ext();
    // open channel between chain_a and chain_b
    // chain_a initiates the channel open
    let channel_id = open_channel_between_chains(&mut chain_a_test_ext, &mut chain_b_test_ext);

    let chain_allowlist = DomainAllowlistUpdates {
        allow_chains: Default::default(),
        remove_chains: BTreeSet::from([chain_b::SelfChainId::get()]),
    };
    chain_a_test_ext.execute_with(|| {
        let channel =
            Channels::<chain_a::Runtime>::get(chain_b::SelfChainId::get(), channel_id).unwrap();
        assert_eq!(channel.state, ChannelState::Open);

        Pallet::<chain_a::Runtime>::update_domain_allowlist(
            RuntimeOrigin::none(),
            chain_allowlist.clone(),
        )
        .unwrap();
    });
}

#[test]
fn test_send_message_between_chains() {
    let mut chain_a_test_ext = chain_a::new_test_ext();
    let mut chain_b_test_ext = chain_b::new_test_ext();
    // open channel between chain_a and chain_b
    // chain_a initiates the channel open
    let channel_id = open_channel_between_chains(&mut chain_a_test_ext, &mut chain_b_test_ext);

    // send message
    send_message_between_chains(
        &1,
        &mut chain_a_test_ext,
        &mut chain_b_test_ext,
        vec![1, 2, 3, 4],
        channel_id,
    )
}

fn initiate_transfer_on_chain(chain_a_ext: &mut TestExternalities) {
    // this account should have 1000 balance on each chain
    let account_id = 1;
    chain_a_ext.execute_with(|| {
        let res = chain_a::Transporter::transfer(
            chain_a::RuntimeOrigin::signed(account_id),
            Location {
                chain_id: chain_b::SelfChainId::get(),
                account_id: chain_b::MockAccountIdConverter::convert(account_id),
            },
            500,
        );
        assert_ok!(res);
        chain_a::System::assert_has_event(chain_a::RuntimeEvent::Transporter(
            pallet_transporter::Event::<chain_a::Runtime>::OutgoingTransferInitiated {
                chain_id: chain_b::SelfChainId::get(),
                message_id: (U256::zero(), U256::one()),
                amount: 500,
            },
        ));
        chain_a::System::assert_has_event(chain_a::RuntimeEvent::Messenger(crate::Event::<
            chain_a::Runtime,
        >::OutboxMessage {
            chain_id: chain_b::SelfChainId::get(),
            channel_id: U256::zero(),
            nonce: U256::one(),
        }));
        assert!(
            chain_a::Transporter::outgoing_transfers(
                chain_b::SelfChainId::get(),
                (U256::zero(), U256::one()),
            )
            .is_some()
        )
    })
}

fn verify_transfer_on_chain(
    chain_a_ext: &mut TestExternalities,
    chain_b_ext: &mut TestExternalities,
) {
    // this account should have 496 balance with 1 fee left
    // chain a should have
    //   a successful event
    //   reduced balance
    //   empty state
    let account_id = 1;
    chain_a_ext.execute_with(|| {
        chain_a::System::assert_has_event(chain_a::RuntimeEvent::Transporter(
            pallet_transporter::Event::<chain_a::Runtime>::OutgoingTransferSuccessful {
                chain_id: chain_b::SelfChainId::get(),
                message_id: (U256::zero(), U256::one()),
            },
        ));
        assert!(
            chain_a::Transporter::outgoing_transfers(
                chain_b::SelfChainId::get(),
                (U256::zero(), U256::one()),
            )
            .is_none()
        )
    });

    // chain a should have
    //   a successful event incoming event
    //   increased balance
    chain_b_ext.execute_with(|| {
        chain_b::System::assert_has_event(chain_b::RuntimeEvent::Transporter(
            pallet_transporter::Event::<chain_b::Runtime>::IncomingTransferSuccessful {
                chain_id: chain_a::SelfChainId::get(),
                message_id: (U256::zero(), U256::one()),
                amount: 500,
            },
        ));
        chain_b::System::assert_has_event(chain_b::RuntimeEvent::Messenger(crate::Event::<
            chain_b::Runtime,
        >::InboxMessageResponse {
            chain_id: chain_a::SelfChainId::get(),
            channel_id: U256::zero(),
            nonce: U256::one(),
        }));
        assert_eq!(chain_b::Balances::free_balance(account_id), 500000500);
    })
}

#[test]
fn test_transport_funds_between_chains() {
    let mut chain_a_test_ext = chain_a::new_test_ext();
    let mut chain_b_test_ext = chain_b::new_test_ext();

    // open channel between chain_a and chain_b
    // chain_a initiates the channel open
    let channel_id = open_channel_between_chains(&mut chain_a_test_ext, &mut chain_b_test_ext);

    // initiate transfer
    initiate_transfer_on_chain(&mut chain_a_test_ext);

    // relay message
    channel_relay_request_and_response(
        &mut chain_a_test_ext,
        &mut chain_b_test_ext,
        channel_id,
        Nonce::one(),
        false,
        Default::default(),
        Some(Endpoint::Id(100)),
        true,
    );

    // post check
    verify_transfer_on_chain(&mut chain_a_test_ext, &mut chain_b_test_ext)
}

#[test]
fn test_transport_funds_between_chains_if_src_chain_disallows_after_message_is_sent() {
    let mut chain_a_test_ext = chain_a::new_test_ext();
    let mut chain_b_test_ext = chain_b::new_test_ext();

    // open channel between chain_a and chain_b
    // chain_a initiates the channel open
    let channel_id = open_channel_between_chains(&mut chain_a_test_ext, &mut chain_b_test_ext);

    // initiate transfer
    initiate_transfer_on_chain(&mut chain_a_test_ext);

    // remove chain_b from allowlist
    chain_a_test_ext.execute_with(ChainAllowlist::<chain_a::Runtime>::kill);

    // relay message
    channel_relay_request_and_response(
        &mut chain_a_test_ext,
        &mut chain_b_test_ext,
        channel_id,
        Nonce::one(),
        false,
        Default::default(),
        Some(Endpoint::Id(100)),
        true,
    );

    // post check should be successful since the chain_a already initiated the
    // transfer before removing chain_b from allowlist
    verify_transfer_on_chain(&mut chain_a_test_ext, &mut chain_b_test_ext)
}

#[test]
fn test_transport_funds_between_chains_if_dst_chain_disallows_after_message_is_sent() {
    let mut chain_a_test_ext = chain_a::new_test_ext();
    let mut chain_b_test_ext = chain_b::new_test_ext();

    // open channel between chain_a and chain_b
    // chain_a initiates the channel open
    let channel_id = open_channel_between_chains(&mut chain_a_test_ext, &mut chain_b_test_ext);

    // initiate transfer
    let account_id = 1;
    let pre_transfer_balance =
        chain_a_test_ext.execute_with(|| chain_a::Balances::total_balance(&account_id));

    initiate_transfer_on_chain(&mut chain_a_test_ext);

    let post_transfer_balance =
        chain_a_test_ext.execute_with(|| chain_a::Balances::total_balance(&account_id));
    // The transferred fund + relay fee should be deducted
    assert!(post_transfer_balance < pre_transfer_balance - 500);

    // remove chain_b from allowlist
    chain_b_test_ext.execute_with(ChainAllowlist::<chain_b::Runtime>::kill);

    // relay message
    channel_relay_request_and_response(
        &mut chain_a_test_ext,
        &mut chain_b_test_ext,
        channel_id,
        Nonce::one(),
        false,
        Default::default(),
        Some(Endpoint::Id(100)),
        true,
    );

    // post check should be not be successful since the chain_b rejected the transfer
    chain_a_test_ext.execute_with(|| {
        chain_a::System::assert_has_event(chain_a::RuntimeEvent::Transporter(
            pallet_transporter::Event::<chain_a::Runtime>::OutgoingTransferFailed {
                chain_id: chain_b::SelfChainId::get(),
                message_id: (U256::zero(), U256::one()),
                err: Error::<chain_a::Runtime>::ChainNotAllowed.into(),
            },
        ));
        assert!(
            chain_a::Transporter::outgoing_transfers(
                chain_b::SelfChainId::get(),
                (U256::zero(), U256::one()),
            )
            .is_none()
        )
    });

    // chain_b should not have successful event from transporter
    // just inbox message response
    chain_b_test_ext.execute_with(|| {
        chain_b::System::assert_has_event(chain_b::RuntimeEvent::Messenger(crate::Event::<
            chain_b::Runtime,
        >::InboxMessageResponse {
            chain_id: chain_a::SelfChainId::get(),
            channel_id: U256::zero(),
            nonce: U256::one(),
        }));
    });

    let post_response_balance =
        chain_a_test_ext.execute_with(|| chain_a::Balances::total_balance(&account_id));
    // The transferred fund should be refunded
    assert_eq!(post_response_balance, post_transfer_balance + 500);

    // The relayer fee and inbox execution fee should be moved to the dst chain and
    // distribute to the operator of the dst chain later
    chain_b_test_ext.execute_with(|| {
        assert_eq!(1, InboxFee::<chain_b::Runtime>::iter().count());
    });
}

#[test]
fn test_transport_funds_between_chains_failed_low_balance() {
    let mut chain_a_test_ext = chain_a::new_test_ext();
    let mut chain_b_test_ext = chain_b::new_test_ext();
    // open channel between chain_a and chain_b
    // chain_a initiates the channel open
    open_channel_between_chains(&mut chain_a_test_ext, &mut chain_b_test_ext);

    // initiate transfer
    let account_id = 100;
    chain_a_test_ext.execute_with(|| {
        let res = chain_a::Transporter::transfer(
            chain_a::RuntimeOrigin::signed(account_id),
            Location {
                chain_id: chain_b::SelfChainId::get(),
                account_id: chain_b::MockAccountIdConverter::convert(account_id),
            },
            500,
        );
        assert_err!(
            res,
            pallet_transporter::Error::<chain_a::Runtime>::LowBalance
        );
    });
}

#[test]
fn test_transport_funds_between_chains_failed_no_open_channel() {
    let mut chain_a_test_ext = chain_a::new_test_ext();

    // initiate transfer
    let account_id = 1;
    chain_a_test_ext.execute_with(|| {
        ChainAllowlist::<chain_a::Runtime>::set(BTreeSet::from([chain_b::SelfChainId::get()]));
        let res = chain_a::Transporter::transfer(
            chain_a::RuntimeOrigin::signed(account_id),
            Location {
                chain_id: chain_b::SelfChainId::get(),
                account_id: chain_b::MockAccountIdConverter::convert(account_id),
            },
            500,
        );
        assert_err!(res, crate::Error::<chain_a::Runtime>::NoOpenChannel);
    });
}

#[cfg(feature = "runtime-benchmarks")]
mod benchmark_fixtures_gen {
    use super::*;
    use crate::mock::{
        chain_a, chain_b, consensus_chain, storage_proof_of_domain_state_root,
        storage_proof_of_inbox_message_responses, storage_proof_of_outbox_messages,
    };
    use crate::pallet::{ChainAllowlist, Inbox, Outbox};
    use crate::tests::force_toggle_channel_state;
    use crate::{Config, Pallet};
    use frame_support::assert_ok;
    use frame_support::pallet_prelude::{Decode, Encode};
    use sp_core::H256;
    use sp_domains::ChannelId;
    use sp_domains::execution_receipt::execution_receipt_v0::ExecutionReceiptV0;
    use sp_domains::execution_receipt::{BlockFees, ExecutionReceipt, Transfers};
    use sp_messenger::messages::{CrossDomainMessage, MessageWeightTag, Nonce, Proof};
    use sp_mmr_primitives::EncodableOpaqueLeaf;
    use sp_subspace_mmr::ConsensusChainMmrLeafProof;
    use std::collections::BTreeSet;
    use std::fs;

    #[derive(Encode, Decode, PartialEq, Debug)]
    pub(crate) struct FromConsensusRelayMessage<T: Config> {
        pub(crate) state_root: T::Hash,
        pub(crate) xdm: CrossDomainMessage<u32, T::Hash, T::MmrHash>,
    }

    #[test]
    fn test_from_consensus_relay_message_channel_open() {
        let mut chain_test_ext = consensus_chain::new_test_ext();
        let dst_chain = chain_a::SelfChainId::get();
        let channel_id = ChannelId::zero();
        let nonce = Nonce::zero();

        chain_test_ext.execute_with(|| {
            let list = BTreeSet::from([dst_chain]);
            ChainAllowlist::<consensus_chain::Runtime>::put(list);
            assert_ok!(Pallet::<consensus_chain::Runtime>::initiate_channel(
                consensus_chain::RuntimeOrigin::signed(USER_ACCOUNT),
                dst_chain,
            ));
            assert!(
                Outbox::<consensus_chain::Runtime>::get((dst_chain, channel_id, nonce)).is_some()
            )
        });

        let (state_root, _, message_proof) =
            storage_proof_of_outbox_messages::<consensus_chain::Runtime>(
                chain_test_ext.as_backend(),
                dst_chain,
                channel_id,
                nonce,
            );

        let xdm = CrossDomainMessage {
            src_chain_id: consensus_chain::SelfChainId::get(),
            dst_chain_id: dst_chain,
            channel_id,
            nonce,
            proof: Proof::Consensus {
                consensus_chain_mmr_proof: ConsensusChainMmrLeafProof::<u32, H256, H256> {
                    consensus_block_number: Default::default(),
                    consensus_block_hash: Default::default(),
                    opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                    proof: MmrProof {
                        leaf_indices: vec![],
                        leaf_count: 0,
                        items: vec![],
                    },
                },
                message_proof,
            },
            weight_tag: MessageWeightTag::ProtocolChannelOpen,
        };

        let data =
            FromConsensusRelayMessage::<consensus_chain::Runtime> { state_root, xdm }.encode();
        fs::write(
            "./src/extensions/fixtures/from_consensus_relay_message_channel_open.data",
            data.clone(),
        )
        .unwrap();
    }

    #[test]
    fn test_from_consensus_relay_message_channel_close() {
        let mut chain_test_ext = consensus_chain::new_test_ext();
        let dst_chain = chain_a::SelfChainId::get();
        let channel_id = ChannelId::zero();
        let nonce = Nonce::one();

        chain_test_ext.execute_with(|| {
            let list = BTreeSet::from([dst_chain]);
            ChainAllowlist::<consensus_chain::Runtime>::put(list);
            assert_ok!(Pallet::<consensus_chain::Runtime>::initiate_channel(
                consensus_chain::RuntimeOrigin::signed(USER_ACCOUNT),
                dst_chain,
            ));

            assert_ok!(Pallet::<consensus_chain::Runtime>::do_open_channel(
                dst_chain, channel_id
            ));

            assert_ok!(Pallet::<consensus_chain::Runtime>::close_channel(
                consensus_chain::RuntimeOrigin::root(),
                dst_chain,
                channel_id
            ));
            assert!(
                Outbox::<consensus_chain::Runtime>::get((dst_chain, channel_id, nonce)).is_some()
            );
        });

        let (state_root, _, message_proof) =
            storage_proof_of_outbox_messages::<consensus_chain::Runtime>(
                chain_test_ext.as_backend(),
                dst_chain,
                channel_id,
                nonce,
            );

        let xdm = CrossDomainMessage {
            src_chain_id: consensus_chain::SelfChainId::get(),
            dst_chain_id: dst_chain,
            channel_id,
            nonce,
            proof: Proof::Consensus {
                consensus_chain_mmr_proof: ConsensusChainMmrLeafProof::<u32, H256, H256> {
                    consensus_block_number: Default::default(),
                    consensus_block_hash: Default::default(),
                    opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                    proof: MmrProof {
                        leaf_indices: vec![],
                        leaf_count: 0,
                        items: vec![],
                    },
                },
                message_proof,
            },
            weight_tag: MessageWeightTag::ProtocolChannelClose,
        };

        let data =
            FromConsensusRelayMessage::<consensus_chain::Runtime> { state_root, xdm }.encode();
        fs::write(
            "./src/extensions/fixtures/from_consensus_relay_message.data",
            data.clone(),
        )
        .unwrap();
    }

    #[test]
    fn test_from_consensus_relay_message_response() {
        let mut chain_test_ext = consensus_chain::new_test_ext();
        let mut chain_a_test_ext = chain_a::new_test_ext();
        let dst_chain = consensus_chain::SelfChainId::get();
        let channel_id = ChannelId::zero();
        let nonce = Nonce::zero();

        let msg = chain_a_test_ext.execute_with(|| {
            let list = BTreeSet::from([dst_chain]);
            ChainAllowlist::<chain_a::Runtime>::put(list);
            assert_ok!(Pallet::<chain_a::Runtime>::initiate_channel(
                chain_a::RuntimeOrigin::signed(USER_ACCOUNT),
                dst_chain,
            ));
            Outbox::<chain_a::Runtime>::get((dst_chain, channel_id, nonce)).unwrap()
        });

        let (_, _, message_proof) = storage_proof_of_outbox_messages::<chain_a::Runtime>(
            chain_a_test_ext.as_backend(),
            dst_chain,
            channel_id,
            nonce,
        );

        let xdm = CrossDomainMessage {
            src_chain_id: chain_a::SelfChainId::get(),
            dst_chain_id: dst_chain,
            channel_id,
            nonce,
            proof: Proof::Consensus {
                consensus_chain_mmr_proof: ConsensusChainMmrLeafProof::<u64, H256, H256> {
                    consensus_block_number: Default::default(),
                    consensus_block_hash: Default::default(),
                    opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                    proof: MmrProof {
                        leaf_indices: vec![],
                        leaf_count: 0,
                        items: vec![],
                    },
                },
                message_proof,
            },
            weight_tag: MessageWeightTag::ProtocolChannelOpen,
        };

        chain_test_ext.execute_with(|| {
            force_toggle_channel_state::<consensus_chain::Runtime>(
                chain_a::SelfChainId::get(),
                channel_id,
                false,
                true,
            );
            Inbox::<chain_b::Runtime>::set(Some(msg));

            // process inbox message
            let result = Pallet::<consensus_chain::Runtime>::relay_message(
                crate::RawOrigin::ValidatedUnsigned.into(),
                xdm,
            );

            assert_ok!(result);

            consensus_chain::Messenger::inbox_responses((
                chain_a::SelfChainId::get(),
                channel_id,
                nonce,
            ))
            .unwrap();
        });

        // relay message response to chain_a
        let (state_root, _key, message_proof) =
            storage_proof_of_inbox_message_responses::<consensus_chain::Runtime>(
                chain_test_ext.as_backend(),
                chain_a::SelfChainId::get(),
                channel_id,
                nonce,
            );

        let xdm = CrossDomainMessage {
            src_chain_id: consensus_chain::SelfChainId::get(),
            dst_chain_id: chain_a::SelfChainId::get(),
            channel_id,
            nonce,
            proof: Proof::Consensus {
                consensus_chain_mmr_proof: ConsensusChainMmrLeafProof::<u32, H256, H256> {
                    consensus_block_number: Default::default(),
                    consensus_block_hash: Default::default(),
                    opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                    proof: MmrProof {
                        leaf_indices: vec![],
                        leaf_count: 0,
                        items: vec![],
                    },
                },
                message_proof,
            },
            weight_tag: MessageWeightTag::ProtocolChannelOpen,
        };

        let data =
            FromConsensusRelayMessage::<consensus_chain::Runtime> { state_root, xdm }.encode();
        fs::write(
            "./src/extensions/fixtures/from_consensus_relay_message_response.data",
            data.clone(),
        )
        .unwrap();
    }

    #[test]
    fn test_from_domains_relay_message_channel_open() {
        let mut chain_test_ext = chain_a::new_test_ext();
        let dst_chain = consensus_chain::SelfChainId::get();
        let channel_id = ChannelId::zero();
        let nonce = Nonce::zero();

        chain_test_ext.execute_with(|| {
            let list = BTreeSet::from([dst_chain]);
            ChainAllowlist::<chain_a::Runtime>::put(list);
            assert_ok!(Pallet::<chain_a::Runtime>::initiate_channel(
                chain_a::RuntimeOrigin::signed(USER_ACCOUNT),
                dst_chain,
            ));
            assert!(Outbox::<chain_a::Runtime>::get((dst_chain, channel_id, nonce)).is_some())
        });

        let (state_root, _key, message_proof) = storage_proof_of_outbox_messages::<chain_a::Runtime>(
            chain_test_ext.as_backend(),
            dst_chain,
            channel_id,
            nonce,
        );

        let er = ExecutionReceipt::V0(ExecutionReceiptV0 {
            domain_block_number: Default::default(),
            domain_block_hash: Default::default(),
            domain_block_extrinsic_root: Default::default(),
            parent_domain_block_receipt_hash: Default::default(),
            consensus_block_number: Default::default(),
            consensus_block_hash: Default::default(),
            inboxed_bundles: vec![],
            final_state_root: state_root,
            execution_trace: vec![],
            execution_trace_root: Default::default(),
            block_fees: BlockFees::default(),
            transfers: Transfers::default(),
        });

        let mut consensus_chain_ext = consensus_chain::new_test_ext();
        consensus_chain_ext.execute_with(|| {
            crate::mock::pallet_domains::LatestConfirmedDomainExecutionReceipt::<
                consensus_chain::Runtime,
            >::insert(
                chain_a::SelfChainId::get().maybe_domain_chain().unwrap(),
                er,
            );
        });

        let (state_root, _key, domain_proof) =
            storage_proof_of_domain_state_root::<consensus_chain::Runtime>(
                consensus_chain_ext.as_backend(),
                chain_a::SelfChainId::get().maybe_domain_chain().unwrap(),
            );

        let xdm = CrossDomainMessage {
            src_chain_id: chain_a::SelfChainId::get(),
            dst_chain_id: dst_chain,
            channel_id,
            nonce,
            proof: Proof::Domain {
                consensus_chain_mmr_proof: ConsensusChainMmrLeafProof::<u32, H256, H256> {
                    consensus_block_number: Default::default(),
                    consensus_block_hash: Default::default(),
                    opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                    proof: MmrProof {
                        leaf_indices: vec![],
                        leaf_count: 0,
                        items: vec![],
                    },
                },
                domain_proof,
                message_proof,
            },
            weight_tag: MessageWeightTag::ProtocolChannelOpen,
        };

        let data =
            FromConsensusRelayMessage::<consensus_chain::Runtime> { state_root, xdm }.encode();
        fs::write(
            "./src/extensions/fixtures/from_domains_relay_message_channel_open.data",
            data.clone(),
        )
        .unwrap();
    }

    #[test]
    fn test_from_domains_relay_message_channel_close() {
        let mut chain_test_ext = chain_a::new_test_ext();
        let dst_chain = consensus_chain::SelfChainId::get();
        let channel_id = ChannelId::zero();
        let nonce = Nonce::one();

        chain_test_ext.execute_with(|| {
            let list = BTreeSet::from([dst_chain]);
            ChainAllowlist::<chain_a::Runtime>::put(list);
            assert_ok!(Pallet::<chain_a::Runtime>::initiate_channel(
                chain_a::RuntimeOrigin::signed(USER_ACCOUNT),
                dst_chain,
            ));

            assert_ok!(Pallet::<chain_a::Runtime>::do_open_channel(
                dst_chain, channel_id
            ));

            assert_ok!(Pallet::<chain_a::Runtime>::close_channel(
                chain_a::RuntimeOrigin::root(),
                dst_chain,
                channel_id
            ));
            assert!(Outbox::<chain_a::Runtime>::get((dst_chain, channel_id, nonce)).is_some());
        });

        let (state_root, _, message_proof) = storage_proof_of_outbox_messages::<chain_a::Runtime>(
            chain_test_ext.as_backend(),
            dst_chain,
            channel_id,
            nonce,
        );

        let er = ExecutionReceipt::V0(ExecutionReceiptV0 {
            domain_block_number: Default::default(),
            domain_block_hash: Default::default(),
            domain_block_extrinsic_root: Default::default(),
            parent_domain_block_receipt_hash: Default::default(),
            consensus_block_number: Default::default(),
            consensus_block_hash: Default::default(),
            inboxed_bundles: vec![],
            final_state_root: state_root,
            execution_trace: vec![],
            execution_trace_root: Default::default(),
            block_fees: BlockFees::default(),
            transfers: Transfers::default(),
        });

        let mut consensus_chain_ext = consensus_chain::new_test_ext();
        consensus_chain_ext.execute_with(|| {
            crate::mock::pallet_domains::LatestConfirmedDomainExecutionReceipt::<
                consensus_chain::Runtime,
            >::insert(
                chain_a::SelfChainId::get().maybe_domain_chain().unwrap(),
                er,
            );
        });

        let (state_root, _key, domain_proof) =
            storage_proof_of_domain_state_root::<consensus_chain::Runtime>(
                consensus_chain_ext.as_backend(),
                chain_a::SelfChainId::get().maybe_domain_chain().unwrap(),
            );

        let xdm = CrossDomainMessage {
            src_chain_id: chain_a::SelfChainId::get(),
            dst_chain_id: dst_chain,
            channel_id,
            nonce,
            proof: Proof::Domain {
                consensus_chain_mmr_proof: ConsensusChainMmrLeafProof::<u32, H256, H256> {
                    consensus_block_number: Default::default(),
                    consensus_block_hash: Default::default(),
                    opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                    proof: MmrProof {
                        leaf_indices: vec![],
                        leaf_count: 0,
                        items: vec![],
                    },
                },
                domain_proof,
                message_proof,
            },
            weight_tag: MessageWeightTag::ProtocolChannelClose,
        };

        let data = FromConsensusRelayMessage::<chain_a::Runtime> { state_root, xdm }.encode();
        fs::write(
            "./src/extensions/fixtures/from_domains_relay_message.data",
            data.clone(),
        )
        .unwrap();
    }

    #[test]
    fn test_from_domains_relay_message_response() {
        let mut chain_a_test_ext = chain_a::new_test_ext();
        let mut chain_consensus_test_ext = consensus_chain::new_test_ext();
        let dst_chain = chain_a::SelfChainId::get();
        let channel_id = ChannelId::zero();
        let nonce = Nonce::zero();

        let msg = chain_consensus_test_ext.execute_with(|| {
            let list = BTreeSet::from([dst_chain]);
            ChainAllowlist::<consensus_chain::Runtime>::put(list);
            assert_ok!(Pallet::<consensus_chain::Runtime>::initiate_channel(
                consensus_chain::RuntimeOrigin::signed(USER_ACCOUNT),
                dst_chain,
            ));
            Outbox::<consensus_chain::Runtime>::get((dst_chain, channel_id, nonce)).unwrap()
        });

        let (_, _, message_proof) = storage_proof_of_outbox_messages::<consensus_chain::Runtime>(
            chain_consensus_test_ext.as_backend(),
            dst_chain,
            channel_id,
            nonce,
        );

        let xdm = CrossDomainMessage {
            src_chain_id: consensus_chain::SelfChainId::get(),
            dst_chain_id: dst_chain,
            channel_id,
            nonce,
            proof: Proof::Consensus {
                consensus_chain_mmr_proof: ConsensusChainMmrLeafProof::<u64, H256, H256> {
                    consensus_block_number: Default::default(),
                    consensus_block_hash: Default::default(),
                    opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                    proof: MmrProof {
                        leaf_indices: vec![],
                        leaf_count: 0,
                        items: vec![],
                    },
                },
                message_proof,
            },
            weight_tag: MessageWeightTag::ProtocolChannelOpen,
        };

        chain_a_test_ext.execute_with(|| {
            force_toggle_channel_state::<chain_a::Runtime>(
                consensus_chain::SelfChainId::get(),
                channel_id,
                false,
                true,
            );
            Inbox::<chain_a::Runtime>::set(Some(msg));

            // process inbox message
            let result = Pallet::<chain_a::Runtime>::relay_message(
                crate::RawOrigin::ValidatedUnsigned.into(),
                xdm,
            );

            assert_ok!(result);

            chain_a::Messenger::inbox_responses((
                consensus_chain::SelfChainId::get(),
                channel_id,
                nonce,
            ))
            .unwrap();
        });

        // relay message response to chain_consensus
        let (state_root, _key, message_proof) =
            storage_proof_of_inbox_message_responses::<chain_a::Runtime>(
                chain_a_test_ext.as_backend(),
                consensus_chain::SelfChainId::get(),
                channel_id,
                nonce,
            );

        let er = ExecutionReceipt::V0(ExecutionReceiptV0 {
            domain_block_number: Default::default(),
            domain_block_hash: Default::default(),
            domain_block_extrinsic_root: Default::default(),
            parent_domain_block_receipt_hash: Default::default(),
            consensus_block_number: Default::default(),
            consensus_block_hash: Default::default(),
            inboxed_bundles: vec![],
            final_state_root: state_root,
            execution_trace: vec![],
            execution_trace_root: Default::default(),
            block_fees: BlockFees::default(),
            transfers: Transfers::default(),
        });

        chain_consensus_test_ext.execute_with(|| {
            crate::mock::pallet_domains::LatestConfirmedDomainExecutionReceipt::<
                consensus_chain::Runtime,
            >::insert(
                chain_a::SelfChainId::get().maybe_domain_chain().unwrap(),
                er,
            );
        });

        let (state_root, _key, domain_proof) =
            storage_proof_of_domain_state_root::<consensus_chain::Runtime>(
                chain_consensus_test_ext.as_backend(),
                chain_a::SelfChainId::get().maybe_domain_chain().unwrap(),
            );

        let xdm = CrossDomainMessage {
            src_chain_id: chain_a::SelfChainId::get(),
            dst_chain_id: consensus_chain::SelfChainId::get(),
            channel_id,
            nonce,
            proof: Proof::Domain {
                consensus_chain_mmr_proof: ConsensusChainMmrLeafProof::<u32, H256, H256> {
                    consensus_block_number: Default::default(),
                    consensus_block_hash: Default::default(),
                    opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                    proof: MmrProof {
                        leaf_indices: vec![],
                        leaf_count: 0,
                        items: vec![],
                    },
                },
                domain_proof,
                message_proof,
            },
            weight_tag: MessageWeightTag::ProtocolChannelOpen,
        };

        let data =
            FromConsensusRelayMessage::<consensus_chain::Runtime> { state_root, xdm }.encode();
        fs::write(
            "./src/extensions/fixtures/from_domains_relay_message_response.data",
            data.clone(),
        )
        .unwrap();
    }

    #[test]
    fn test_between_domains_relay_message_channel_open() {
        let mut chain_test_ext = chain_b::new_test_ext();
        let dst_chain = chain_a::SelfChainId::get();
        let channel_id = ChannelId::zero();
        let nonce = Nonce::zero();

        chain_test_ext.execute_with(|| {
            let list = BTreeSet::from([dst_chain]);
            ChainAllowlist::<chain_b::Runtime>::put(list);
            assert_ok!(Pallet::<chain_b::Runtime>::initiate_channel(
                chain_b::RuntimeOrigin::signed(USER_ACCOUNT),
                dst_chain,
            ));
            assert!(Outbox::<chain_b::Runtime>::get((dst_chain, channel_id, nonce)).is_some())
        });

        let (state_root, _, message_proof) = storage_proof_of_outbox_messages::<chain_b::Runtime>(
            chain_test_ext.as_backend(),
            dst_chain,
            channel_id,
            nonce,
        );

        let xdm = CrossDomainMessage {
            src_chain_id: chain_b::SelfChainId::get(),
            dst_chain_id: dst_chain,
            channel_id,
            nonce,
            proof: Proof::Consensus {
                consensus_chain_mmr_proof: ConsensusChainMmrLeafProof::<u32, H256, H256> {
                    consensus_block_number: Default::default(),
                    consensus_block_hash: Default::default(),
                    opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                    proof: MmrProof {
                        leaf_indices: vec![],
                        leaf_count: 0,
                        items: vec![],
                    },
                },
                message_proof,
            },
            weight_tag: MessageWeightTag::ProtocolChannelOpen,
        };

        let data = FromConsensusRelayMessage::<chain_b::Runtime> { state_root, xdm }.encode();
        fs::write(
            "./src/extensions/fixtures/between_domains_relay_message_channel_open.data",
            data.clone(),
        )
        .unwrap();
    }

    #[test]
    fn test_between_domains_relay_message_channel_close() {
        let mut chain_test_ext = chain_b::new_test_ext();
        let dst_chain = chain_a::SelfChainId::get();
        let channel_id = ChannelId::zero();
        let nonce = Nonce::one();

        chain_test_ext.execute_with(|| {
            let list = BTreeSet::from([dst_chain]);
            ChainAllowlist::<chain_b::Runtime>::put(list);
            assert_ok!(Pallet::<chain_b::Runtime>::initiate_channel(
                chain_b::RuntimeOrigin::signed(USER_ACCOUNT),
                dst_chain,
            ));

            assert_ok!(Pallet::<chain_b::Runtime>::do_open_channel(
                dst_chain, channel_id
            ));

            assert_ok!(Pallet::<chain_b::Runtime>::close_channel(
                chain_b::RuntimeOrigin::root(),
                dst_chain,
                channel_id
            ));
            assert!(Outbox::<chain_b::Runtime>::get((dst_chain, channel_id, nonce)).is_some());
        });

        let (state_root, _, message_proof) = storage_proof_of_outbox_messages::<chain_b::Runtime>(
            chain_test_ext.as_backend(),
            dst_chain,
            channel_id,
            nonce,
        );

        let xdm = CrossDomainMessage {
            src_chain_id: chain_b::SelfChainId::get(),
            dst_chain_id: dst_chain,
            channel_id,
            nonce,
            proof: Proof::Consensus {
                consensus_chain_mmr_proof: ConsensusChainMmrLeafProof::<u32, H256, H256> {
                    consensus_block_number: Default::default(),
                    consensus_block_hash: Default::default(),
                    opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                    proof: MmrProof {
                        leaf_indices: vec![],
                        leaf_count: 0,
                        items: vec![],
                    },
                },
                message_proof,
            },
            weight_tag: MessageWeightTag::ProtocolChannelClose,
        };

        let data = FromConsensusRelayMessage::<chain_b::Runtime> { state_root, xdm }.encode();
        fs::write(
            "./src/extensions/fixtures/between_domains_relay_message.data",
            data.clone(),
        )
        .unwrap();
    }

    #[test]
    fn test_between_domains_relay_message_response() {
        let mut chain_test_ext = chain_b::new_test_ext();
        let mut chain_a_test_ext = chain_a::new_test_ext();
        let dst_chain = chain_b::SelfChainId::get();
        let channel_id = ChannelId::zero();
        let nonce = Nonce::zero();

        let msg = chain_a_test_ext.execute_with(|| {
            let list = BTreeSet::from([dst_chain]);
            ChainAllowlist::<chain_a::Runtime>::put(list);
            assert_ok!(Pallet::<chain_a::Runtime>::initiate_channel(
                chain_a::RuntimeOrigin::signed(USER_ACCOUNT),
                dst_chain,
            ));
            Outbox::<chain_a::Runtime>::get((dst_chain, channel_id, nonce)).unwrap()
        });

        let (_, _, message_proof) = storage_proof_of_outbox_messages::<chain_a::Runtime>(
            chain_a_test_ext.as_backend(),
            dst_chain,
            channel_id,
            nonce,
        );

        let xdm = CrossDomainMessage {
            src_chain_id: chain_a::SelfChainId::get(),
            dst_chain_id: dst_chain,
            channel_id,
            nonce,
            proof: Proof::Consensus {
                consensus_chain_mmr_proof: ConsensusChainMmrLeafProof::<u64, H256, H256> {
                    consensus_block_number: Default::default(),
                    consensus_block_hash: Default::default(),
                    opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                    proof: MmrProof {
                        leaf_indices: vec![],
                        leaf_count: 0,
                        items: vec![],
                    },
                },
                message_proof,
            },
            weight_tag: MessageWeightTag::ProtocolChannelOpen,
        };

        chain_test_ext.execute_with(|| {
            force_toggle_channel_state::<chain_b::Runtime>(
                chain_a::SelfChainId::get(),
                channel_id,
                false,
                true,
            );
            Inbox::<chain_b::Runtime>::set(Some(msg));

            // process inbox message
            let result = Pallet::<chain_b::Runtime>::relay_message(
                crate::RawOrigin::ValidatedUnsigned.into(),
                xdm,
            );

            assert_ok!(result);

            chain_b::Messenger::inbox_responses((chain_a::SelfChainId::get(), channel_id, nonce))
                .unwrap();
        });

        // relay message response to chain_a
        let (state_root, _key, message_proof) =
            storage_proof_of_inbox_message_responses::<chain_b::Runtime>(
                chain_test_ext.as_backend(),
                chain_a::SelfChainId::get(),
                channel_id,
                nonce,
            );

        let xdm = CrossDomainMessage {
            src_chain_id: chain_b::SelfChainId::get(),
            dst_chain_id: chain_a::SelfChainId::get(),
            channel_id,
            nonce,
            proof: Proof::Consensus {
                consensus_chain_mmr_proof: ConsensusChainMmrLeafProof::<u32, H256, H256> {
                    consensus_block_number: Default::default(),
                    consensus_block_hash: Default::default(),
                    opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
                    proof: MmrProof {
                        leaf_indices: vec![],
                        leaf_count: 0,
                        items: vec![],
                    },
                },
                message_proof,
            },
            weight_tag: MessageWeightTag::ProtocolChannelOpen,
        };

        let data = FromConsensusRelayMessage::<chain_b::Runtime> { state_root, xdm }.encode();
        fs::write(
            "./src/extensions/fixtures/between_domains_relay_message_response.data",
            data.clone(),
        )
        .unwrap();
    }
}

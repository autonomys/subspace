//! Benchmarking for `pallet-messenger`.

use super::*;
use crate::Pallet as Messenger;
use frame_benchmarking::v2::*;
use frame_support::assert_ok;
use frame_support::traits::fungible::Mutate;
use frame_support::traits::Get;
use frame_system::RawOrigin;
use sp_messenger::endpoint::{Endpoint, EndpointRequest};
use sp_messenger::messages::{
    CrossDomainMessage, ExecutionFee, InitiateChannelParams, Message, MessageWeightTag, Payload,
    Proof, RequestResponse, VersionedPayload,
};

const SEED: u32 = 0;

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn initiate_channel() {
        let relayer = account("relayer", 1, SEED);
        T::Currency::mint_into(
            &relayer,
            T::RelayerDeposit::get() + T::Currency::minimum_balance(),
        )
        .unwrap();
        unchecked_join_relayer_set::<T>(relayer);
        let dst_chain_id: ChainId = u32::MAX.into();
        assert_ne!(T::SelfChainId::get(), dst_chain_id);
        let channel_params = dummy_channel_params::<T>();
        let channel_id = NextChannelId::<T>::get(dst_chain_id);

        #[extrinsic_call]
        _(RawOrigin::Root, dst_chain_id, channel_params);

        let channel = Channels::<T>::get(dst_chain_id, channel_id).expect("channel should exist");
        assert_eq!(channel.state, ChannelState::Initiated);
        assert!(
            Outbox::<T>::get((dst_chain_id, channel_id, channel.next_outbox_nonce - 1)).is_some()
        );
    }

    #[benchmark]
    fn close_channel() {
        let relayer = account("relayer", 1, SEED);
        T::Currency::mint_into(
            &relayer,
            T::RelayerDeposit::get() + T::Currency::minimum_balance(),
        )
        .unwrap();
        unchecked_join_relayer_set::<T>(relayer);

        let dst_chain_id: ChainId = u32::MAX.into();
        assert_ne!(T::SelfChainId::get(), dst_chain_id);
        let channel_id = open_channel::<T>(dst_chain_id, dummy_channel_params::<T>());

        #[extrinsic_call]
        _(RawOrigin::Root, dst_chain_id, channel_id);

        let channel = Channels::<T>::get(dst_chain_id, channel_id).expect("channel should exist");
        assert_eq!(channel.state, ChannelState::Closed);
        assert!(
            Outbox::<T>::get((dst_chain_id, channel_id, channel.next_outbox_nonce - 1)).is_some()
        );
    }

    #[benchmark]
    fn do_open_channel() {
        let relayer = account("relayer", 1, SEED);
        T::Currency::mint_into(
            &relayer,
            T::RelayerDeposit::get() + T::Currency::minimum_balance(),
        )
        .unwrap();
        unchecked_join_relayer_set::<T>(relayer);

        let dst_chain_id: ChainId = u32::MAX.into();
        assert_ne!(T::SelfChainId::get(), dst_chain_id);
        let channel_id = NextChannelId::<T>::get(dst_chain_id);
        assert_ok!(Messenger::<T>::do_init_channel(
            dst_chain_id,
            dummy_channel_params::<T>()
        ));
        let channel = Channels::<T>::get(dst_chain_id, channel_id).expect("channel should exist");
        assert_eq!(channel.state, ChannelState::Initiated);

        #[block]
        {
            assert_ok!(Messenger::<T>::do_open_channel(dst_chain_id, channel_id));
        }

        let channel = Channels::<T>::get(dst_chain_id, channel_id).expect("channel should exist");
        assert_eq!(channel.state, ChannelState::Open);
    }

    #[benchmark]
    fn do_close_channel() {
        let relayer = account("relayer", 1, SEED);
        T::Currency::mint_into(
            &relayer,
            T::RelayerDeposit::get() + T::Currency::minimum_balance(),
        )
        .unwrap();
        unchecked_join_relayer_set::<T>(relayer);

        let dst_chain_id: ChainId = u32::MAX.into();
        assert_ne!(T::SelfChainId::get(), dst_chain_id);
        let channel_id = open_channel::<T>(dst_chain_id, dummy_channel_params::<T>());

        #[block]
        {
            assert_ok!(Messenger::<T>::do_close_channel(dst_chain_id, channel_id));
        }

        let channel = Channels::<T>::get(dst_chain_id, channel_id).expect("channel should exist");
        assert_eq!(channel.state, ChannelState::Closed);
    }

    // Benchmark the outer weight when processing endpoint message (i.e. updating the `next_nonce`
    // of the channel, assigning msg to the relayer, etc.), the endponit message will be handled by
    // a dummy handler that consume zero weight
    #[benchmark]
    fn relay_message<T: Config>() {
        let relayer = account("relayer", 1, SEED);
        T::Currency::mint_into(
            &relayer,
            T::RelayerDeposit::get() + T::Currency::minimum_balance(),
        )
        .unwrap();
        unchecked_join_relayer_set::<T>(relayer);

        let endpoint = Endpoint::Id(100);
        let dst_chain_id: ChainId = u32::MAX.into();
        assert_ne!(T::SelfChainId::get(), dst_chain_id);
        let channel_id = open_channel::<T>(dst_chain_id, dummy_channel_params::<T>());
        let channel = Channels::<T>::get(dst_chain_id, channel_id).expect("channel should exist");

        // Insert a dummy inbox message which will be handled during the `relay_message` call
        let msg: Message<BalanceOf<T>> = Message {
            src_chain_id: dst_chain_id,
            dst_chain_id: T::SelfChainId::get(),
            channel_id,
            nonce: channel.next_inbox_nonce,
            payload: VersionedPayload::V0(Payload::Endpoint(RequestResponse::Request(
                EndpointRequest {
                    dst_endpoint: endpoint.clone(),
                    src_endpoint: endpoint.clone(),
                    payload: Vec::new(),
                },
            ))),
            last_delivered_message_response_nonce: None,
        };
        Inbox::<T>::put(msg);

        let xdm: CrossDomainMessage<T::BlockNumber, T::Hash, StateRootOf<T>> = CrossDomainMessage {
            src_chain_id: dst_chain_id,
            dst_chain_id: T::SelfChainId::get(),
            channel_id,
            nonce: channel.next_inbox_nonce,
            proof: Proof::dummy(),
            weight_tag: MessageWeightTag::EndpointRequest(endpoint),
        };

        #[extrinsic_call]
        _(RawOrigin::None, xdm);

        let post_channel =
            Channels::<T>::get(dst_chain_id, channel_id).expect("channel should exist");
        assert_eq!(
            post_channel.next_inbox_nonce,
            channel.next_inbox_nonce + Nonce::one()
        );
    }

    // Benchmark the outer weight when processing endponit message response (i.e. updating the `next_nonce`
    // of the channel, assigning msg to the relayer, etc.), the endponit message response will be handled
    // by a dummy handler that consume zero weight
    #[benchmark]
    fn relay_message_response() {
        let relayer = account("relayer", 1, SEED);
        T::Currency::mint_into(
            &relayer,
            T::RelayerDeposit::get() + T::Currency::minimum_balance(),
        )
        .unwrap();
        unchecked_join_relayer_set::<T>(relayer);

        let endpoint = Endpoint::Id(100);
        let dst_chain_id: ChainId = u32::MAX.into();
        assert_ne!(T::SelfChainId::get(), dst_chain_id);
        let channel_id = open_channel::<T>(dst_chain_id, dummy_channel_params::<T>());
        let channel = Channels::<T>::get(dst_chain_id, channel_id).expect("channel should exist");
        let resp_nonce = match channel.latest_response_received_message_nonce {
            None => Nonce::zero(),
            Some(last_nonce) => last_nonce
                .checked_add(Nonce::one())
                .expect("should not overflow"),
        };
        let next_outbox_nonce = channel.next_outbox_nonce;

        // Insert a dummy outbox request message which will be handled during the `relay_message_response` call
        let req_msg: Message<BalanceOf<T>> = Message {
            src_chain_id: T::SelfChainId::get(),
            dst_chain_id,
            channel_id,
            nonce: next_outbox_nonce,
            payload: VersionedPayload::V0(Payload::Endpoint(RequestResponse::Request(
                EndpointRequest {
                    dst_endpoint: endpoint.clone(),
                    src_endpoint: endpoint.clone(),
                    payload: Vec::new(),
                },
            ))),
            last_delivered_message_response_nonce: None,
        };
        Outbox::<T>::insert((dst_chain_id, channel_id, next_outbox_nonce), req_msg);
        // Insert a dummy response message which will be handled during the `relay_message_response` call
        let resp_msg: Message<BalanceOf<T>> = Message {
            src_chain_id: T::SelfChainId::get() + 1,
            dst_chain_id: T::SelfChainId::get(),
            channel_id,
            nonce: resp_nonce,
            payload: VersionedPayload::V0(Payload::Endpoint(RequestResponse::Response(Ok(
                Vec::new(),
            )))),
            last_delivered_message_response_nonce: None,
        };
        OutboxResponses::<T>::put(resp_msg);

        let xdm: CrossDomainMessage<T::BlockNumber, T::Hash, StateRootOf<T>> = CrossDomainMessage {
            src_chain_id: dst_chain_id,
            dst_chain_id: T::SelfChainId::get(),
            channel_id,
            nonce: resp_nonce,
            proof: Proof::dummy(),
            weight_tag: MessageWeightTag::EndpointResponse(endpoint),
        };

        #[extrinsic_call]
        _(RawOrigin::None, xdm);

        let post_channel =
            Channels::<T>::get(dst_chain_id, channel_id).expect("channel should exist");
        assert_eq!(
            post_channel.latest_response_received_message_nonce,
            Some(resp_nonce)
        );
    }

    #[benchmark]
    fn join_relayer_set() {
        let relayer = account("relayer", 1, SEED);
        T::Currency::mint_into(
            &relayer,
            T::RelayerDeposit::get() + T::Currency::minimum_balance(),
        )
        .unwrap();

        #[extrinsic_call]
        _(RawOrigin::Signed(relayer.clone()), relayer.clone());

        assert!(RelayersInfo::<T>::contains_key(&relayer));
    }

    /// Benchmark `exit_relayer_set` extrinsic with the worst possible conditions:
    /// - The existed relayer index is < next_relayer_idx (i.e. next_index need to be shifted)
    #[benchmark]
    fn exit_relayer_set() {
        let mut relayers = Vec::new();
        for i in 0..10 {
            let relayer = account("relayer", i, SEED);
            T::Currency::mint_into(
                &relayer,
                T::RelayerDeposit::get() + T::Currency::minimum_balance(),
            )
            .unwrap();
            unchecked_join_relayer_set::<T>(relayer.clone());
            relayers.push(relayer);

            // Move next_relayer_idx
            assert_ok!(Messenger::<T>::next_relayer());
        }

        let next_relayer_idx = NextRelayerIdx::<T>::get();

        #[extrinsic_call]
        _(RawOrigin::Signed(relayers[0].clone()), relayers[0].clone());

        assert!(!RelayersInfo::<T>::contains_key(&relayers[0]));
        assert_eq!(T::Currency::reserved_balance(&relayers[0]), 0u32.into());
        assert_eq!(NextRelayerIdx::<T>::get(), next_relayer_idx - 1);
    }

    fn unchecked_join_relayer_set<T: Config>(relayer: T::AccountId) {
        assert_ok!(Messenger::<T>::do_join_relayer_set(
            relayer.clone(),
            relayer.clone()
        ));
        assert!(RelayersInfo::<T>::contains_key(&relayer));
    }

    fn dummy_channel_params<T: Config>() -> InitiateChannelParams<BalanceOf<T>> {
        let fee_model = FeeModel {
            outbox_fee: ExecutionFee {
                relayer_pool_fee: 1u32.into(),
                compute_fee: 2u32.into(),
            },
            inbox_fee: ExecutionFee {
                relayer_pool_fee: 3u32.into(),
                compute_fee: 4u32.into(),
            },
        };
        InitiateChannelParams {
            max_outgoing_messages: 100,
            fee_model,
        }
    }

    fn open_channel<T: Config>(
        dst_chain_id: ChainId,
        params: InitiateChannelParams<BalanceOf<T>>,
    ) -> ChannelId {
        let channel_id = NextChannelId::<T>::get(dst_chain_id);
        assert_ok!(Messenger::<T>::do_init_channel(dst_chain_id, params));
        let channel = Channels::<T>::get(dst_chain_id, channel_id).expect("channel should exist");
        assert_eq!(channel.state, ChannelState::Initiated);

        assert_ok!(Messenger::<T>::do_open_channel(dst_chain_id, channel_id));
        let channel = Channels::<T>::get(dst_chain_id, channel_id).expect("channel should exist");
        assert_eq!(channel.state, ChannelState::Open);

        channel_id
    }

    impl_benchmark_test_suite!(
        Messenger,
        crate::mock::chain_a::new_test_ext(),
        crate::mock::chain_a::Runtime,
    );
}

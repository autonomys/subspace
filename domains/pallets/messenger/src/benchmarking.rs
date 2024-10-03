//! Benchmarking for `pallet-messenger`.

use super::*;
use crate::{CloseChannelBy, Pallet as Messenger};
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use frame_benchmarking::v2::*;
use frame_support::assert_ok;
use frame_support::traits::fungible::Mutate;
use frame_support::traits::Get;
use frame_system::RawOrigin;
use sp_messenger::endpoint::{Endpoint, EndpointRequest};
use sp_messenger::messages::{
    ChannelOpenParams, CrossDomainMessage, Message, MessageWeightTag, Payload, Proof,
    RequestResponse, VersionedPayload,
};
use sp_mmr_primitives::{EncodableOpaqueLeaf, LeafProof as MmrProof};
use sp_runtime::traits::Zero;
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
use sp_trie::StorageProof;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn initiate_channel() {
        let dst_chain_id: ChainId = u32::MAX.into();
        assert_ne!(T::SelfChainId::get(), dst_chain_id);
        let channel_params = InitiateChannelParams {
            max_outgoing_messages: 100,
        };
        let channel_id = NextChannelId::<T>::get(dst_chain_id);
        let account = account("account", 0, 0);
        T::Currency::set_balance(
            &account,
            T::ChannelReserveFee::get() + T::Currency::minimum_balance(),
        );

        let list = BTreeSet::from([dst_chain_id]);
        ChainAllowlist::<T>::put(list);

        #[extrinsic_call]
        _(
            RawOrigin::Signed(account.clone()),
            dst_chain_id,
            channel_params,
        );

        let channel = Channels::<T>::get(dst_chain_id, channel_id).expect("channel should exist");
        assert_eq!(channel.state, ChannelState::Initiated);
        assert!(
            Outbox::<T>::get((dst_chain_id, channel_id, channel.next_outbox_nonce - 1)).is_some()
        );
    }

    #[benchmark]
    fn close_channel() {
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
        let dst_chain_id: ChainId = u32::MAX.into();
        assert_ne!(T::SelfChainId::get(), dst_chain_id);
        let channel_id = NextChannelId::<T>::get(dst_chain_id);
        let list = BTreeSet::from([dst_chain_id]);
        ChainAllowlist::<T>::put(list);
        assert_ok!(Messenger::<T>::do_init_channel(
            dst_chain_id,
            dummy_channel_params::<T>(),
            None,
            true,
            Zero::zero(),
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
        let dst_chain_id: ChainId = u32::MAX.into();
        assert_ne!(T::SelfChainId::get(), dst_chain_id);
        let channel_id = open_channel::<T>(dst_chain_id, dummy_channel_params::<T>());

        #[block]
        {
            assert_ok!(Messenger::<T>::do_close_channel(
                dst_chain_id,
                channel_id,
                CloseChannelBy::Sudo
            ));
        }

        let channel = Channels::<T>::get(dst_chain_id, channel_id).expect("channel should exist");
        assert_eq!(channel.state, ChannelState::Closed);
    }

    // Benchmark the outer weight when processing endpoint message (i.e. updating the `next_nonce`
    // of the channel, assigning msg to the relayer, etc.), the endponit message will be handled by
    // a dummy handler that consume zero weight
    #[benchmark]
    fn relay_message<T: Config>() {
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

        let xdm = CrossDomainMessage::<BlockNumberFor<T>, T::Hash, T::MmrHash> {
            src_chain_id: dst_chain_id,
            dst_chain_id: T::SelfChainId::get(),
            channel_id,
            nonce: channel.next_inbox_nonce,
            proof: dummy_proof(),
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
            src_chain_id: dst_chain_id,
            dst_chain_id: T::SelfChainId::get(),
            channel_id,
            nonce: resp_nonce,
            payload: VersionedPayload::V0(Payload::Endpoint(RequestResponse::Response(Ok(
                Vec::new(),
            )))),
            last_delivered_message_response_nonce: None,
        };
        OutboxResponses::<T>::put(resp_msg);

        let xdm = CrossDomainMessage::<BlockNumberFor<T>, T::Hash, T::MmrHash> {
            src_chain_id: dst_chain_id,
            dst_chain_id: T::SelfChainId::get(),
            channel_id,
            nonce: resp_nonce,
            proof: dummy_proof(),
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

    fn dummy_channel_params<T: Config>() -> ChannelOpenParams<BalanceOf<T>> {
        let fee_model = FeeModel {
            relay_fee: 1u32.into(),
        };
        ChannelOpenParams {
            max_outgoing_messages: 100,
            fee_model,
        }
    }

    fn open_channel<T: Config>(
        dst_chain_id: ChainId,
        params: ChannelOpenParams<BalanceOf<T>>,
    ) -> ChannelId {
        let channel_id = NextChannelId::<T>::get(dst_chain_id);
        let list = BTreeSet::from([dst_chain_id]);
        ChainAllowlist::<T>::put(list);
        assert_ok!(Messenger::<T>::do_init_channel(
            dst_chain_id,
            params,
            None,
            true,
            Zero::zero(),
        ));
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

pub fn dummy_proof<CNumber, CBlockHash, MmrHash>() -> Proof<CNumber, CBlockHash, MmrHash>
where
    CNumber: Default,
    CBlockHash: Default,
{
    Proof::Consensus {
        consensus_chain_mmr_proof: ConsensusChainMmrLeafProof {
            consensus_block_number: Default::default(),
            consensus_block_hash: Default::default(),
            opaque_mmr_leaf: EncodableOpaqueLeaf(vec![]),
            proof: MmrProof {
                leaf_indices: vec![],
                leaf_count: 0,
                items: vec![],
            },
        },
        message_proof: StorageProof::empty(),
    }
}

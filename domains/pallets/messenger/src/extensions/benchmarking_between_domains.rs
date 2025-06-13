//! Benchmarking for `pallet-messenger` extensions.

#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::pallet::ChainAllowlist;
use crate::{Config, Pallet as Messenger, ValidatedRelayMessage};
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
use frame_benchmarking::v2::*;
use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use frame_system::pallet_prelude::BlockNumberFor;
use parity_scale_codec::{Decode, Encode};
use scale_info::prelude::fmt;
use sp_domains::{ChainId, ChannelId};
use sp_messenger::messages::{ChannelOpenParamsV1, CrossDomainMessage};
use sp_runtime::traits::{Dispatchable, Zero};
#[cfg(feature = "std")]
use std::collections::BTreeSet;

pub struct Pallet<T: Config>(Messenger<T>);

#[derive(Encode, Decode)]
pub(crate) struct RelayMessage<T: Config> {
    pub(crate) state_root: T::Hash,
    pub(crate) xdm: CrossDomainMessage<BlockNumberFor<T>, T::Hash, T::MmrHash>,
}

// Between domains relay message channel open data.
const BDRMCO: &[u8; 746] =
    include_bytes!("./fixtures/between_domains_relay_message_channel_open.data");

// Between domains relay message.
const BDRM: &[u8; 814] = include_bytes!("./fixtures/between_domains_relay_message.data");

// Between domains relay message response.
const BDRMR: &[u8; 705] = include_bytes!("./fixtures/between_domains_relay_message_response.data");

#[allow(clippy::multiple_bound_locations)]
#[benchmarks(where
	T: Send + Sync + scale_info::TypeInfo + fmt::Debug,
    RuntimeCallFor<T>: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>)
]
mod benchmarks {
    use super::*;
    use frame_system::pallet_prelude::RuntimeCallFor;

    #[benchmark]
    fn from_domains_relay_message_channel_open() {
        let RelayMessage { state_root, xdm } =
            RelayMessage::<T>::decode(&mut BDRMCO.as_slice()).unwrap();
        #[block]
        {
            let ValidatedRelayMessage {
                message,
                should_init_channel,
                ..
            } = Messenger::<T>::validate_relay_message(&xdm, state_root).unwrap();

            Messenger::<T>::pre_dispatch_relay_message(message, should_init_channel).unwrap();
        }
    }

    #[benchmark]
    fn from_domains_relay_message() {
        let RelayMessage { state_root, xdm } =
            RelayMessage::<T>::decode(&mut BDRMCO.as_slice()).unwrap();

        // channel init and open
        let ValidatedRelayMessage {
            message,
            should_init_channel,
            ..
        } = Messenger::<T>::validate_relay_message(&xdm, state_root).unwrap();
        Messenger::<T>::pre_dispatch_relay_message(message, should_init_channel).unwrap();
        Messenger::<T>::do_open_channel(xdm.src_chain_id, xdm.channel_id).unwrap();

        let RelayMessage { state_root, xdm } =
            RelayMessage::<T>::decode(&mut BDRM.as_slice()).unwrap();

        #[block]
        {
            let ValidatedRelayMessage {
                message,
                should_init_channel,
                ..
            } = Messenger::<T>::validate_relay_message(&xdm, state_root).unwrap();

            Messenger::<T>::pre_dispatch_relay_message(message, should_init_channel).unwrap();
        }
    }

    #[benchmark]
    fn from_domains_relay_message_response() {
        let RelayMessage { state_root, xdm } =
            RelayMessage::<T>::decode(&mut BDRMR.as_slice()).unwrap();

        // channel init
        set_channel_init_state::<T>(xdm.src_chain_id, xdm.channel_id);
        #[block]
        {
            let ValidatedRelayMessage { message, .. } =
                Messenger::<T>::validate_relay_message_response(&xdm, state_root).unwrap();

            Messenger::<T>::pre_dispatch_relay_message_response(message).unwrap();
        }
    }

    impl_benchmark_test_suite!(
        Pallet,
        crate::mock::chain_a::new_test_ext(),
        crate::mock::chain_a::Runtime,
    );
}

pub(crate) fn set_channel_init_state<T: Config>(dst_chain_id: ChainId, channel_id: ChannelId) {
    let init_params = ChannelOpenParamsV1 {
        max_outgoing_messages: 100,
    };

    crate::Pallet::<T>::channels(dst_chain_id, channel_id).unwrap_or_else(|| {
        let list = BTreeSet::from([dst_chain_id]);
        ChainAllowlist::<T>::put(list);
        crate::Pallet::<T>::do_init_channel(dst_chain_id, init_params, None, true, Zero::zero())
            .unwrap();
        crate::Pallet::<T>::channels(dst_chain_id, channel_id).unwrap()
    });
}

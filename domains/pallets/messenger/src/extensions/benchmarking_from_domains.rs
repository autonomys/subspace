//! Benchmarking for `pallet-messenger` extensions.

use crate::extensions::benchmarking_from_consensus::{RelayMessage, set_channel_init_state};
use crate::{Config, Pallet as Messenger, ValidatedRelayMessage};
use frame_benchmarking::v2::*;
use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use parity_scale_codec::Decode;
use scale_info::prelude::fmt;
use sp_runtime::traits::Dispatchable;

pub struct Pallet<T: Config>(Messenger<T>);

// From domain relay message channel open data.
const FDRMCO: &[u8; 1197] =
    include_bytes!("./fixtures/from_domains_relay_message_channel_open.data");

// From domain relay message data.
const FDRM: &[u8; 1265] = include_bytes!("./fixtures/from_domains_relay_message.data");

// From domain relay message response.
const FDRMR: &[u8; 1189] = include_bytes!("./fixtures/from_domains_relay_message_response.data");

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
            RelayMessage::<T>::decode(&mut FDRMCO.as_slice()).unwrap();
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
            RelayMessage::<T>::decode(&mut FDRMCO.as_slice()).unwrap();

        // channel init and open
        let ValidatedRelayMessage {
            message,
            should_init_channel,
            ..
        } = Messenger::<T>::validate_relay_message(&xdm, state_root).unwrap();
        Messenger::<T>::pre_dispatch_relay_message(message, should_init_channel).unwrap();
        Messenger::<T>::do_open_channel(xdm.src_chain_id, xdm.channel_id).unwrap();

        let RelayMessage { state_root, xdm } =
            RelayMessage::<T>::decode(&mut FDRM.as_slice()).unwrap();

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
            RelayMessage::<T>::decode(&mut FDRMR.as_slice()).unwrap();

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

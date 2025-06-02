//! Benchmarking for `pallet-transporter`.

use super::*;
use frame_benchmarking::v2::*;
use frame_support::assert_ok;
use frame_system::RawOrigin;
use sp_messenger::endpoint::{
    Endpoint, EndpointHandler as EndpointHandlerT, EndpointRequest, Sender,
};
use sp_runtime::DispatchError;
use sp_runtime::traits::{Bounded, Convert};
use sp_std::marker::PhantomData;

#[cfg(test)]
use crate::Pallet as Transporter;

const SEED: u32 = 0;

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn transfer() {
        let sender: T::AccountId = account("sender", 1, SEED);
        let receiver: T::AccountId = account("receiver", 2, SEED);

        let amount: BalanceOf<T> = 100u32.into();
        let dst_chain_id: ChainId = u32::MAX.into();
        let free_balance = BalanceOf::<T>::max_value();
        assert_ne!(T::SelfChainId::get(), dst_chain_id);
        let location = Location {
            chain_id: dst_chain_id,
            account_id: T::AccountIdConverter::convert(receiver),
        };

        T::Currency::make_free_balance_be(&sender, free_balance);
        assert_ok!(T::Sender::unchecked_open_channel(dst_chain_id));

        #[extrinsic_call]
        _(RawOrigin::Signed(sender.clone()), location, amount);

        // `amount + relayer fee` are deducted
        assert!(T::Currency::free_balance(&sender) < free_balance - amount);
    }

    #[benchmark]
    fn message() {
        let sender: T::AccountId = account("sender", 1, SEED);
        let receiver: T::AccountId = account("receiver", 2, SEED);
        let dst_chain_id: ChainId = u32::MAX.into();
        let amount = 10u32.into();

        assert_ne!(T::SelfChainId::get(), dst_chain_id);
        UnconfirmedTransfers::<T>::insert(dst_chain_id, T::SelfChainId::get(), amount);

        let transfer_obj: Transfer<BalanceOf<T>> = Transfer {
            amount,
            sender: Location {
                chain_id: dst_chain_id,
                account_id: T::AccountIdConverter::convert(sender),
            },
            receiver: Location {
                chain_id: T::SelfChainId::get(),
                account_id: T::AccountIdConverter::convert(receiver),
            },
        };
        let endpoint_req = EndpointRequest {
            src_endpoint: Endpoint::Id(T::SelfEndpointId::get()),
            dst_endpoint: Endpoint::Id(T::SelfEndpointId::get()),
            payload: transfer_obj.encode(),
        };
        let message_id = MessageIdOf::<T>::default();

        #[block]
        {
            assert_ok!(EndpointHandler(PhantomData::<T>).message(
                dst_chain_id,
                message_id,
                endpoint_req,
                Ok(())
            ));
        }
    }

    /// Benchmark `message_response` with the worst possible conditions:
    /// - Handling an error response (i.e. need to revert burned funds)
    #[benchmark]
    fn message_response() {
        let sender: T::AccountId = account("sender", 1, SEED);
        let receiver: T::AccountId = account("receiver", 2, SEED);
        let dst_chain_id: ChainId = u32::MAX.into();
        let amount = 10u32.into();

        assert_ne!(T::SelfChainId::get(), dst_chain_id);
        CancelledTransfers::<T>::insert(T::SelfChainId::get(), dst_chain_id, amount);

        let transfer_obj = Transfer {
            amount,
            sender: Location {
                chain_id: T::SelfChainId::get(),
                account_id: T::AccountIdConverter::convert(sender.clone()),
            },
            receiver: Location {
                chain_id: dst_chain_id,
                account_id: T::AccountIdConverter::convert(receiver),
            },
        };
        let endpoint_req = EndpointRequest {
            src_endpoint: Endpoint::Id(T::SelfEndpointId::get()),
            dst_endpoint: Endpoint::Id(T::SelfEndpointId::get()),
            payload: transfer_obj.encode(),
        };
        let endpoint_resp = Err(DispatchError::Exhausted);
        let message_id = MessageIdOf::<T>::default();
        OutgoingTransfers::<T>::insert(dst_chain_id, message_id, transfer_obj);

        #[block]
        {
            assert_ok!(EndpointHandler(PhantomData::<T>).message_response(
                dst_chain_id,
                message_id,
                endpoint_req,
                endpoint_resp,
            ));
        }
    }

    impl_benchmark_test_suite!(
        Transporter,
        crate::mock::new_test_ext(),
        crate::mock::MockRuntime,
    );
}

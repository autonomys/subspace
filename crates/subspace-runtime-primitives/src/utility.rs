//! Runtime primitives for pallet-utility.

use core::marker::PhantomData;
use frame_support::pallet_prelude::TypeInfo;
use frame_system::pallet_prelude::RuntimeCallFor;
use scale_info::prelude::collections::VecDeque;
use sp_runtime::traits::{BlockNumberProvider, Get};

/// Trait used to convert from a generated `RuntimeCall` type to `pallet_utility::Call<Runtime>`.
pub trait MaybeIntoUtilityCall<Runtime>
where
    Runtime: pallet_utility::Config,
{
    /// If this call is a `pallet_utility::Call<Runtime>` call, returns the inner call.
    fn maybe_into_utility_call(&self) -> Option<&pallet_utility::Call<Runtime>>;
}

/// Trait used to convert from a generated `RuntimeCall` type to `pallet_multisig::Call<Runtime>`.
pub trait MaybeMultisigCall<Runtime>
where
    Runtime: pallet_multisig::Config,
{
    /// Returns possible pallet_multisig::Call
    fn maybe_multisig_call(&self) -> Option<&pallet_multisig::Call<Runtime>>;
}

/// Returns an interator over `call`, and any calls nested within it using `pallet-utility`.
///
/// The iterator yields all calls in depth-first order, including calls which contain other calls.
/// `pallet_utility::Call::__Ignore` calls are yielded themsevles, but their contents are not.
// This function doesn't use stack recursion, so there's no need to check the recursion depth.
pub fn nested_utility_call_iter<Runtime>(
    call: &RuntimeCallFor<Runtime>,
) -> impl Iterator<Item = &RuntimeCallFor<Runtime>>
where
    Runtime: frame_system::Config + pallet_utility::Config,
    RuntimeCallFor<Runtime>: MaybeIntoUtilityCall<Runtime>,
    for<'block> &'block RuntimeCallFor<Runtime>:
        From<&'block <Runtime as pallet_utility::Config>::RuntimeCall>,
{
    // Instead of using recursion, we allocate references to each call on the heap.
    // TODO: re-use the same memory with an enum for a call ref, a boxed call, or a vec of calls
    let mut new_calls = VecDeque::from([call]);

    core::iter::from_fn(move || {
        let call = new_calls.pop_front()?;

        if let Some(call) = call.maybe_into_utility_call() {
            match call {
                pallet_utility::Call::batch { calls }
                | pallet_utility::Call::batch_all { calls }
                | pallet_utility::Call::force_batch { calls } => calls.iter().for_each(|call| {
                    new_calls.push_front(call.into());
                }),
                pallet_utility::Call::as_derivative { call, .. }
                | pallet_utility::Call::dispatch_as { call, .. }
                | pallet_utility::Call::with_weight { call, .. } => {
                    new_calls.push_front(call.as_ref().into())
                }
                pallet_utility::Call::__Ignore(..) => {}
            }
        }

        Some(call)
    })
}

/// Returns an interator over `call`, and any calls nested within it using
/// `pallet-utility` or `pallet-multisig`.
///
/// The iterator yields all calls in depth-first order, including calls which contain other calls.
/// Rest of the call types that do not hold inner calls are yielded as is.
// This function doesn't use stack recursion, so there's no need to check the recursion depth.
pub fn nested_call_iter<Runtime>(
    call: &RuntimeCallFor<Runtime>,
) -> impl Iterator<Item = &RuntimeCallFor<Runtime>>
where
    Runtime: frame_system::Config + pallet_utility::Config + pallet_multisig::Config,
    RuntimeCallFor<Runtime>: MaybeIntoUtilityCall<Runtime> + MaybeMultisigCall<Runtime>,
    for<'block> &'block RuntimeCallFor<Runtime>: From<&'block <Runtime as pallet_utility::Config>::RuntimeCall>
        + From<&'block <Runtime as pallet_multisig::Config>::RuntimeCall>,
{
    // Instead of using recursion, we allocate references to each call on the heap.
    // TODO: re-use the same memory with an enum for a call ref, a boxed call, or a vec of calls
    let mut new_calls = VecDeque::from([call]);

    core::iter::from_fn(move || {
        let call = new_calls.pop_front()?;

        if let Some(call) = call.maybe_into_utility_call() {
            match call {
                pallet_utility::Call::batch { calls }
                | pallet_utility::Call::batch_all { calls }
                | pallet_utility::Call::force_batch { calls } => calls.iter().for_each(|call| {
                    new_calls.push_front(call.into());
                }),
                pallet_utility::Call::as_derivative { call, .. }
                | pallet_utility::Call::dispatch_as { call, .. }
                | pallet_utility::Call::with_weight { call, .. } => {
                    new_calls.push_front(call.as_ref().into())
                }
                pallet_utility::Call::__Ignore(..) => {}
            }
        }

        if let Some(call) = call.maybe_multisig_call() {
            match call {
                pallet_multisig::Call::__Ignore(_, _)
                | pallet_multisig::Call::approve_as_multi { .. }
                | pallet_multisig::Call::cancel_as_multi { .. } => {}
                pallet_multisig::Call::as_multi_threshold_1 { call, .. }
                | pallet_multisig::Call::as_multi { call, .. } => {
                    new_calls.push_front(call.as_ref().into())
                }
            }
        }

        Some(call)
    })
}

// `DefaultNonceProvider` uses the current block number as the nonce of the new account,
// this is used to prevent the replay attack see https://wiki.polkadot.network/docs/transaction-attacks#replay-attack
// for more detail.
#[derive(Debug, TypeInfo)]
pub struct DefaultNonceProvider<T, N>(PhantomData<(T, N)>);

impl<N, T: BlockNumberProvider<BlockNumber = N>> Get<N> for DefaultNonceProvider<T, N> {
    fn get() -> N {
        T::current_block_number()
    }
}

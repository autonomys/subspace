//! Runtime primitives for pallet-utility.

use core::marker::PhantomData;
use frame_support::pallet_prelude::TypeInfo;
use frame_system::pallet_prelude::RuntimeCallFor;
use scale_info::prelude::collections::VecDeque;
use scale_info::prelude::vec;
use sp_runtime::Vec;
use sp_runtime::traits::{BlockNumberProvider, Get};

/// Trait used to convert from a generated `RuntimeCall` type to `pallet_utility::Call<Runtime>`.
pub trait MaybeUtilityCall<Runtime>
where
    Runtime: pallet_utility::Config,
    for<'call> &'call RuntimeCallFor<Runtime>:
        From<&'call <Runtime as pallet_utility::Config>::RuntimeCall>,
{
    /// If this call is a `pallet_utility::Call<Runtime>` call, returns the inner `pallet_utility::Call`.
    fn maybe_utility_call(&self) -> Option<&pallet_utility::Call<Runtime>>;

    /// If this call is a `pallet_utility::Call<Runtime>` call, returns the inner `RuntimeCall`.
    ///
    /// Runtimes can override this default implementation if they want to ignore (or not ignore)
    /// certain utility calls. For example, a stack limit check shouldn't ignore `Call::__Ignore`.
    fn maybe_nested_utility_calls(&self) -> Option<Vec<&RuntimeCallFor<Runtime>>> {
        if let Some(call) = self.maybe_utility_call() {
            match call {
                pallet_utility::Call::batch { calls }
                | pallet_utility::Call::batch_all { calls }
                | pallet_utility::Call::force_batch { calls } => {
                    Some(calls.iter().map(Into::into).collect())
                }
                pallet_utility::Call::as_derivative { call, .. }
                | pallet_utility::Call::dispatch_as { call, .. }
                | pallet_utility::Call::with_weight { call, .. } => {
                    Some(vec![call.as_ref().into()])
                }
                pallet_utility::Call::__Ignore(..) => None,
            }
        } else {
            None
        }
    }
}

/// Trait used to convert from a generated `RuntimeCall` type to `pallet_multisig::Call<Runtime>`.
pub trait MaybeMultisigCall<Runtime>
where
    Runtime: pallet_multisig::Config,
    for<'call> &'call RuntimeCallFor<Runtime>:
        From<&'call <Runtime as pallet_multisig::Config>::RuntimeCall>,
{
    /// If this call is a `pallet_multisig::Call<Runtime>` call, returns the inner `pallet_multisig::Call`.
    fn maybe_multisig_call(&self) -> Option<&pallet_multisig::Call<Runtime>>;

    /// If this call is a `pallet_multisig::Call<Runtime>` call, returns the inner `RuntimeCall`.
    ///
    /// Runtimes can override this default implementation if they want to ignore (or not ignore)
    /// certain multisig calls.
    fn maybe_nested_multisig_calls(&self) -> Option<Vec<&RuntimeCallFor<Runtime>>> {
        if let Some(call) = self.maybe_multisig_call() {
            match call {
                pallet_multisig::Call::as_multi { call, .. }
                | pallet_multisig::Call::as_multi_threshold_1 { call, .. } => Some(vec![call.as_ref().into()]),
                // Doesn't contain any actual calls
                pallet_multisig::Call::approve_as_multi {  .. }
                | pallet_multisig::Call::cancel_as_multi { .. }
                // Ignored calls
                | pallet_multisig::Call::__Ignore(..) => None,
            }
        } else {
            None
        }
    }
}

/// Trait used to extract nested `RuntimeCall`s from a `RuntimeCall` type.
/// Each runtime has a different set of pallets which can nest calls.
pub trait MaybeNestedCall<Runtime: frame_system::Config> {
    /// If this call is a nested runtime call, returns the inner call(s).
    ///
    /// Ignored calls (such as `pallet_utility::Call::__Ignore`) should be yielded themsevles, but
    /// their contents should not be yielded.
    fn maybe_nested_call(&self) -> Option<Vec<&RuntimeCallFor<Runtime>>>;
}

/// Returns an interator over `call`, and any calls nested within it.
///
/// The iterator yields all calls in depth-first order, including calls which contain other calls.
/// Ignored calls (such as `pallet_utility::Call::__Ignore`) are yielded themsevles, but their
/// contents are not.
///
/// This function doesn't use stack recursion, so there's no need to check the recursion depth.
pub fn nested_call_iter<Runtime>(
    call: &RuntimeCallFor<Runtime>,
) -> impl Iterator<Item = &RuntimeCallFor<Runtime>>
where
    Runtime: frame_system::Config,
    RuntimeCallFor<Runtime>: MaybeNestedCall<Runtime>,
{
    // Instead of using recursion, we allocate references to each call on the heap.
    let mut new_calls = VecDeque::from([call]);

    core::iter::from_fn(move || {
        let call = new_calls.pop_front()?;

        for call in call.maybe_nested_call().into_iter().flatten() {
            new_calls.push_front(call);
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

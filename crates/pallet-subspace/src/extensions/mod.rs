//! Extensions for unsigned general extrinsics

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;
pub mod weights;

use crate::pallet::Call as SubspaceCall;
use crate::{Config, Pallet as Subspace};
use codec::{Decode, Encode};
use frame_support::pallet_prelude::{PhantomData, TypeInfo, Weight};
use frame_system::pallet_prelude::{BlockNumberFor, RuntimeCallFor};
use scale_info::prelude::fmt;
use sp_consensus_subspace::SignedVote;
use sp_runtime::impl_tx_ext_default;
use sp_runtime::traits::{
    AsSystemOriginSigner, DispatchInfoOf, DispatchOriginOf, Dispatchable, Implication,
    TransactionExtension, ValidateResult,
};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidity, ValidTransaction,
};

/// Trait to convert Runtime call to possible Subspace call.
pub trait MaybeSubspaceCall<Runtime>
where
    Runtime: Config,
{
    fn maybe_subspace_call(&self) -> Option<&SubspaceCall<Runtime>>;
}

/// Extensions for pallet-subspace unsigned extrinsics.
#[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct SubspaceExtension<Runtime>(PhantomData<Runtime>);

impl<Runtime> SubspaceExtension<Runtime> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<Runtime> Default for SubspaceExtension<Runtime> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Config> fmt::Debug for SubspaceExtension<T> {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SubspaceExtension",)
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

impl<Runtime> SubspaceExtension<Runtime>
where
    Runtime: Config + scale_info::TypeInfo + fmt::Debug + Send + Sync,
{
    fn do_check_vote(
        signed_vote: &SignedVote<BlockNumberFor<Runtime>, Runtime::Hash, Runtime::AccountId>,
        source: TransactionSource,
    ) -> TransactionValidity {
        let pre_dispatch = source == TransactionSource::InBlock;
        if pre_dispatch {
            Subspace::<Runtime>::pre_dispatch_vote(signed_vote).map(|_| ValidTransaction::default())
        } else {
            Subspace::<Runtime>::validate_vote(signed_vote)
        }
    }
}

impl<Runtime> TransactionExtension<RuntimeCallFor<Runtime>> for SubspaceExtension<Runtime>
where
    Runtime: Config + scale_info::TypeInfo + fmt::Debug + Send + Sync,
    <RuntimeCallFor<Runtime> as Dispatchable>::RuntimeOrigin:
        AsSystemOriginSigner<<Runtime as frame_system::Config>::AccountId> + Clone,
    RuntimeCallFor<Runtime>: MaybeSubspaceCall<Runtime>,
{
    const IDENTIFIER: &'static str = "SubspaceExtension";
    type Implicit = ();
    type Val = ();
    type Pre = ();

    // TODO: return correct weights
    fn weight(&self, _call: &RuntimeCallFor<Runtime>) -> Weight {
        Weight::zero()
    }

    fn validate(
        &self,
        origin: DispatchOriginOf<RuntimeCallFor<Runtime>>,
        call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
        _self_implicit: Self::Implicit,
        _inherited_implication: &impl Implication,
        source: TransactionSource,
    ) -> ValidateResult<Self::Val, RuntimeCallFor<Runtime>> {
        // we only care about unsigned calls
        if origin.as_system_origin_signer().is_some() {
            return Ok((ValidTransaction::default(), (), origin));
        };

        let subspace_call = match call.maybe_subspace_call() {
            Some(subspace_call) => subspace_call,
            None => return Ok((ValidTransaction::default(), (), origin)),
        };

        let validity = match subspace_call {
            SubspaceCall::vote { signed_vote } => Self::do_check_vote(signed_vote, source)?,
            _ => return Err(InvalidTransaction::Call.into()),
        };

        Ok((validity, (), origin))
    }

    // nothing to prepare since vote is already checked
    impl_tx_ext_default!(RuntimeCallFor<Runtime>; prepare);
}

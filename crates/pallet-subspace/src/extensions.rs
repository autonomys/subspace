//! Extensions for unsigned general extrinsics

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;
pub mod weights;

pub use crate::extensions::weights::WeightInfo;
use crate::pallet::Call as SubspaceCall;
use crate::{Config, Origin, Pallet as Subspace};
use frame_support::RuntimeDebugNoBound;
use frame_support::pallet_prelude::{PhantomData, TypeInfo, Weight};
use frame_system::ensure_root;
use frame_system::pallet_prelude::{BlockNumberFor, RuntimeCallFor};
use log::info;
use pallet_sudo::Call as SudoCall;
use parity_scale_codec::{Decode, Encode};
use scale_info::prelude::fmt;
use sp_consensus_subspace::SignedVote;
use sp_runtime::DispatchResult;
use sp_runtime::traits::{
    AsSystemOriginSigner, DispatchInfoOf, DispatchOriginOf, Dispatchable, Implication,
    PostDispatchInfoOf, TransactionExtension, ValidateResult,
};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidityError, ValidTransaction,
};

/// Trait to convert Runtime call to possible Subspace call.
pub trait MaybeSubspaceCall<Runtime>
where
    Runtime: Config,
{
    fn maybe_subspace_call(&self) -> Option<&SubspaceCall<Runtime>>;
}

/// Trait to convert Runtime call to possible Sudo call.
pub trait MaybeSudoCall<Runtime>
where
    Runtime: pallet_sudo::Config,
{
    fn maybe_sudo_call(&self) -> Option<&SudoCall<Runtime>>;
}

/// Weight info used by this extension
#[derive(RuntimeDebugNoBound)]
pub enum ExtensionWeightData {
    /// Represents the validated call's used weight
    Validated(Weight),
    /// Skipped validation
    Skipped,
}

/// Extension for pallet-subspace unsigned extrinsics.
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

impl<Runtime> fmt::Debug for SubspaceExtension<Runtime> {
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
    Runtime: Config + scale_info::TypeInfo + Send + Sync,
{
    fn do_check_vote(
        signed_vote: &SignedVote<BlockNumberFor<Runtime>, Runtime::Hash, Runtime::AccountId>,
        source: TransactionSource,
    ) -> Result<(ValidTransaction, Weight), TransactionValidityError> {
        let pre_dispatch = source == TransactionSource::InBlock;
        if pre_dispatch {
            Subspace::<Runtime>::pre_dispatch_vote(signed_vote)
                .map(|weight| (ValidTransaction::default(), weight))
        } else {
            Subspace::<Runtime>::validate_vote(signed_vote)
        }
    }

    fn max_weight() -> Weight {
        <Runtime as Config>::ExtensionWeightInfo::vote()
            .max(<Runtime as Config>::ExtensionWeightInfo::vote_with_equivocation())
    }
}

impl<Runtime> TransactionExtension<RuntimeCallFor<Runtime>> for SubspaceExtension<Runtime>
where
    Runtime: Config + scale_info::TypeInfo + Send + Sync,
    <RuntimeCallFor<Runtime> as Dispatchable>::RuntimeOrigin:
        AsSystemOriginSigner<<Runtime as frame_system::Config>::AccountId> + From<Origin> + Clone,
    RuntimeCallFor<Runtime>: MaybeSubspaceCall<Runtime>,
{
    const IDENTIFIER: &'static str = "SubspaceExtension";
    type Implicit = ();
    type Val = ExtensionWeightData;
    type Pre = ExtensionWeightData;

    fn weight(&self, call: &RuntimeCallFor<Runtime>) -> Weight {
        match call.maybe_subspace_call() {
            Some(SubspaceCall::vote { .. }) => Self::max_weight(),
            _ => Weight::zero(),
        }
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
            return Ok((
                ValidTransaction::default(),
                ExtensionWeightData::Skipped,
                origin,
            ));
        };

        let subspace_call = match call.maybe_subspace_call() {
            Some(subspace_call) => subspace_call,
            None => {
                return Ok((
                    ValidTransaction::default(),
                    ExtensionWeightData::Skipped,
                    origin,
                ));
            }
        };

        let (validity, weight_used) = match subspace_call {
            SubspaceCall::vote { signed_vote } => Self::do_check_vote(signed_vote, source)?,
            _ => return Err(InvalidTransaction::Call.into()),
        };

        Ok((
            validity,
            ExtensionWeightData::Validated(weight_used),
            Origin::ValidatedUnsigned.into(),
        ))
    }

    fn prepare(
        self,
        val: Self::Val,
        _origin: &DispatchOriginOf<RuntimeCallFor<Runtime>>,
        _call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        Ok(val)
    }

    fn post_dispatch_details(
        pre: Self::Pre,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _post_info: &PostDispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
        _result: &DispatchResult,
    ) -> Result<Weight, TransactionValidityError> {
        match pre {
            // return the unused weight for a validated call.
            ExtensionWeightData::Validated(used_weight) => {
                Ok(Self::max_weight().saturating_sub(used_weight))
            }
            // return no weight since this call is not validated and took no weight.
            ExtensionWeightData::Skipped => Ok(Weight::zero()),
        }
    }
}

/// Extension for runtime call monitoring.
#[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct CallMonitorExtension<Runtime>(PhantomData<Runtime>);

impl<Runtime> CallMonitorExtension<Runtime> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<Runtime> Default for CallMonitorExtension<Runtime> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Runtime> fmt::Debug for CallMonitorExtension<Runtime> {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CallMonitorExtension",)
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

impl<Runtime> CallMonitorExtension<Runtime>
where
    Runtime: pallet_sudo::Config + scale_info::TypeInfo + Send + Sync,
{
    /// Log a sudo call before it is called.
    fn do_log_sudo_call(sudo_call: &SudoCall<Runtime>, source: TransactionSource, len: usize) {
        info!(
            "subspace sudo call: {:?} ({} bytes) from source: {:?}",
            sudo_call, len, source,
        );
    }

    /// Log the outcome of a sudo call.
    fn do_log_sudo_call_result(result: &DispatchResult, len: usize) {
        info!("subspace sudo call ({} bytes) result: {:?}", len, result);
    }

    fn max_weight() -> Weight {
        // We assume this extension runs in less than 300 instructions (100 microseconds).
        // TODO: benchmark this extension if it ever does significant work
        Weight::from_parts(100_000, 0)
    }
}

impl<Runtime> TransactionExtension<RuntimeCallFor<Runtime>> for CallMonitorExtension<Runtime>
where
    Runtime: pallet_sudo::Config + scale_info::TypeInfo + Send + Sync,
    <RuntimeCallFor<Runtime> as Dispatchable>::RuntimeOrigin:
        AsSystemOriginSigner<<Runtime as frame_system::Config>::AccountId> + From<Origin> + Clone,
    RuntimeCallFor<Runtime>: MaybeSudoCall<Runtime>,
{
    const IDENTIFIER: &'static str = "CallMonitorExtension";
    type Implicit = ();
    type Val = ExtensionWeightData;
    type Pre = ExtensionWeightData;

    fn weight(&self, call: &RuntimeCallFor<Runtime>) -> Weight {
        match call.maybe_sudo_call() {
            Some(_sudo_call) => Self::max_weight(),
            _ => Weight::zero(),
        }
    }

    fn validate(
        &self,
        origin: DispatchOriginOf<RuntimeCallFor<Runtime>>,
        call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        len: usize,
        _self_implicit: Self::Implicit,
        _inherited_implication: &impl Implication,
        source: TransactionSource,
    ) -> ValidateResult<Self::Val, RuntimeCallFor<Runtime>> {
        // we only care about successful sudo calls, from the root origin
        if let Ok(()) = ensure_root(origin.clone())
            && let Some(sudo_call) = call.maybe_sudo_call()
        {
            Self::do_log_sudo_call(sudo_call, source, len);

            Ok((
                ValidTransaction::default(),
                ExtensionWeightData::Validated(Self::max_weight()),
                origin,
            ))
        } else {
            Ok((
                ValidTransaction::default(),
                ExtensionWeightData::Skipped,
                origin,
            ))
        }
    }

    fn prepare(
        self,
        val: Self::Val,
        _origin: &DispatchOriginOf<RuntimeCallFor<Runtime>>,
        _call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        Ok(val)
    }

    fn post_dispatch_details(
        pre: Self::Pre,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _post_info: &PostDispatchInfoOf<RuntimeCallFor<Runtime>>,
        len: usize,
        result: &DispatchResult,
    ) -> Result<Weight, TransactionValidityError> {
        match pre {
            // return the unused weight for a validated call.
            ExtensionWeightData::Validated(used_weight) => {
                // TODO: clone the call into `pre` and log it here as well if neeed
                Self::do_log_sudo_call_result(result, len);
                Ok(Self::max_weight().saturating_sub(used_weight))
            }
            // return no weight since this call is not validated and took no weight.
            ExtensionWeightData::Skipped => Ok(Weight::zero()),
        }
    }
}

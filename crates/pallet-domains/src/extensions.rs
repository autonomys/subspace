//! Extensions for unsigned general extrinsics

use crate::pallet::Call as DomainsCall;
use crate::{
    Config, FraudProofFor, OpaqueBundleOf, Origin, Pallet as Domains, SingletonReceiptOf,
    WeightInfo,
};
use frame_support::ensure;
use frame_support::pallet_prelude::{PhantomData, TypeInfo};
use frame_support::weights::Weight;
use frame_system::pallet_prelude::RuntimeCallFor;
use parity_scale_codec::{Decode, Encode};
use scale_info::prelude::fmt;
use sp_domains_fraud_proof::InvalidTransactionCode;
use sp_domains_fraud_proof::weights::fraud_proof_verification_weights;
use sp_runtime::impl_tx_ext_default;
use sp_runtime::traits::{
    AsSystemOriginSigner, DispatchInfoOf, DispatchOriginOf, Dispatchable, Get, Implication,
    TransactionExtension, ValidateResult,
};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionLongevity, TransactionSource, TransactionValidity,
    ValidTransaction,
};

/// Trait to convert Runtime call to possible Domains call.
pub trait MaybeDomainsCall<Runtime>
where
    Runtime: Config,
{
    fn maybe_domains_call(&self) -> Option<&DomainsCall<Runtime>>;
}

/// Trait to check if the Domains are enabled on Consensus.
pub trait DomainsCheck {
    /// Check if the domains are enabled on Runtime.
    fn is_domains_enabled() -> bool;
}

/// Extensions for pallet-domains unsigned extrinsics.
#[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct DomainsExtension<Runtime>(PhantomData<Runtime>);

impl<Runtime> DomainsExtension<Runtime> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<Runtime> Default for DomainsExtension<Runtime> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Config> fmt::Debug for DomainsExtension<T> {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DomainsExtension",)
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

impl<Runtime> DomainsExtension<Runtime>
where
    Runtime: Config + scale_info::TypeInfo + fmt::Debug + Send + Sync,
{
    fn do_validate_submit_bundle(
        opaque_bundle: &OpaqueBundleOf<Runtime>,
        source: TransactionSource,
    ) -> TransactionValidity {
        let pre_dispatch = TransactionSource::InBlock == source;
        if pre_dispatch {
            Domains::<Runtime>::validate_submit_bundle(opaque_bundle, true)
                .map_err(|_| InvalidTransaction::Call.into())
                .map(|_| ValidTransaction::default())
        } else {
            let domain_id = opaque_bundle.domain_id();
            let operator_id = opaque_bundle.operator_id();
            let slot_number = opaque_bundle.slot_number();

            if let Err(e) = Domains::<Runtime>::validate_submit_bundle(opaque_bundle, false) {
                Domains::<Runtime>::log_bundle_error(&e, domain_id, operator_id);
                return e.into();
            }

            ValidTransaction::with_tag_prefix("SubspaceSubmitBundle")
                // Bundle have a bit higher priority than normal extrinsic but must less than
                // fraud proof
                .priority(1)
                .longevity(
                    Runtime::ConfirmationDepthK::get()
                        .try_into()
                        .unwrap_or_else(|_| {
                            panic!("Block number always fits in TransactionLongevity; qed")
                        }),
                )
                .and_provides((operator_id, slot_number))
                .propagate(true)
                .build()
        }
    }

    fn do_validate_fraud_proof(
        fraud_proof: &FraudProofFor<Runtime>,
        source: TransactionSource,
    ) -> TransactionValidity {
        let pre_dispatch = TransactionSource::InBlock == source;
        if pre_dispatch {
            Domains::<Runtime>::validate_fraud_proof(fraud_proof)
                .map(|_| ())
                .map_err(|_| InvalidTransaction::Call.into())
                .map(|_| ValidTransaction::default())
        } else {
            let (tag, priority) = match Domains::<Runtime>::validate_fraud_proof(fraud_proof) {
                Err(e) => {
                    log::warn!("Bad fraud proof {fraud_proof:?}, error: {e:?}",);
                    return InvalidTransactionCode::FraudProof.into();
                }
                Ok(tp) => tp,
            };

            ValidTransaction::with_tag_prefix("SubspaceSubmitFraudProof")
                .priority(priority)
                .and_provides(tag)
                .longevity(TransactionLongevity::MAX)
                // We need this extrinsic to be propagated to the farmer nodes.
                .propagate(true)
                .build()
        }
    }

    fn do_validate_singleton_receipt(
        singleton_receipt: &SingletonReceiptOf<Runtime>,
        source: TransactionSource,
    ) -> TransactionValidity {
        let pre_dispatch = TransactionSource::InBlock == source;
        if pre_dispatch {
            Domains::<Runtime>::validate_singleton_receipt(singleton_receipt, true)
                .map_err(|_| InvalidTransaction::Call.into())
                .map(|_| ValidTransaction::default())
        } else {
            let domain_id = singleton_receipt.domain_id();
            let operator_id = singleton_receipt.operator_id();
            let slot_number = singleton_receipt.slot_number();

            if let Err(e) = Domains::<Runtime>::validate_singleton_receipt(singleton_receipt, false)
            {
                Domains::<Runtime>::log_bundle_error(&e, domain_id, operator_id);
                return e.into();
            }

            ValidTransaction::with_tag_prefix("SubspaceSubmitReceipt")
                // Receipt have a bit higher priority than normal extrinsic but must less than
                // fraud proof
                .priority(1)
                .longevity(
                    Runtime::ConfirmationDepthK::get()
                        .try_into()
                        .unwrap_or_else(|_| {
                            panic!("Block number always fits in TransactionLongevity; qed")
                        }),
                )
                .and_provides((operator_id, slot_number))
                .propagate(true)
                .build()
        }
    }
}

impl<Runtime> TransactionExtension<RuntimeCallFor<Runtime>> for DomainsExtension<Runtime>
where
    Runtime: Config + scale_info::TypeInfo + fmt::Debug + Send + Sync + DomainsCheck,
    <RuntimeCallFor<Runtime> as Dispatchable>::RuntimeOrigin:
        AsSystemOriginSigner<<Runtime as frame_system::Config>::AccountId> + From<Origin> + Clone,
    RuntimeCallFor<Runtime>: MaybeDomainsCall<Runtime>,
{
    const IDENTIFIER: &'static str = "DomainsExtension";
    type Implicit = ();
    type Val = ();
    type Pre = ();

    fn weight(&self, call: &Runtime::RuntimeCall) -> Weight {
        // This extension only apply to the following 3 calls thus only return weight for them.
        let maybe_weight = match call.maybe_domains_call() {
            Some(DomainsCall::submit_bundle { .. }) => {
                Some(<Runtime as Config>::WeightInfo::validate_submit_bundle())
            }
            Some(DomainsCall::submit_fraud_proof { fraud_proof }) => Some(
                <Runtime as Config>::WeightInfo::fraud_proof_pre_check()
                    .saturating_add(fraud_proof_verification_weights::<_, _, _, _>(fraud_proof)),
            ),
            Some(DomainsCall::submit_receipt { .. }) => {
                Some(<Runtime as Config>::WeightInfo::validate_singleton_receipt())
            }
            _ => None,
        };

        // There is one additional runtime read to check if the domains are enabled
        maybe_weight
            .and_then(|weight| weight.checked_add(&Runtime::DbWeight::get().reads(1)))
            .unwrap_or(Runtime::DbWeight::get().reads(1))
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

        let domains_call = match call.maybe_domains_call() {
            Some(domains_call) => domains_call,
            None => return Ok((ValidTransaction::default(), (), origin)),
        };

        // ensure domains are enabled
        ensure!(Runtime::is_domains_enabled(), InvalidTransaction::Call);

        let validity = match domains_call {
            DomainsCall::submit_bundle { opaque_bundle } => {
                Self::do_validate_submit_bundle(opaque_bundle, source)?
            }
            DomainsCall::submit_fraud_proof { fraud_proof } => {
                Self::do_validate_fraud_proof(fraud_proof, source)?
            }
            DomainsCall::submit_receipt { singleton_receipt } => {
                Self::do_validate_singleton_receipt(singleton_receipt, source)?
            }
            _ => return Err(InvalidTransaction::Call.into()),
        };

        Ok((validity, (), Origin::ValidatedUnsigned.into()))
    }

    impl_tx_ext_default!(RuntimeCallFor<Runtime>; prepare);
}

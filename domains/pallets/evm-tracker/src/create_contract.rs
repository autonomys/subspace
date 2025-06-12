//! Contract creation allow list implementations

use crate::traits::{AccountIdFor, MaybeIntoEthCall, MaybeIntoEvmCall};
use crate::weights::SubstrateWeightInfo;
use crate::{MAXIMUM_NUMBER_OF_CALLS, WeightInfo};
use domain_runtime_primitives::{ERR_CONTRACT_CREATION_NOT_ALLOWED, EthereumAccountId};
use frame_support::RuntimeDebugNoBound;
use frame_support::dispatch::PostDispatchInfo;
use frame_support::pallet_prelude::{DispatchResult, PhantomData, TypeInfo};
use frame_system::pallet_prelude::{OriginFor, RuntimeCallFor};
use pallet_ethereum::{Transaction as EthereumTransaction, TransactionAction};
use parity_scale_codec::{Decode, Encode};
use scale_info::prelude::fmt;
use sp_runtime::traits::{
    AsSystemOriginSigner, DispatchInfoOf, DispatchOriginOf, Dispatchable, PostDispatchInfoOf,
    RefundWeight, TransactionExtension, ValidateResult,
};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidity, TransactionValidityError,
    ValidTransaction,
};
use sp_weights::Weight;
use subspace_runtime_primitives::utility::{MaybeNestedCall, nested_call_iter};

/// Rejects contracts that can't be created under the current allow list.
/// Returns false if the call is a contract call, and the account is *not* allowed to call it.
/// Otherwise, returns true.
pub fn is_create_contract_allowed<Runtime>(
    call: &RuntimeCallFor<Runtime>,
    signer: &EthereumAccountId,
) -> (bool, u32)
where
    Runtime: frame_system::Config<AccountId = EthereumAccountId>
        + pallet_ethereum::Config
        + pallet_evm::Config
        + crate::Config,
    RuntimeCallFor<Runtime>:
        MaybeIntoEthCall<Runtime> + MaybeIntoEvmCall<Runtime> + MaybeNestedCall<Runtime>,
    Result<pallet_ethereum::RawOrigin, OriginFor<Runtime>>: From<OriginFor<Runtime>>,
{
    // If the account is allowed to create contracts, or it's not a contract call, return true.
    // Only enters allocating code if this account can't create contracts.
    if crate::Pallet::<Runtime>::is_allowed_to_create_contracts(signer) {
        return (true, 0);
    }

    let (is_create, call_count) = is_create_contract::<Runtime>(call);
    (!is_create, call_count)
}

/// If anyone is allowed to create contracts, allows contracts. Otherwise, rejects contracts.
/// Returns false if the call is a contract call, and there is a specific (possibly empty) allow
/// list. Otherwise, returns true.
pub fn is_create_unsigned_contract_allowed<Runtime>(call: &RuntimeCallFor<Runtime>) -> (bool, u32)
where
    Runtime: frame_system::Config + pallet_ethereum::Config + pallet_evm::Config + crate::Config,
    RuntimeCallFor<Runtime>:
        MaybeIntoEthCall<Runtime> + MaybeIntoEvmCall<Runtime> + MaybeNestedCall<Runtime>,
    Result<pallet_ethereum::RawOrigin, OriginFor<Runtime>>: From<OriginFor<Runtime>>,
{
    // If any account is allowed to create contracts, or it's not a contract call, return true.
    // Only enters allocating code if there is a contract creation filter.
    if crate::Pallet::<Runtime>::is_allowed_to_create_unsigned_contracts() {
        return (true, 0);
    }

    let (is_create, call_count) = is_create_contract::<Runtime>(call);
    (!is_create, call_count)
}

/// Returns true if the call is a contract creation call.
pub fn is_create_contract<Runtime>(call: &RuntimeCallFor<Runtime>) -> (bool, u32)
where
    Runtime: frame_system::Config + pallet_ethereum::Config + pallet_evm::Config,
    RuntimeCallFor<Runtime>:
        MaybeIntoEthCall<Runtime> + MaybeIntoEvmCall<Runtime> + MaybeNestedCall<Runtime>,
    Result<pallet_ethereum::RawOrigin, OriginFor<Runtime>>: From<OriginFor<Runtime>>,
{
    let mut call_count = 0;
    for call in nested_call_iter::<Runtime>(call) {
        call_count += 1;

        if let Some(call) = call.maybe_into_eth_call() {
            match call {
                pallet_ethereum::Call::transact {
                    transaction: EthereumTransaction::Legacy(transaction),
                    ..
                } => {
                    if transaction.action == TransactionAction::Create {
                        return (true, call_count);
                    }
                }
                pallet_ethereum::Call::transact {
                    transaction: EthereumTransaction::EIP2930(transaction),
                    ..
                } => {
                    if transaction.action == TransactionAction::Create {
                        return (true, call_count);
                    }
                }
                pallet_ethereum::Call::transact {
                    transaction: EthereumTransaction::EIP1559(transaction),
                    ..
                } => {
                    if transaction.action == TransactionAction::Create {
                        return (true, call_count);
                    }
                }
                // Inconclusive, other calls might create contracts.
                _ => {}
            }
        }

        if let Some(pallet_evm::Call::create { .. } | pallet_evm::Call::create2 { .. }) =
            call.maybe_into_evm_call()
        {
            return (true, call_count);
        }
    }

    (false, call_count)
}

/// Reject contract creation, unless the account is in the current evm contract allow list.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct CheckContractCreation<Runtime>(PhantomData<Runtime>);

impl<Runtime> CheckContractCreation<Runtime> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<Runtime> Default for CheckContractCreation<Runtime> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Runtime> CheckContractCreation<Runtime>
where
    Runtime: frame_system::Config<AccountId = EthereumAccountId>
        + pallet_ethereum::Config
        + pallet_evm::Config
        + crate::Config
        + scale_info::TypeInfo
        + fmt::Debug
        + Send
        + Sync,
    RuntimeCallFor<Runtime>:
        MaybeIntoEthCall<Runtime> + MaybeIntoEvmCall<Runtime> + MaybeNestedCall<Runtime>,
    Result<pallet_ethereum::RawOrigin, OriginFor<Runtime>>: From<OriginFor<Runtime>>,
    <RuntimeCallFor<Runtime> as Dispatchable>::RuntimeOrigin:
        AsSystemOriginSigner<AccountIdFor<Runtime>> + Clone,
{
    pub(crate) fn do_validate_unsigned(
        call: &RuntimeCallFor<Runtime>,
    ) -> Result<(ValidTransaction, u32), TransactionValidityError> {
        let (is_allowed, call_count) = is_create_unsigned_contract_allowed::<Runtime>(call);
        if !is_allowed {
            Err(InvalidTransaction::Custom(ERR_CONTRACT_CREATION_NOT_ALLOWED).into())
        } else {
            Ok((ValidTransaction::default(), call_count))
        }
    }

    pub(crate) fn do_validate_signed(
        origin: &OriginFor<Runtime>,
        call: &RuntimeCallFor<Runtime>,
    ) -> Result<(ValidTransaction, u32), TransactionValidityError> {
        let Some(who) = origin.as_system_origin_signer() else {
            // Reject unsigned contract creation unless anyone is allowed to create them.
            return Self::do_validate_unsigned(call);
        };

        // Reject contract creation unless the account is in the allow list.
        let (is_allowed, call_count) = is_create_contract_allowed::<Runtime>(call, who);
        if !is_allowed {
            Err(InvalidTransaction::Custom(ERR_CONTRACT_CREATION_NOT_ALLOWED).into())
        } else {
            Ok((ValidTransaction::default(), call_count))
        }
    }

    pub fn get_weights(n: u32) -> Weight {
        SubstrateWeightInfo::<Runtime>::evm_contract_check_multiple(n)
            .max(SubstrateWeightInfo::<Runtime>::evm_contract_check_nested(n))
    }
}

/// Data passed from prepare to post_dispatch.
#[derive(RuntimeDebugNoBound)]
pub enum Pre {
    /// Refund this exact amount of weight.
    Refund(Weight),
}

/// Data passed from validate to prepare.
#[derive(RuntimeDebugNoBound)]
pub enum Val {
    /// Partially refund, based on the actual number of calls.
    PartialRefund(u32),
}

// Unsigned calls can't create contracts. Only pallet-evm and pallet-ethereum can create contracts.
// For pallet-evm all contracts are signed extrinsics, for pallet-ethereum there is only one
// extrinsic that is self-contained.
impl<Runtime> TransactionExtension<RuntimeCallFor<Runtime>> for CheckContractCreation<Runtime>
where
    Runtime: frame_system::Config<AccountId = EthereumAccountId>
        + pallet_ethereum::Config
        + pallet_evm::Config
        + crate::Config
        + scale_info::TypeInfo
        + fmt::Debug
        + Send
        + Sync,
    RuntimeCallFor<Runtime>:
        MaybeIntoEthCall<Runtime> + MaybeIntoEvmCall<Runtime> + MaybeNestedCall<Runtime>,
    Result<pallet_ethereum::RawOrigin, OriginFor<Runtime>>: From<OriginFor<Runtime>>,
    <RuntimeCallFor<Runtime> as Dispatchable>::RuntimeOrigin:
        AsSystemOriginSigner<AccountIdFor<Runtime>> + Clone,
    for<'a> &'a mut PostDispatchInfoOf<RuntimeCallFor<Runtime>>: Into<&'a mut PostDispatchInfo>,
{
    const IDENTIFIER: &'static str = "CheckContractCreation";
    type Implicit = ();
    type Val = Val;
    type Pre = Pre;

    fn weight(&self, _: &RuntimeCallFor<Runtime>) -> Weight {
        Self::get_weights(MAXIMUM_NUMBER_OF_CALLS)
    }

    fn validate(
        &self,
        origin: OriginFor<Runtime>,
        call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
        _self_implicit: Self::Implicit,
        _inherited_implication: &impl Encode,
        _source: TransactionSource,
    ) -> ValidateResult<Self::Val, RuntimeCallFor<Runtime>> {
        let (validity, val) = if origin.as_system_origin_signer().is_some() {
            let (valid, call_count) = Self::do_validate_signed(&origin, call)?;
            (valid, Val::PartialRefund(call_count))
        } else {
            let (valid, call_count) = Self::do_validate_unsigned(call)?;
            (valid, Val::PartialRefund(call_count))
        };

        Ok((validity, val, origin))
    }

    fn prepare(
        self,
        val: Self::Val,
        _origin: &DispatchOriginOf<RuntimeCallFor<Runtime>>,
        _call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        let pre_dispatch_weights = Self::get_weights(MAXIMUM_NUMBER_OF_CALLS);
        match val {
            // Refund any extra call weight
            // TODO: use frame_system::Pallet::<Runtime>::reclaim_weight when we upgrade to 40.1.0
            // See <https://github.com/paritytech/polkadot-sdk/blob/292368d05eec5d6649607251ab21ed2c96ebd158/cumulus/pallets/weight-reclaim/src/lib.rs#L178>
            Val::PartialRefund(calls) => {
                let actual_weights = Self::get_weights(calls);
                Ok(Pre::Refund(
                    pre_dispatch_weights.saturating_sub(actual_weights),
                ))
            }
        }
    }

    fn post_dispatch_details(
        pre: Self::Pre,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _post_info: &PostDispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
        _result: &DispatchResult,
    ) -> Result<Weight, TransactionValidityError> {
        let Pre::Refund(weight) = pre;
        Ok(weight)
    }

    fn bare_validate(
        call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
    ) -> TransactionValidity {
        Self::do_validate_unsigned(call).map(|(validity, _call_count)| validity)
    }

    fn bare_validate_and_prepare(
        call: &RuntimeCallFor<Runtime>,
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
    ) -> Result<(), TransactionValidityError> {
        Self::do_validate_unsigned(call)?;
        Ok(())
    }

    // Weights for bare calls are calculated in the runtime, and excess weight refunded here.
    fn bare_post_dispatch(
        _info: &DispatchInfoOf<RuntimeCallFor<Runtime>>,
        post_info: &mut PostDispatchInfoOf<RuntimeCallFor<Runtime>>,
        _len: usize,
        _result: &DispatchResult,
    ) -> Result<(), TransactionValidityError> {
        let pre_dispatch_weights = Self::get_weights(MAXIMUM_NUMBER_OF_CALLS);
        // The number of Ethereum calls in a RuntimeCall is always 1, this is checked by
        // is_self_contained() in the runtime.
        let actual_weights = Self::get_weights(1);

        // TODO: use frame_system::Pallet::<Runtime>::reclaim_weight when we upgrade to 40.1.0
        let unspent = pre_dispatch_weights.saturating_sub(actual_weights);

        // If we overcharged the weight, refund the extra weight.
        let post_info = Into::<&mut PostDispatchInfo>::into(post_info);
        if let Some(actual_weight) = post_info.actual_weight
            && actual_weight.ref_time() >= pre_dispatch_weights.ref_time()
        {
            post_info.refund(unspent);
        }

        Ok(())
    }
}

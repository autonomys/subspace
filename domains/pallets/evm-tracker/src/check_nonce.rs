use crate::Config;
#[cfg(not(feature = "std"))]
use alloc::vec;
use core::cmp::max;
use core::fmt;
use core::result::Result;
use frame_support::RuntimeDebugNoBound;
use frame_support::dispatch::DispatchInfo;
use frame_support::pallet_prelude::{
    InvalidTransaction, TransactionLongevity, TransactionValidityError, TypeInfo, ValidTransaction,
    Weight,
};
use frame_support::sp_runtime::traits::{DispatchInfoOf, One, TransactionExtension};
use parity_scale_codec::{Decode, Encode};
use sp_runtime::DispatchResult;
use sp_runtime::traits::{
    AsSystemOriginSigner, Dispatchable, PostDispatchInfoOf, ValidateResult, Zero,
};
use sp_runtime::transaction_validity::TransactionSource;
#[cfg(feature = "std")]
use std::vec;

#[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct CheckNonce<T: Config>(#[codec(compact)] pub T::Nonce);

impl<T: Config> CheckNonce<T> {
    /// utility constructor. Used only in client/factory code.
    pub fn from(nonce: T::Nonce) -> Self {
        Self(nonce)
    }
}

impl<T: Config> fmt::Debug for CheckNonce<T> {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CheckNonce({})", self.0)
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

/// Operation to perform from `validate` to `prepare` in [`frame_system::CheckNonce`] transaction extension.
#[derive(RuntimeDebugNoBound)]
pub enum Val<T: frame_system::Config> {
    /// Account and its nonce to check for.
    CheckNonce((T::AccountId, T::Nonce)),
    /// Weight to refund.
    Refund(Weight),
}

/// Operation to perform from `prepare` to `post_dispatch_details` in [`frame_system::CheckNonce`] transaction
/// extension.
#[derive(RuntimeDebugNoBound)]
pub enum Pre {
    /// The transaction extension weight should not be refunded.
    NonceChecked,
    /// The transaction extension weight should be refunded.
    Refund(Weight),
}

impl<T: Config> TransactionExtension<T::RuntimeCall> for CheckNonce<T>
where
    T::RuntimeCall: Dispatchable<Info = DispatchInfo>,
    <T::RuntimeCall as Dispatchable>::RuntimeOrigin: AsSystemOriginSigner<T::AccountId> + Clone,
{
    const IDENTIFIER: &'static str = "CheckNonce";
    type Implicit = ();
    type Val = Val<T>;
    type Pre = Pre;

    fn weight(&self, _: &T::RuntimeCall) -> sp_weights::Weight {
        <T::ExtensionsWeightInfo as frame_system::ExtensionsWeightInfo>::check_nonce()
    }

    fn validate(
        &self,
        origin: <T as frame_system::Config>::RuntimeOrigin,
        call: &T::RuntimeCall,
        _info: &DispatchInfoOf<T::RuntimeCall>,
        _len: usize,
        _self_implicit: Self::Implicit,
        _inherited_implication: &impl Encode,
        _source: TransactionSource,
    ) -> ValidateResult<Self::Val, T::RuntimeCall> {
        let Some(who) = origin.as_system_origin_signer() else {
            return Ok((Default::default(), Val::Refund(self.weight(call)), origin));
        };

        let account = frame_system::Account::<T>::get(who);
        if account.providers.is_zero() && account.sufficients.is_zero() {
            // Nonce storage not paid for
            return Err(InvalidTransaction::Payment.into());
        }
        if self.0 < account.nonce {
            return Err(InvalidTransaction::Stale.into());
        }

        let provides = vec![Encode::encode(&(who, self.0))];
        let requires = if account.nonce < self.0 {
            vec![Encode::encode(&(who, self.0 - One::one()))]
        } else {
            vec![]
        };

        let validity = ValidTransaction {
            priority: 0,
            requires,
            provides,
            longevity: TransactionLongevity::MAX,
            propagate: true,
        };

        Ok((
            validity,
            Val::CheckNonce((who.clone(), account.nonce)),
            origin,
        ))
    }

    fn prepare(
        self,
        val: Self::Val,
        _origin: &T::RuntimeOrigin,
        _call: &T::RuntimeCall,
        _info: &DispatchInfoOf<T::RuntimeCall>,
        _len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        let (who, mut nonce) = match val {
            Val::CheckNonce((who, nonce)) => (who, nonce),
            Val::Refund(weight) => return Ok(Pre::Refund(weight)),
        };

        // if a sender sends an evm transaction first and substrate transaction
        // after with same nonce, then reject the second transaction
        // if sender reverse the transaction types, substrate first and evm second,
        // evm transaction will be rejected, since substrate updates nonce in pre_dispatch.
        let account_nonce = if let Some(tracked_nonce) = crate::AccountNonce::<T>::get(who.clone())
        {
            max(tracked_nonce.as_u32().into(), nonce)
        } else {
            nonce
        };

        if self.0 != account_nonce {
            return Err(if self.0 < nonce {
                InvalidTransaction::Stale
            } else {
                InvalidTransaction::Future
            }
            .into());
        }
        nonce += T::Nonce::one();
        frame_system::Account::<T>::mutate(who, |account| account.nonce = nonce);
        Ok(Pre::NonceChecked)
    }

    fn post_dispatch_details(
        pre: Self::Pre,
        _info: &DispatchInfo,
        _post_info: &PostDispatchInfoOf<T::RuntimeCall>,
        _len: usize,
        _result: &DispatchResult,
    ) -> Result<Weight, TransactionValidityError> {
        match pre {
            Pre::NonceChecked => Ok(Weight::zero()),
            Pre::Refund(weight) => Ok(weight),
        }
    }
}

use crate::{AccountId, EVMNoncetracker, Runtime, RuntimeCall};
use codec::{Decode, Encode};
use domain_runtime_primitives::Nonce;
use frame_support::pallet_prelude::{
    InvalidTransaction, TransactionLongevity, TransactionValidity, TransactionValidityError,
    TypeInfo, ValidTransaction,
};
use frame_support::sp_runtime::traits::{DispatchInfoOf, One, SignedExtension, Zero};
use sp_core::{H160, U256};
use sp_std::cmp::max;
use sp_std::vec;

/// Check nonce is a fork of frame_system::CheckNonce with change to pre_dispatch function
/// where this fork uses EVMNonceTracker to track the nonce since EVM pre_dispatch does not
/// increment the nonce unlike the Substrate pre_dispatch
#[derive(Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct CheckNonce(#[codec(compact)] pub Nonce);

impl CheckNonce {
    /// utility constructor. Used only in client/factory code.
    pub fn from(nonce: Nonce) -> Self {
        Self(nonce)
    }
}

impl sp_std::fmt::Debug for CheckNonce {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        write!(f, "CheckNonce({})", self.0)
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
        Ok(())
    }
}

impl SignedExtension for CheckNonce {
    const IDENTIFIER: &'static str = "CheckNonce";
    type AccountId = AccountId;
    type Call = RuntimeCall;
    type AdditionalSigned = ();
    type Pre = ();

    fn additional_signed(&self) -> Result<(), TransactionValidityError> {
        Ok(())
    }

    fn validate(
        &self,
        who: &Self::AccountId,
        _call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> TransactionValidity {
        let account = frame_system::Account::<Runtime>::get(who);
        if account.providers.is_zero() && account.sufficients.is_zero() {
            // Nonce storage not paid for
            return InvalidTransaction::Payment.into();
        }
        if self.0 < account.nonce {
            return InvalidTransaction::Stale.into();
        }

        let provides = vec![Encode::encode(&(who, self.0))];
        let requires = if account.nonce < self.0 {
            vec![Encode::encode(&(who, self.0 - Nonce::one()))]
        } else {
            vec![]
        };

        Ok(ValidTransaction {
            priority: 0,
            requires,
            provides,
            longevity: TransactionLongevity::MAX,
            propagate: true,
        })
    }

    fn pre_dispatch(
        self,
        who: &Self::AccountId,
        _call: &Self::Call,
        _info: &DispatchInfoOf<Self::Call>,
        _len: usize,
    ) -> Result<(), TransactionValidityError> {
        let mut account = frame_system::Account::<Runtime>::get(who);
        if account.providers.is_zero() && account.sufficients.is_zero() {
            // Nonce storage not paid for
            return Err(InvalidTransaction::Payment.into());
        }

        // if a sender sends an evm transaction first and substrate transaction
        // after with same nonce, then reject the second transaction
        // if sender reverse the transaction types, substrate first and evm second,
        // evm transaction will be rejected, since substrate updates nonce in pre_dispatch.
        let account_nonce =
            if let Some(tracked_nonce) = EVMNoncetracker::account_nonce(H160::from(*who)) {
                let account_nonce = U256::from(account.nonce);
                let current_nonce = max(tracked_nonce, account_nonce);
                current_nonce.as_u32()
            } else {
                account.nonce
            };

        if self.0 != account_nonce {
            return Err(if self.0 < account.nonce {
                InvalidTransaction::Stale
            } else {
                InvalidTransaction::Future
            }
            .into());
        }
        account.nonce += Nonce::one();
        frame_system::Account::<Runtime>::insert(who, account);
        Ok(())
    }
}

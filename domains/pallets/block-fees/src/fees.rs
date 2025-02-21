use crate::Pallet as BlockFees;
use codec::Encode;
use frame_support::traits::fungible::Inspect;
use frame_support::traits::tokens::WithdrawConsequence;
use frame_support::traits::{Currency, ExistenceRequirement, Imbalance, WithdrawReasons};
use sp_runtime::traits::{DispatchInfoOf, PostDispatchInfoOf, Zero};
use sp_runtime::transaction_validity::{InvalidTransaction, TransactionValidityError};
use sp_runtime::Saturating;
use sp_std::marker::PhantomData;

pub struct LiquidityInfo<Balance, NegativeImbalance> {
    consensus_storage_fee: Balance,
    imbalance: NegativeImbalance,
}

type AccountIdOf<T> = <T as frame_system::Config>::AccountId;
type BalanceOf<C, T> = <C as Currency<AccountIdOf<T>>>::Balance;
type NegativeImbalanceOf<C, T> = <C as Currency<AccountIdOf<T>>>::NegativeImbalance;

/// Implementation of [`pallet_transaction_payment::OnChargeTransaction`] that charges transaction
/// fees and distributes storage/compute fees and tip separately.
pub struct OnChargeDomainTransaction<C>(PhantomData<C>);

impl<T, C> pallet_transaction_payment::OnChargeTransaction<T> for OnChargeDomainTransaction<C>
where
    T: pallet_transaction_payment::Config + crate::Config<Balance = BalanceOf<C, T>>,
    C: Currency<AccountIdOf<T>> + Inspect<AccountIdOf<T>, Balance = BalanceOf<C, T>>,
    C::PositiveImbalance: Imbalance<BalanceOf<C, T>, Opposite = C::NegativeImbalance>,
{
    type Balance = BalanceOf<C, T>;
    type LiquidityInfo = Option<LiquidityInfo<BalanceOf<C, T>, NegativeImbalanceOf<C, T>>>;

    fn withdraw_fee(
        who: &AccountIdOf<T>,
        call: &T::RuntimeCall,
        _info: &DispatchInfoOf<T::RuntimeCall>,
        fee: Self::Balance,
        tip: Self::Balance,
    ) -> Result<Self::LiquidityInfo, TransactionValidityError> {
        if fee.is_zero() {
            return Ok(None);
        }

        let withdraw_reason = if tip.is_zero() {
            WithdrawReasons::TRANSACTION_PAYMENT
        } else {
            WithdrawReasons::TRANSACTION_PAYMENT | WithdrawReasons::TIP
        };

        let withdraw_result =
            C::withdraw(who, fee, withdraw_reason, ExistenceRequirement::KeepAlive);
        let imbalance = withdraw_result.map_err(|_error| InvalidTransaction::Payment)?;

        // Separate consensus storage fee while we have access to the call data structure to calculate it.
        let consensus_storage_fee = BlockFees::<T>::consensus_chain_byte_fee()
            * Self::Balance::from(call.encoded_size() as u32);

        Ok(Some(LiquidityInfo {
            consensus_storage_fee,
            imbalance,
        }))
    }

    fn can_withdraw_fee(
        who: &T::AccountId,
        _call: &T::RuntimeCall,
        _dispatch_info: &DispatchInfoOf<T::RuntimeCall>,
        fee: Self::Balance,
        _tip: Self::Balance,
    ) -> Result<(), TransactionValidityError> {
        if fee.is_zero() {
            return Ok(());
        }

        match C::can_withdraw(who, fee) {
            WithdrawConsequence::Success => Ok(()),
            _ => Err(InvalidTransaction::Payment.into()),
        }
    }

    fn correct_and_deposit_fee(
        who: &AccountIdOf<T>,
        _dispatch_info: &DispatchInfoOf<T::RuntimeCall>,
        _post_info: &PostDispatchInfoOf<T::RuntimeCall>,
        corrected_fee: Self::Balance,
        _tip: Self::Balance,
        liquidity_info: Self::LiquidityInfo,
    ) -> Result<(), TransactionValidityError> {
        if let Some(LiquidityInfo {
            consensus_storage_fee,
            imbalance,
        }) = liquidity_info
        {
            // Calculate how much refund we should return
            let refund_amount = imbalance.peek().saturating_sub(corrected_fee);
            // Refund to the the account that paid the fees. If this fails, the account might have
            // dropped below the existential balance. In that case we don't refund anything.
            let refund_imbalance = C::deposit_into_existing(who, refund_amount)
                .unwrap_or_else(|_| C::PositiveImbalance::zero());
            // Merge the imbalance caused by paying the fees and refunding parts of it again.
            let adjusted_paid = imbalance
                .offset(refund_imbalance)
                .same()
                .map_err(|_| TransactionValidityError::Invalid(InvalidTransaction::Payment))?;

            // Split the paid consensus storage fee and the paid domain execution fee so that they can
            // be distributed separately.
            let (paid_consensus_storage_fee, paid_domain_fee) =
                adjusted_paid.split(consensus_storage_fee);

            BlockFees::<T>::note_consensus_storage_fee(paid_consensus_storage_fee.peek());
            BlockFees::<T>::note_domain_execution_fee(paid_domain_fee.peek());
        }
        Ok(())
    }
}

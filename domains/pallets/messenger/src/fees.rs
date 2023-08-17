use crate::pallet::RelayerRewards;
use crate::{BalanceOf, Config, Error, Pallet};
use frame_support::traits::fungible::{Inspect, Mutate};
use frame_support::traits::tokens::{Fortitude, Precision, Preservation};
use frame_support::PalletId;
use sp_messenger::messages::FeeModel;
use sp_runtime::traits::{AccountIdConversion, CheckedAdd};
use sp_runtime::{ArithmeticError, DispatchResult};

/// Messenger Id used to store deposits and fees.
const MESSENGER_PALLET_ID: PalletId = PalletId(*b"messengr");

impl<T: Config> Pallet<T> {
    /// Returns the account_id to holds fees and and acts as treasury for messenger.
    pub(crate) fn messenger_account_id() -> T::AccountId {
        MESSENGER_PALLET_ID.into_account_truncating()
    }

    /// Ensures the fees from the sender per FeeModel provided for a single request for a response.
    #[inline]
    pub(crate) fn ensure_fees_for_outbox_message(
        sender: &T::AccountId,
        fee_model: &FeeModel<BalanceOf<T>>,
    ) -> DispatchResult {
        let msgr_acc_id = Self::messenger_account_id();
        // reserve outbox fee by transferring it to the messenger account.
        // we will use the funds to pay the relayers once the response is received.
        let outbox_fee = fee_model.outbox_fee().ok_or(ArithmeticError::Overflow)?;
        T::Currency::transfer(sender, &msgr_acc_id, outbox_fee, Preservation::Preserve)?;

        // burn the fees that need to be paid on the dst_chain
        let inbox_fee = fee_model.inbox_fee().ok_or(ArithmeticError::Overflow)?;
        T::Currency::burn_from(sender, inbox_fee, Precision::Exact, Fortitude::Polite)?;
        Ok(())
    }

    /// Ensures the fee paid by the sender on the src_chain are minted here and paid to
    /// relayer set when the acknowledgments are received.
    #[inline]
    pub(crate) fn ensure_fees_for_inbox_message(
        fee_model: &FeeModel<BalanceOf<T>>,
    ) -> DispatchResult {
        let inbox_fee = fee_model.inbox_fee().ok_or(ArithmeticError::Overflow)?;
        let msngr_acc_id = Self::messenger_account_id();
        T::Currency::mint_into(&msngr_acc_id, inbox_fee)?;
        Ok(())
    }

    /// Increments the current block's relayer rewards.
    /// Operation is no-op if there is not enough balance to pay.
    pub(crate) fn reward_relayers(reward: BalanceOf<T>) -> DispatchResult {
        // ensure we have enough to pay but maintain minimum existential deposit
        let msngr_acc_id = Self::messenger_account_id();
        let balance =
            T::Currency::reducible_balance(&msngr_acc_id, Preservation::Protect, Fortitude::Polite);
        if balance < reward {
            return Ok(());
        }

        RelayerRewards::<T>::try_mutate(|current_reward| {
            *current_reward = current_reward
                .checked_add(&reward)
                .ok_or(Error::<T>::BalanceOverflow)?;
            Ok(())
        })
    }
}

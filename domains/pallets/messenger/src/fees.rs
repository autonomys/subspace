use crate::{BalanceOf, Config, Pallet, Relayers};
use frame_support::traits::ExistenceRequirement::AllowDeath;
use frame_support::traits::{Currency, ExistenceRequirement, WithdrawReasons};
use frame_support::PalletId;
use sp_messenger::messages::FeeModel;
use sp_runtime::traits::{AccountIdConversion, CheckedDiv, CheckedSub};
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
        T::Currency::transfer(sender, &msgr_acc_id, outbox_fee, AllowDeath)?;
        // burn the fees that need to be paid on the dst_domain
        let inbox_fee = fee_model.inbox_fee().ok_or(ArithmeticError::Overflow)?;
        T::Currency::withdraw(
            sender,
            inbox_fee,
            WithdrawReasons::TRANSACTION_PAYMENT,
            AllowDeath,
        )?;
        Ok(())
    }

    /// Ensures the fee paid by the sender on the src_domain are minted here and paid to
    /// relayer set when the acknowledgments are received.
    #[inline]
    pub(crate) fn ensure_fees_for_inbox_message(
        fee_model: &FeeModel<BalanceOf<T>>,
    ) -> DispatchResult {
        let inbox_fee = fee_model.inbox_fee().ok_or(ArithmeticError::Overflow)?;
        let msngr_acc_id = Self::messenger_account_id();
        T::Currency::deposit_creating(&msngr_acc_id, inbox_fee);
        Ok(())
    }

    /// Distribute the rewards to the relayers.
    /// Operation is no-op if there is not enough balance to pay.
    /// Operation is no-op if there are no relayers.
    pub(crate) fn distribute_reward_to_relayers(reward: BalanceOf<T>) -> DispatchResult {
        let relayers = Relayers::<T>::get();
        let relayer_count: BalanceOf<T> = (relayers.len() as u32).into();
        let reward_per_relayer = match reward.checked_div(&relayer_count) {
            // no relayers yet.
            None => return Ok(()),
            Some(reward) => reward,
        };

        // ensure we have enough to pay but maintain minimum existential deposit
        let msngr_acc_id = Self::messenger_account_id();
        if !T::Currency::free_balance(&msngr_acc_id)
            .checked_sub(&T::Currency::minimum_balance())
            .map(|usable| usable >= reward)
            .unwrap_or(false)
        {
            return Ok(());
        }

        // distribute reward to relayers
        for relayer in relayers.into_iter() {
            // ensure msngr account is still kept alive after transfer.
            T::Currency::transfer(
                &msngr_acc_id,
                &relayer,
                reward_per_relayer,
                ExistenceRequirement::KeepAlive,
            )?;
        }
        Ok(())
    }
}

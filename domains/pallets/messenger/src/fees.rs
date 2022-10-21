use crate::{BalanceOf, Config, Pallet, Relayers};
use codec::{Decode, Encode};
use frame_support::traits::ExistenceRequirement::AllowDeath;
use frame_support::traits::{Currency, ExistenceRequirement, WithdrawReasons};
use frame_support::PalletId;
use scale_info::TypeInfo;
use sp_runtime::traits::{AccountIdConversion, CheckedAdd, CheckedDiv, CheckedSub};
use sp_runtime::{ArithmeticError, DispatchResult};

/// Messenger Id used to store deposits and fees.
const MESSENGER_PALLET_ID: PalletId = PalletId(*b"messengr");

/// Execution Fee to execute a send or receive request.
#[derive(Default, Debug, Encode, Decode, Clone, Copy, Eq, PartialEq, TypeInfo)]
pub struct ExecutionFee<Balance> {
    /// Fee paid to the relayer pool for the execution.
    pub relayer_pool_fee: Balance,
    /// Fee paid to the network for computation.
    pub compute_fee: Balance,
}

/// Fee model to send a request and receive a response from another domain.
/// A user of the endpoint will pay
///     - outbox_fee on src_domain
///     - inbox_fee on dst_domain
/// The reward is distributed to
///     - src_domain relayer pool when the response is received
///     - dst_domain relayer pool when the response acknowledgement from src_domain.
#[derive(Default, Debug, Encode, Decode, Clone, Copy, Eq, PartialEq, TypeInfo)]
pub struct FeeModel<Balance> {
    /// Fee paid by the endpoint user for any outgoing message.
    pub outbox_fee: ExecutionFee<Balance>,
    /// Fee paid by the endpoint user any incoming message.
    pub inbox_fee: ExecutionFee<Balance>,
}

impl<T: Config> Pallet<T> {
    /// Returns the account_id to holds fees and and acts as treasury for messenger.
    pub(crate) fn messenger_account_id() -> T::AccountId {
        MESSENGER_PALLET_ID.into_account_truncating()
    }

    /// Ensures the fees from the sender per FeeModel provided for a single request for a response.
    pub(crate) fn ensure_fees_for_outbox_message(
        sender: &T::AccountId,
        fee_model: &FeeModel<BalanceOf<T>>,
    ) -> DispatchResult {
        let msgr_acc_id = Self::messenger_account_id();

        // reserve outbox fee by transferring it to the messenger account.
        // we will use the funds to pay the relayers once the response is received.
        let fee = fee_model
            .outbox_fee
            .relayer_pool_fee
            .checked_add(&fee_model.outbox_fee.compute_fee)
            .ok_or(ArithmeticError::Overflow)?;

        T::Currency::transfer(sender, &msgr_acc_id, fee, AllowDeath)?;

        // burn the fees that need to be paid on the dst_domain
        let fee = fee_model
            .inbox_fee
            .compute_fee
            .checked_add(&fee_model.inbox_fee.relayer_pool_fee)
            .ok_or(ArithmeticError::Overflow)?;
        T::Currency::withdraw(
            sender,
            fee,
            WithdrawReasons::TRANSACTION_PAYMENT,
            AllowDeath,
        )?;

        Ok(())
    }

    /// Ensures the fee paid by the sender on the src_domain are minted here and paid to
    /// relayer set when the acknowledgments are received.
    pub(crate) fn ensure_fees_for_inbox_message(
        fee_model: &FeeModel<BalanceOf<T>>,
    ) -> DispatchResult {
        let fee = fee_model
            .inbox_fee
            .compute_fee
            .checked_add(&fee_model.inbox_fee.relayer_pool_fee)
            .ok_or(ArithmeticError::Overflow)?;

        let msngr_acc_id = Self::messenger_account_id();
        T::Currency::deposit_creating(&msngr_acc_id, fee);
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
        let free_balance = match T::Currency::free_balance(&msngr_acc_id)
            .checked_sub(&T::Currency::minimum_balance())
        {
            // do not have enough to pay relayers
            None => return Ok(()),
            Some(bal) => bal,
        };

        if free_balance <= reward {
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

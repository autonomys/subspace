use crate::pallet::{
    InboxFee, InboxFeesOnHold, InboxResponseMessageWeightTags, InboxResponses, OutboxFee,
    OutboxFeesOnHold,
};
use crate::{BalanceOf, Config, Error, Pallet};
use frame_support::traits::fungible::{Balanced, Mutate};
use frame_support::traits::tokens::{Fortitude, Precision, Preservation};
use frame_support::weights::WeightToFee;
use sp_core::Get;
use sp_messenger::OnXDMRewards;
use sp_messenger::endpoint::{CollectedFee, Endpoint};
use sp_messenger::messages::{ChainId, ChannelId, MessageId, Nonce};
use sp_runtime::traits::{CheckedAdd, CheckedMul, CheckedSub, Zero};
use sp_runtime::{DispatchError, DispatchResult, Saturating};

impl<T: Config> Pallet<T> {
    /// Ensures the fees from the sender to complete the XDM request and response.
    #[inline]
    pub(crate) fn collect_fees_for_message_v1(
        sender: &T::AccountId,
        endpoint: &Endpoint,
    ) -> Result<CollectedFee<BalanceOf<T>>, DispatchError> {
        let handler = T::get_endpoint_handler(endpoint).ok_or(Error::<T>::NoMessageHandler)?;

        let fee_multiplier = BalanceOf::<T>::from(T::FeeMultiplier::get());

        // fees need to be paid for following
        // - Execution on dst_chain. This is burned here and minted on dst_chain
        let dst_chain_inbox_execution_fee =
            T::AdjustedWeightToFee::weight_to_fee(&handler.message_weight());

        // adjust the dst_chain fee with xdm multiplier
        let dst_chain_fee = dst_chain_inbox_execution_fee
            .checked_mul(&fee_multiplier)
            .ok_or(Error::<T>::BalanceOverflow)?;

        // - Execution of response on src_chain.
        // - This is collected and given to operators once response is received.
        let src_chain_outbox_response_execution_fee =
            T::AdjustedWeightToFee::weight_to_fee(&handler.message_response_weight());

        // adjust the src_chain fee with xdm multiplier
        let src_chain_fee = src_chain_outbox_response_execution_fee
            .checked_mul(&fee_multiplier)
            .ok_or(Error::<T>::BalanceOverflow)?;

        // burn the total fees
        let total_fees = dst_chain_fee
            .checked_add(&src_chain_fee)
            .ok_or(Error::<T>::BalanceOverflow)?;
        T::Currency::burn_from(
            sender,
            total_fees,
            Preservation::Preserve,
            Precision::Exact,
            Fortitude::Polite,
        )?;

        Ok(CollectedFee {
            src_chain_fee,
            dst_chain_fee,
        })
    }

    /// Rewards operators for executing an inbox message since src_chain signalled that responses are delivered.
    /// Remove messages responses from Inbox responses.
    /// All the messages with nonce <= latest_confirmed_nonce are deleted.
    pub(crate) fn reward_operators_for_inbox_execution(
        dst_chain_id: ChainId,
        channel_id: ChannelId,
        latest_confirmed_nonce: Option<Nonce>,
    ) -> DispatchResult {
        if latest_confirmed_nonce.is_none() {
            return Ok(());
        }

        let mut current_nonce = latest_confirmed_nonce;
        let mut inbox_fees = BalanceOf::<T>::zero();
        while let Some(nonce) = current_nonce {
            if InboxResponses::<T>::take((dst_chain_id, channel_id, nonce)).is_none() {
                // Make the loop efficient, by breaking as soon as there are no more responses.
                // If we didn't break here, we'd spend a lot of CPU hashing missing StorageMap
                // keys.
                break;
            }

            // Remove weight tags for inbox response messages.
            InboxResponseMessageWeightTags::<T>::remove((dst_chain_id, (channel_id, nonce)));

            // For every inbox response we take, distribute the reward to the operators.
            if let Some(inbox_fee) = InboxFee::<T>::take((dst_chain_id, (channel_id, nonce))) {
                inbox_fees = inbox_fees.saturating_add(inbox_fee);
            }

            current_nonce = nonce.checked_sub(Nonce::one())
        }

        if !inbox_fees.is_zero() {
            InboxFeesOnHold::<T>::mutate(|inbox_fees_on_hold| {
                *inbox_fees_on_hold = inbox_fees_on_hold
                    .checked_sub(&inbox_fees)
                    .ok_or(Error::<T>::BalanceUnderflow)?;

                // If the `imbalance` is dropped without consuming it will increase the total issuance by
                // the same amount as we rescinded here, thus we need to manually `mem::forget` it.
                let imbalance = T::Currency::rescind(inbox_fees);
                core::mem::forget(imbalance);

                Ok::<(), Error<T>>(())
            })?;

            Self::reward_operators(inbox_fees);
        }

        Ok(())
    }

    pub(crate) fn reward_operators_for_outbox_execution(
        dst_chain_id: ChainId,
        message_id: MessageId,
    ) -> DispatchResult {
        if let Some(fee) = OutboxFee::<T>::take((dst_chain_id, message_id)) {
            OutboxFeesOnHold::<T>::mutate(|outbox_fees_on_hold| {
                *outbox_fees_on_hold = outbox_fees_on_hold
                    .checked_sub(&fee)
                    .ok_or(Error::<T>::BalanceUnderflow)?;

                // If the `imbalance` is dropped without consuming it will increase the total issuance by
                // the same amount as we rescinded here, thus we need to manually `mem::forget` it.
                let imbalance = T::Currency::rescind(fee);
                core::mem::forget(imbalance);

                Ok::<(), Error<T>>(())
            })?;

            Self::reward_operators(fee);
        }
        Ok(())
    }

    /// Increments the current block's relayer rewards.
    fn reward_operators(reward: BalanceOf<T>) {
        T::OnXDMRewards::on_xdm_rewards(reward)
    }
}

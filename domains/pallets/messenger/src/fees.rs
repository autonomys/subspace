use crate::pallet::{InboxFee, InboxResponses, MessageWeightTags, OutboxFee};
use crate::{BalanceOf, Config, Error, Pallet};
use frame_support::traits::fungible::Mutate;
use frame_support::traits::tokens::{Fortitude, Precision, Preservation};
use frame_support::weights::WeightToFee;
use sp_messenger::endpoint::Endpoint;
use sp_messenger::messages::{ChainId, ChannelId, FeeModel, MessageId, Nonce};
use sp_messenger::OnXDMRewards;
use sp_runtime::traits::CheckedAdd;
use sp_runtime::{DispatchResult, Saturating};

impl<T: Config> Pallet<T> {
    /// Ensures the fees from the sender per FeeModel provided for a single request for a response.
    #[inline]
    pub(crate) fn collect_fees_for_message(
        sender: &T::AccountId,
        message_id: (ChainId, MessageId),
        fee_model: &FeeModel<BalanceOf<T>>,
        endpoint: &Endpoint,
    ) -> DispatchResult {
        let handler = T::get_endpoint_handler(endpoint).ok_or(Error::<T>::NoMessageHandler)?;

        // fees need to be paid for following
        // - Execution on dst_chain + Relay Fee. This is burned here and minted on dst_chain
        let dst_chain_inbox_execution_fee =
            T::WeightToFee::weight_to_fee(&handler.message_weight());
        let dst_chain_fee = dst_chain_inbox_execution_fee
            .checked_add(&fee_model.relay_fee)
            .ok_or(Error::<T>::BalanceOverflow)?;

        // - Execution of response on src_chain + relay fee.
        // - This is collected and given to operators once response is received.
        let src_chain_outbox_response_execution_fee =
            T::WeightToFee::weight_to_fee(&handler.message_response_weight());
        let src_chain_fee = src_chain_outbox_response_execution_fee
            .checked_add(&fee_model.relay_fee)
            .ok_or(Error::<T>::BalanceOverflow)?;
        OutboxFee::<T>::insert(message_id, src_chain_fee);

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

        Ok(())
    }

    /// Ensures the fee paid by the sender on the src_chain for execution on this chain are stored as operator rewards
    #[inline]
    pub(crate) fn store_fees_for_inbox_message(
        message_id: (ChainId, MessageId),
        fee_model: &FeeModel<BalanceOf<T>>,
        endpoint: &Endpoint,
    ) {
        let mut inbox_fee = fee_model.relay_fee;

        // If the endpoint handler does not exist the message won't be handled thus it is okay
        // to not add the execution fee in this case
        if let Some(handler) = T::get_endpoint_handler(endpoint) {
            let inbox_execution_fee = T::WeightToFee::weight_to_fee(&handler.message_weight());
            inbox_fee = inbox_fee.saturating_add(inbox_execution_fee);
        }

        InboxFee::<T>::insert(message_id, inbox_fee);
    }

    /// Rewards operators for executing an inbox message since src_chain signalled that responses are delivered.
    /// Removes messages responses from Inbox responses.
    /// All the messages with nonce <= latest_confirmed_nonce are deleted.
    pub(crate) fn reward_operators_for_inbox_execution(
        dst_chain_id: ChainId,
        channel_id: ChannelId,
        latest_confirmed_nonce: Option<Nonce>,
    ) -> DispatchResult {
        let mut current_nonce = latest_confirmed_nonce;

        while let Some(nonce) = current_nonce {
            // clear weight tags for inbox response messages
            MessageWeightTags::<T>::mutate(|maybe_messages| {
                let mut messages = maybe_messages.as_mut().cloned().unwrap_or_default();
                messages
                    .inbox_responses
                    .remove(&(dst_chain_id, (channel_id, nonce)));
                *maybe_messages = Some(messages)
            });

            // for every inbox response we take, distribute the reward to the operators.
            if InboxResponses::<T>::take((dst_chain_id, channel_id, nonce)).is_none() {
                return Ok(());
            }

            if let Some(inbox_fee) = InboxFee::<T>::take((dst_chain_id, (channel_id, nonce))) {
                Self::reward_operators(inbox_fee);
            }

            current_nonce = nonce.checked_sub(Nonce::one())
        }

        Ok(())
    }

    pub(crate) fn reward_operators_for_outbox_execution(
        dst_chain_id: ChainId,
        message_id: MessageId,
    ) {
        if let Some(fee) = OutboxFee::<T>::take((dst_chain_id, message_id)) {
            Self::reward_operators(fee);
        }
    }

    /// Increments the current block's relayer rewards.
    fn reward_operators(reward: BalanceOf<T>) {
        T::OnXDMRewards::on_xdm_rewards(reward)
    }
}

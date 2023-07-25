//! Staking epoch transition for domain

use crate::pallet::{
    DomainStakingSummary, LastEpochStakingDistribution, Nominators, OperatorIdOwner, Operators,
    PendingDeposits, PendingNominatorUnlocks, PendingOperatorDeregistrations,
    PendingOperatorSwitches, PendingOperatorUnlocks, PendingSlashes, PendingUnlocks,
    PendingWithdrawals,
};
use crate::staking::{Error as TransitionError, Nominator, Withdraw};
use crate::{
    BalanceOf, Config, ElectionVerificationParams, FreezeIdentifier, FungibleFreezeId, NominatorId,
};
use codec::{Decode, Encode};
use frame_support::dispatch::TypeInfo;
use frame_support::traits::fungible::{InspectFreeze, Mutate, MutateFreeze};
use frame_support::traits::tokens::{Fortitude, Precision};
use frame_support::PalletError;
use sp_core::Get;
use sp_domains::{DomainId, OperatorId};
use sp_runtime::traits::{CheckedAdd, CheckedSub, One, Zero};
use sp_runtime::Perbill;
use sp_std::collections::btree_map::BTreeMap;

#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum Error {
    FinalizeSwitchOperatorDomain(TransitionError),
    FinalizeOperatorDeregistration(TransitionError),
    UnlockOperator(TransitionError),
    FinalizeDomainPendingTransfers(TransitionError),
    UnlockNominator(TransitionError),
    OperatorRewardStaking(TransitionError),
    SlashOperator(TransitionError),
}

/// Finalizes the domain's current epoch and begins the next epoch.
/// Returns true of the epoch indeed was finished.
pub(crate) fn do_finalize_domain_current_epoch<T: Config>(
    domain_id: DomainId,
    domain_block_number: T::DomainNumber,
    current_consensus_block_number: T::BlockNumber,
) -> Result<bool, Error> {
    if domain_block_number % T::StakeEpochDuration::get() != Zero::zero() {
        return Ok(false);
    }

    // slash the operators
    do_finalize_slashed_operators::<T>(domain_id).map_err(Error::SlashOperator)?;

    // re stake operator's tax from the rewards
    operator_take_reward_tax_and_stake::<T>(domain_id)?;

    // finalize any operator switches
    do_finalize_switch_operator_domain::<T>(domain_id)?;

    // finalize operator de-registrations
    do_finalize_operator_deregistrations::<T>(domain_id, current_consensus_block_number)?;

    // finalize any withdrawals and then deposits
    do_finalize_domain_pending_transfers::<T>(domain_id, current_consensus_block_number)?;
    Ok(true)
}

/// Unlocks any operators who are de-registering or nominators who are withdrawing staked funds.
pub(crate) fn do_unlock_pending_withdrawals<T: Config>(
    consensus_block_number: T::BlockNumber,
) -> Result<(), Error> {
    if let Some(operator_ids) = PendingUnlocks::<T>::take(consensus_block_number) {
        PendingOperatorUnlocks::<T>::try_mutate(|unlocking_operator_ids| {
            for operator_id in operator_ids {
                if unlocking_operator_ids.contains(&operator_id) {
                    unlock_operator::<T>(operator_id)?;
                    unlocking_operator_ids.remove(&operator_id);
                } else {
                    unlock_nominator_withdrawals::<T>(operator_id, consensus_block_number)?;
                }
            }

            Ok(())
        })?;
    }
    Ok(())
}

/// Operator takes `NominationTax` of the current epoch rewards and stake them.
pub(crate) fn operator_take_reward_tax_and_stake<T: Config>(
    domain_id: DomainId,
) -> Result<(), Error> {
    DomainStakingSummary::<T>::try_mutate(domain_id, |maybe_domain_stake_summary| {
        let stake_summary = maybe_domain_stake_summary
            .as_mut()
            .ok_or(TransitionError::DomainNotInitialized)?;

        while let Some((operator_id, reward)) = stake_summary.current_epoch_rewards.pop_first() {
            Operators::<T>::try_mutate(operator_id, |maybe_operator| {
                let operator = match maybe_operator.as_mut() {
                    // it is possible that operator may have de registered by the time they got rewards
                    // if not available, skip the operator
                    None => return Ok(()),
                    Some(operator) => operator,
                };

                // calculate operator tax, mint the balance, and stake them
                let operator_tax = operator.nomination_tax.mul_floor(reward);
                if !operator_tax.is_zero() {
                    let nominator_id = OperatorIdOwner::<T>::get(operator_id)
                        .ok_or(TransitionError::MissingOperatorOwner)?;
                    T::Currency::mint_into(&nominator_id, operator_tax)
                        .map_err(|_| TransitionError::MintBalance)?;

                    // add an pending deposit for the operator tax
                    let updated_total_deposit =
                        match PendingDeposits::<T>::get(operator_id, nominator_id.clone()) {
                            None => operator_tax,
                            Some(existing_deposit) => existing_deposit
                                .checked_add(&operator_tax)
                                .ok_or(TransitionError::BalanceOverflow)?,
                        };

                    crate::staking::freeze_account_balance_to_operator::<T>(
                        &nominator_id,
                        operator_id,
                        operator_tax,
                    )?;
                    PendingDeposits::<T>::insert(operator_id, nominator_id, updated_total_deposit);
                }

                // add remaining rewards to nominators to be distributed during the epoch transition
                let rewards = reward
                    .checked_sub(&operator_tax)
                    .ok_or(TransitionError::BalanceUnderflow)?;

                operator.current_epoch_rewards = operator
                    .current_epoch_rewards
                    .checked_add(&rewards)
                    .ok_or(TransitionError::BalanceOverflow)?;

                Ok(())
            })?;
        }

        Ok(())
    })
    .map_err(Error::OperatorRewardStaking)
}

/// Add all the switched operators to new domain as next operators.
/// Once the new domain's epoch is complete, operators are included in the next epoch.
fn do_finalize_switch_operator_domain<T: Config>(domain_id: DomainId) -> Result<(), Error> {
    if let Some(operators) = PendingOperatorSwitches::<T>::take(domain_id) {
        operators.into_iter().try_for_each(|operator_id| {
            switch_operator::<T>(operator_id).map_err(Error::FinalizeSwitchOperatorDomain)
        })?;
    }

    Ok(())
}

fn switch_operator<T: Config>(operator_id: OperatorId) -> Result<(), TransitionError> {
    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator
            .as_mut()
            .ok_or(TransitionError::UnknownOperator)?;

        // operator is frozen, just no-op
        if operator.is_frozen {
            return Ok(());
        }

        operator.current_domain_id = operator.next_domain_id;
        DomainStakingSummary::<T>::try_mutate(operator.current_domain_id, |maybe_stake_summary| {
            let stake_summary = maybe_stake_summary
                .as_mut()
                .ok_or(TransitionError::DomainNotInitialized)?;

            stake_summary.next_operators.insert(operator_id);

            Ok(())
        })
    })
}

fn do_finalize_operator_deregistrations<T: Config>(
    domain_id: DomainId,
    consensus_block_number: T::BlockNumber,
) -> Result<(), Error> {
    let stake_withdrawal_locking_period = T::StakeWithdrawalLockingPeriod::get();
    let unlock_block_number = consensus_block_number
        .checked_add(&stake_withdrawal_locking_period)
        .ok_or(Error::FinalizeOperatorDeregistration(
            TransitionError::BlockNumberOverflow,
        ))?;

    if let Some(operator_ids) = PendingOperatorDeregistrations::<T>::take(domain_id) {
        PendingUnlocks::<T>::mutate(unlock_block_number, |maybe_stored_operator_ids| {
            let mut stored_operator_ids = maybe_stored_operator_ids.take().unwrap_or_default();
            operator_ids.into_iter().for_each(|operator_id| {
                PendingOperatorUnlocks::<T>::append(operator_id);
                stored_operator_ids.insert(operator_id);
            });
            *maybe_stored_operator_ids = Some(stored_operator_ids)
        })
    }

    Ok(())
}

fn unlock_operator<T: Config>(operator_id: OperatorId) -> Result<(), Error> {
    Operators::<T>::try_mutate_exists(operator_id, |maybe_operator| {
        // take the operator so this operator info is removed once we unlock the operator.
        let operator = maybe_operator
            .take()
            .ok_or(TransitionError::UnknownOperator)?;

        let mut total_shares = operator.total_shares;
        let mut total_stake = operator
            .current_total_stake
            .checked_add(&operator.current_epoch_rewards)
            .ok_or(TransitionError::BalanceOverflow)?;

        let freeze_identifier = T::FreezeIdentifier::staking_freeze_id(operator_id);

        Nominators::<T>::drain_prefix(operator_id).try_for_each(|(nominator_id, nominator)| {
            let nominator_share = Perbill::from_rational(nominator.shares, total_shares);
            let nominator_staked_amount = nominator_share.mul_floor(total_stake);

            let locked_amount = T::Currency::balance_frozen(&freeze_identifier, &nominator_id);
            let amount_to_mint = nominator_staked_amount
                .checked_sub(&locked_amount)
                .unwrap_or(Zero::zero());

            // remove the lock and mint any gains
            T::Currency::thaw(&freeze_identifier, &nominator_id)
                .map_err(|_| TransitionError::RemoveLock)?;

            mint_funds::<T>(&nominator_id, amount_to_mint)?;

            // update pool's remaining shares and stake
            total_shares = total_shares
                .checked_sub(&nominator.shares)
                .ok_or(TransitionError::ShareUnderflow)?;
            total_stake = total_stake
                .checked_sub(&nominator_staked_amount)
                .ok_or(TransitionError::BalanceUnderflow)?;

            // remove any pending deposits for this nominator and then remove the lock
            PendingDeposits::<T>::remove(operator_id, nominator_id);

            Ok(())
        })?;

        // TODO: transfer any remaining amount to treasury

        // remove all of the pending deposits since we initiated withdrawal for all nominators.
        let _ = PendingWithdrawals::<T>::clear_prefix(operator_id, u32::MAX, None);

        // remove lock on any remaining deposits, all these are new nominators recorded after start
        // of new epoch and before operator de-registered
        for (nominator_id, _) in PendingDeposits::<T>::drain_prefix(operator_id) {
            T::Currency::thaw(&freeze_identifier, &nominator_id)
                .map_err(|_| TransitionError::RemoveLock)?;
        }

        // remove OperatorOwner Details
        OperatorIdOwner::<T>::remove(operator_id);

        Ok(())
    })
    .map_err(Error::UnlockOperator)
}

fn unlock_nominator_withdrawals<T: Config>(
    operator_id: OperatorId,
    current_consensus_block: T::BlockNumber,
) -> Result<(), Error> {
    let freeze_identifier = T::FreezeIdentifier::staking_freeze_id(operator_id);
    match PendingNominatorUnlocks::<T>::take(operator_id, current_consensus_block) {
        None => Ok(()),
        Some(withdrawals) => withdrawals.into_iter().try_for_each(|withdrawal| {
            let frozen_balance =
                T::Currency::balance_frozen(&freeze_identifier, &withdrawal.nominator_id);

            let remaining_staked_balance = frozen_balance
                .checked_sub(&withdrawal.balance)
                .ok_or(TransitionError::BalanceUnderflow)?;

            T::Currency::set_freeze(
                &freeze_identifier,
                &withdrawal.nominator_id,
                remaining_staked_balance,
            )
            .map_err(|_| TransitionError::UpdateLock)?;

            Ok(())
        }),
    }
    .map_err(Error::UnlockNominator)
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct PendingNominatorUnlock<NominatorId, Balance> {
    pub nominator_id: NominatorId,
    pub balance: Balance,
}

fn do_finalize_domain_pending_transfers<T: Config>(
    domain_id: DomainId,
    current_consensus_block: T::BlockNumber,
) -> Result<(), Error> {
    DomainStakingSummary::<T>::try_mutate(domain_id, |maybe_stake_summary| {
        let stake_summary = maybe_stake_summary
            .as_mut()
            .ok_or(TransitionError::DomainNotInitialized)?;

        let next_epoch = stake_summary
            .current_epoch_index
            .checked_add(One::one())
            .ok_or(TransitionError::EpochOverflow)?;

        let mut total_domain_stake = BalanceOf::<T>::zero();
        let mut current_operators = BTreeMap::new();
        for next_operator_id in &stake_summary.next_operators {
            let operator_stake = finalize_operator_pending_transfers::<T>(
                *next_operator_id,
                current_consensus_block,
            )?;

            total_domain_stake = total_domain_stake
                .checked_add(&operator_stake)
                .ok_or(TransitionError::BalanceOverflow)?;
            current_operators.insert(*next_operator_id, operator_stake);
        }

        let election_verification_params = ElectionVerificationParams {
            operators: stake_summary.current_operators.clone(),
            total_domain_stake: stake_summary.current_total_stake,
        };

        LastEpochStakingDistribution::<T>::insert(domain_id, election_verification_params);

        stake_summary.current_epoch_index = next_epoch;
        stake_summary.current_total_stake = total_domain_stake;
        stake_summary.current_operators = current_operators;

        Ok(())
    })
    .map_err(Error::FinalizeDomainPendingTransfers)
}

fn finalize_operator_pending_transfers<T: Config>(
    operator_id: OperatorId,
    current_consensus_block: T::BlockNumber,
) -> Result<BalanceOf<T>, TransitionError> {
    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator
            .as_mut()
            .ok_or(TransitionError::UnknownOperator)?;

        if operator.is_frozen {
            return Err(TransitionError::OperatorFrozen);
        }

        let mut total_stake = operator
            .current_total_stake
            .checked_add(&operator.current_epoch_rewards)
            .ok_or(TransitionError::BalanceOverflow)?;

        let mut total_shares = operator.total_shares;
        finalize_pending_withdrawals::<T>(
            operator_id,
            &mut total_stake,
            &mut total_shares,
            current_consensus_block,
        )?;

        finalize_pending_deposits::<T>(operator_id, &mut total_stake, &mut total_shares)?;

        // update operator state
        operator.total_shares = total_shares;
        operator.current_total_stake = total_stake;
        operator.current_epoch_rewards = Zero::zero();

        Ok(total_stake)
    })
}

fn finalize_pending_withdrawals<T: Config>(
    operator_id: OperatorId,
    total_stake: &mut BalanceOf<T>,
    total_shares: &mut T::Share,
    current_consensus_block_number: T::BlockNumber,
) -> Result<(), TransitionError> {
    let freeze_identifier = T::FreezeIdentifier::staking_freeze_id(operator_id);
    let unlock_block_number = current_consensus_block_number
        .checked_add(&T::StakeWithdrawalLockingPeriod::get())
        .ok_or(TransitionError::BlockNumberOverflow)?;
    PendingWithdrawals::<T>::drain_prefix(operator_id).try_for_each(|(nominator_id, withdraw)| {
        finalize_nominator_withdrawal::<T>(
            operator_id,
            &freeze_identifier,
            nominator_id,
            withdraw,
            total_stake,
            total_shares,
            unlock_block_number,
        )
    })
}

fn mint_funds<T: Config>(
    nominator_id: &NominatorId<T>,
    amount_to_mint: BalanceOf<T>,
) -> Result<(), TransitionError> {
    if !amount_to_mint.is_zero() {
        T::Currency::mint_into(nominator_id, amount_to_mint)
            .map_err(|_| TransitionError::MintBalance)?;
    }

    Ok(())
}

fn finalize_nominator_withdrawal<T: Config>(
    operator_id: OperatorId,
    freeze_identifier: &FungibleFreezeId<T>,
    nominator_id: NominatorId<T>,
    withdraw: Withdraw<BalanceOf<T>>,
    total_stake: &mut BalanceOf<T>,
    total_shares: &mut T::Share,
    unlock_at: T::BlockNumber,
) -> Result<(), TransitionError> {
    let (withdrew_stake, withdrew_shares) = match withdraw {
        Withdraw::All => {
            let nominator = Nominators::<T>::take(operator_id, nominator_id.clone())
                .ok_or(TransitionError::UnknownNominator)?;

            let nominator_share = Perbill::from_rational(nominator.shares, *total_shares);
            let nominator_staked_amount = nominator_share.mul_floor(*total_stake);

            let locked_amount = T::Currency::balance_frozen(freeze_identifier, &nominator_id);
            let amount_to_mint = nominator_staked_amount
                .checked_sub(&locked_amount)
                .unwrap_or(Zero::zero());

            // mint any gains and then update the lock
            mint_funds::<T>(&nominator_id, amount_to_mint)?;
            T::Currency::set_freeze(freeze_identifier, &nominator_id, nominator_staked_amount)
                .map_err(|_| TransitionError::UpdateLock)?;
            (nominator_staked_amount, nominator.shares)
        }
        Withdraw::Some(withdraw_amount) => {
            Nominators::<T>::try_mutate(operator_id, nominator_id.clone(), |maybe_nominator| {
                let nominator = maybe_nominator
                    .as_mut()
                    .ok_or(TransitionError::UnknownNominator)?;

                // calculate nominator total staked value
                let nominator_share = Perbill::from_rational(nominator.shares, *total_shares);
                let nominator_staked_amount = nominator_share.mul_floor(*total_stake);

                // calculate the shares to be deducted from the withdraw amount and adjust
                let share_per_ssc =
                    Perbill::from_rational(*total_shares, T::Share::from(*total_stake));
                let shares_to_withdraw = T::Share::from(share_per_ssc.mul_ceil(withdraw_amount));
                nominator.shares = nominator
                    .shares
                    .checked_sub(&shares_to_withdraw)
                    .ok_or(TransitionError::ShareUnderflow)?;

                // adjust the locked stake amount with any gains minted
                let old_locked_amount =
                    T::Currency::balance_frozen(freeze_identifier, &nominator_id);
                let amount_to_mint = nominator_staked_amount
                    .checked_sub(&old_locked_amount)
                    .unwrap_or(Zero::zero());
                mint_funds::<T>(&nominator_id, amount_to_mint)?;
                T::Currency::set_freeze(freeze_identifier, &nominator_id, nominator_staked_amount)
                    .map_err(|_| TransitionError::UpdateLock)?;

                Ok((withdraw_amount, shares_to_withdraw))
            })?
        }
    };

    PendingNominatorUnlocks::<T>::append(
        operator_id,
        unlock_at,
        PendingNominatorUnlock {
            nominator_id,
            balance: withdrew_stake,
        },
    );

    let mut operator_ids = PendingUnlocks::<T>::get(unlock_at).unwrap_or_default();
    operator_ids.insert(operator_id);
    PendingUnlocks::<T>::insert(unlock_at, operator_ids);

    // update pool's remaining shares and stake
    *total_shares = total_shares
        .checked_sub(&withdrew_shares)
        .ok_or(TransitionError::ShareUnderflow)?;
    *total_stake = total_stake
        .checked_sub(&withdrew_stake)
        .ok_or(TransitionError::BalanceUnderflow)?;

    Ok(())
}

fn finalize_pending_deposits<T: Config>(
    operator_id: OperatorId,
    total_stake: &mut BalanceOf<T>,
    total_shares: &mut T::Share,
) -> Result<(), TransitionError> {
    PendingDeposits::<T>::drain_prefix(operator_id).try_for_each(|(nominator_id, deposit)| {
        finalize_nominator_deposit::<T>(
            operator_id,
            nominator_id,
            deposit,
            total_stake,
            total_shares,
        )
    })
}

fn finalize_nominator_deposit<T: Config>(
    operator_id: OperatorId,
    nominator_id: NominatorId<T>,
    deposit: BalanceOf<T>,
    total_stake: &mut BalanceOf<T>,
    total_shares: &mut T::Share,
) -> Result<(), TransitionError> {
    // calculate the shares to be added to nominator
    let share_per_ssc = Perbill::from_rational(*total_shares, T::Share::from(*total_stake));
    let shares_to_deposit = T::Share::from(share_per_ssc.mul_floor(deposit));
    let mut nominator =
        Nominators::<T>::get(operator_id, nominator_id.clone()).unwrap_or(Nominator {
            shares: Zero::zero(),
        });

    nominator.shares = nominator
        .shares
        .checked_add(&shares_to_deposit)
        .ok_or(TransitionError::ShareOverflow)?;

    Nominators::<T>::insert(operator_id, nominator_id, nominator);

    // update operator's remaining shares and stake
    *total_shares = total_shares
        .checked_add(&shares_to_deposit)
        .ok_or(TransitionError::ShareOverflow)?;
    *total_stake = total_stake
        .checked_add(&deposit)
        .ok_or(TransitionError::BalanceOverflow)?;

    Ok(())
}

pub(crate) fn do_finalize_slashed_operators<T: Config>(
    domain_id: DomainId,
) -> Result<(), TransitionError> {
    let mut total_slashed_amount = BalanceOf::<T>::zero();
    for operator_id in PendingSlashes::<T>::take(domain_id).unwrap_or_default() {
        let slashed_amount = slash_operator::<T>(operator_id)?;
        total_slashed_amount = total_slashed_amount
            .checked_add(&slashed_amount)
            .ok_or(TransitionError::BalanceOverflow)?;
    }

    // TODO: mint the total slashed amount to treasury

    Ok(())
}

fn thaw_and_burn_frozen_balance<T: Config>(
    id: &FungibleFreezeId<T>,
    from: &T::AccountId,
) -> Result<(), TransitionError> {
    // thaw the frozen amount and burn
    let locked_amount = T::Currency::balance_frozen(id, from);
    T::Currency::thaw(id, from).map_err(|_| TransitionError::RemoveLock)?;
    T::Currency::burn_from(from, locked_amount, Precision::Exact, Fortitude::Force)
        .map_err(|_| TransitionError::BalanceBurn)?;

    Ok(())
}

fn slash_operator<T: Config>(operator_id: OperatorId) -> Result<BalanceOf<T>, TransitionError> {
    Operators::<T>::try_mutate_exists(operator_id, |maybe_operator| {
        // take the operator so this operator info is removed once we slash the operator.
        let operator = maybe_operator
            .take()
            .ok_or(TransitionError::UnknownOperator)?;

        // slashed_amount = current_total_stake + rewards + new deposits
        let mut slashed_amount = operator
            .current_total_stake
            .checked_add(&operator.current_epoch_rewards)
            .ok_or(TransitionError::BalanceOverflow)?;

        let freeze_identifier = T::FreezeIdentifier::staking_freeze_id(operator_id);

        Nominators::<T>::drain_prefix(operator_id).try_for_each(|(nominator_id, _)| {
            thaw_and_burn_frozen_balance::<T>(&freeze_identifier, &nominator_id)?;

            // if there was a pending deposit from this nominator,
            // then account that deposit in the slashed amount since this new deposit
            // was burned above
            if let Some(deposit) = PendingDeposits::<T>::take(operator_id, nominator_id) {
                slashed_amount = slashed_amount
                    .checked_add(&deposit)
                    .ok_or(TransitionError::BalanceOverflow)?;
            }

            Ok(())
        })?;

        // remove all of the pending deposits since we initiated withdrawal for all nominators.
        let _ = PendingWithdrawals::<T>::clear_prefix(operator_id, u32::MAX, None);

        // slash any new nominators as well
        // all these are new nominators recorded after start
        // of new epoch and before operator was slashed
        for (nominator_id, deposit) in PendingDeposits::<T>::drain_prefix(operator_id) {
            thaw_and_burn_frozen_balance::<T>(&freeze_identifier, &nominator_id)?;
            slashed_amount = slashed_amount
                .checked_add(&deposit)
                .ok_or(TransitionError::BalanceOverflow)?;
        }

        // remove OperatorOwner Details
        OperatorIdOwner::<T>::remove(operator_id);

        Ok(slashed_amount)
    })
}

#[cfg(test)]
mod tests {
    use crate::pallet::{
        DomainStakingSummary, LastEpochStakingDistribution, Nominators, OperatorIdOwner, Operators,
        PendingDeposits, PendingOperatorDeregistrations, PendingOperatorSwitches,
        PendingOperatorUnlocks, PendingUnlocks, PendingWithdrawals,
    };
    use crate::staking::{
        do_deregister_operator, do_nominate_operator, Nominator, Operator, StakingSummary,
    };
    use crate::staking_epoch::{
        do_finalize_domain_pending_transfers, do_finalize_operator_deregistrations,
        do_finalize_switch_operator_domain, do_unlock_pending_withdrawals,
        operator_take_reward_tax_and_stake,
    };
    use crate::tests::{new_test_ext, Test};
    use crate::{BalanceOf, Config, FreezeIdentifier as FreezeIdentifierT, NominatorId};
    use frame_support::assert_ok;
    use frame_support::traits::fungible::{InspectFreeze, MutateFreeze};
    use frame_support::traits::Currency;
    use sp_core::{Pair, U256};
    use sp_domains::{DomainId, OperatorId, OperatorPair};
    use sp_runtime::traits::Zero;
    use sp_runtime::Percent;
    use std::collections::{BTreeMap, BTreeSet};
    use subspace_runtime_primitives::SSC;

    type Balances = pallet_balances::Pallet<Test>;
    type ShareOf<T> = <T as Config>::Share;

    struct RequiredStateParams {
        domain_id: DomainId,
        total_domain_stake: BalanceOf<Test>,
        current_operators: Vec<(OperatorId, BalanceOf<Test>)>,
        next_operators: Vec<OperatorId>,
        operator_id: OperatorId,
        operator_account: <Test as frame_system::Config>::AccountId,
        operator: Operator<BalanceOf<Test>, ShareOf<Test>>,
        operator_rewards: Vec<(OperatorId, BalanceOf<Test>)>,
    }

    fn create_operator_state(params: RequiredStateParams) {
        let RequiredStateParams {
            domain_id,
            total_domain_stake,
            current_operators,
            next_operators,
            operator_id,
            operator_account,
            operator,
            operator_rewards,
        } = params;

        DomainStakingSummary::<Test>::insert(
            domain_id,
            StakingSummary {
                current_epoch_index: 0,
                current_total_stake: total_domain_stake,
                current_operators: BTreeMap::from_iter(current_operators),
                next_operators: BTreeSet::from_iter(next_operators),
                current_epoch_rewards: BTreeMap::from_iter(operator_rewards),
            },
        );

        OperatorIdOwner::<Test>::insert(operator_id, operator_account);
        Operators::<Test>::insert(operator_id, operator);
    }

    #[test]
    fn finalize_operator_domain_switch() {
        let old_domain_id = DomainId::new(0);
        let new_domain_id = DomainId::new(1);
        let operator_account = 1;
        let operator_id = 1;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            create_operator_state(RequiredStateParams {
                domain_id: new_domain_id,
                total_domain_stake: 0,
                current_operators: vec![],
                next_operators: vec![],
                operator_id,
                operator_account,
                operator: Operator {
                    signing_key: pair.public(),
                    current_domain_id: old_domain_id,
                    next_domain_id: new_domain_id,
                    minimum_nominator_stake: 100 * SSC,
                    nomination_tax: Default::default(),
                    current_total_stake: Zero::zero(),
                    current_epoch_rewards: Zero::zero(),
                    total_shares: Zero::zero(),
                    is_frozen: false,
                },
                operator_rewards: vec![],
            });

            PendingOperatorSwitches::<Test>::append(old_domain_id, operator_id);
            assert!(do_finalize_switch_operator_domain::<Test>(old_domain_id).is_ok());

            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(operator.current_domain_id, new_domain_id);
            assert_eq!(operator.next_domain_id, new_domain_id);
            assert_eq!(PendingOperatorSwitches::<Test>::get(old_domain_id), None);

            let domain_stake_summary = DomainStakingSummary::<Test>::get(new_domain_id).unwrap();
            assert!(domain_stake_summary.next_operators.contains(&operator_id));
        });
    }

    fn unlock_operator(
        nominators: Vec<(NominatorId<Test>, BalanceOf<Test>)>,
        pending_deposits: Vec<(NominatorId<Test>, BalanceOf<Test>)>,
        rewards: BalanceOf<Test>,
    ) {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_id = 1;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());
        let minimum_free_balance = 10 * SSC;
        let nominators = BTreeMap::from_iter(nominators);
        let pending_deposits = BTreeMap::from_iter(pending_deposits);
        let mut total_deposits = nominators.clone();
        for pending_deposit in &pending_deposits {
            let staked_deposit = nominators
                .get(pending_deposit.0)
                .cloned()
                .unwrap_or_default();
            let total_balance = staked_deposit + *pending_deposit.1;
            total_deposits.insert(*pending_deposit.0, total_balance);
        }

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            for total_deposit in &total_deposits {
                Balances::make_free_balance_be(
                    total_deposit.0,
                    total_deposit.1 + minimum_free_balance,
                );
            }
            let mut total_stake = Zero::zero();
            let mut total_shares = Zero::zero();
            let freeze_id = crate::tests::FreezeIdentifier::staking_freeze_id(operator_id);
            for nominator in &nominators {
                total_stake += nominator.1;
                total_shares += nominator.1;

                assert_ok!(Balances::set_freeze(&freeze_id, nominator.0, *nominator.1));
                assert_eq!(
                    Balances::balance_frozen(&freeze_id, nominator.0),
                    *nominator.1
                );
                Nominators::<Test>::insert(
                    operator_id,
                    nominator.0,
                    Nominator {
                        shares: *nominator.1,
                    },
                )
            }
            create_operator_state(RequiredStateParams {
                domain_id,
                total_domain_stake: total_stake,
                current_operators: vec![],
                next_operators: vec![],
                operator_id,
                operator_account,
                operator: Operator {
                    signing_key: pair.public(),
                    current_domain_id: domain_id,
                    next_domain_id: domain_id,
                    minimum_nominator_stake: 10 * SSC,
                    nomination_tax: Default::default(),
                    current_total_stake: total_stake,
                    current_epoch_rewards: Zero::zero(),
                    total_shares,
                    is_frozen: false,
                },
                operator_rewards: vec![(operator_account, rewards)],
            });

            // add pending deposits
            for pending_deposit in &pending_deposits {
                do_nominate_operator::<Test>(operator_id, *pending_deposit.0, *pending_deposit.1)
                    .unwrap();
            }

            // de-register operator
            do_deregister_operator::<Test>(operator_account, operator_id).unwrap();

            // finalize and add to pending operator unlocks
            let consensus_block_number = 100;
            do_finalize_operator_deregistrations::<Test>(domain_id, consensus_block_number)
                .unwrap();

            // unlock operator
            let unlock_at = 100 + crate::tests::StakeWithdrawalLockingPeriod::get();
            assert!(do_unlock_pending_withdrawals::<Test>(unlock_at).is_ok());

            for nominator in &total_deposits {
                let mut required_minimum_free_balance = minimum_free_balance + nominator.1;
                if rewards.is_zero() {
                    // subtracted 1 SSC to account for any rounding errors if there are not rewards
                    required_minimum_free_balance -= SSC;
                }
                assert_eq!(Nominators::<Test>::get(operator_id, nominator.0), None);
                assert!(Balances::usable_balance(nominator.0) >= required_minimum_free_balance);
                assert_eq!(
                    Balances::balance_frozen(&freeze_id, nominator.0),
                    Zero::zero()
                );
                assert_eq!(
                    PendingDeposits::<Test>::get(operator_id, *nominator.0),
                    None
                );
                assert_eq!(
                    PendingWithdrawals::<Test>::get(operator_id, *nominator.0),
                    None
                );
            }

            assert_eq!(Operators::<Test>::get(operator_id), None);
            assert_eq!(OperatorIdOwner::<Test>::get(operator_id), None);
            assert!(PendingOperatorUnlocks::<Test>::get().is_empty())
        });
    }

    #[test]
    fn unlock_operator_with_no_rewards() {
        unlock_operator(
            vec![(1, 150 * SSC), (2, 50 * SSC), (3, 10 * SSC)],
            vec![(2, 10 * SSC), (4, 10 * SSC)],
            0,
        );
    }

    #[test]
    fn unlock_operator_with_rewards() {
        unlock_operator(
            vec![(1, 150 * SSC), (2, 50 * SSC), (3, 10 * SSC)],
            vec![(2, 10 * SSC), (4, 10 * SSC)],
            20 * SSC,
        );
    }

    #[test]
    fn finalize_operator_deregistration() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_id = 1;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            create_operator_state(RequiredStateParams {
                domain_id,
                total_domain_stake: 0,
                current_operators: vec![],
                next_operators: vec![],
                operator_id,
                operator_account,
                operator: Operator {
                    signing_key: pair.public(),
                    current_domain_id: domain_id,
                    next_domain_id: domain_id,
                    minimum_nominator_stake: 100 * SSC,
                    nomination_tax: Default::default(),
                    current_total_stake: Zero::zero(),
                    current_epoch_rewards: Zero::zero(),
                    total_shares: Zero::zero(),
                    is_frozen: true,
                },
                operator_rewards: vec![],
            });

            PendingOperatorDeregistrations::<Test>::append(domain_id, operator_id);
            let current_consensus_block_number = 100;
            assert!(do_finalize_operator_deregistrations::<Test>(
                domain_id,
                current_consensus_block_number,
            )
            .is_ok());

            let expected_unlock = 100 + crate::tests::StakeWithdrawalLockingPeriod::get();
            assert_eq!(
                PendingOperatorUnlocks::<Test>::get(),
                BTreeSet::from_iter(vec![operator_id])
            );
            assert_eq!(
                PendingUnlocks::<Test>::get(expected_unlock),
                Some(BTreeSet::from_iter(vec![operator_id]))
            )
        });
    }

    struct FinalizeDomainParams {
        total_stake: BalanceOf<Test>,
        rewards: BalanceOf<Test>,
        nominators: Vec<(NominatorId<Test>, <Test as Config>::Share)>,
        deposits: Vec<(NominatorId<Test>, BalanceOf<Test>)>,
    }

    fn finalize_domain_epoch(params: FinalizeDomainParams) {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_id = 1;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let FinalizeDomainParams {
            total_stake,
            rewards,
            nominators,
            deposits,
        } = params;

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let mut total_shares = Zero::zero();
            let nominators = BTreeMap::from_iter(nominators);
            let operator_stake = nominators.get(&operator_id).cloned().unwrap();
            for nominator in nominators {
                total_shares += nominator.1;
                Nominators::<Test>::insert(
                    operator_id,
                    nominator.0,
                    Nominator {
                        shares: nominator.1,
                    },
                );
            }
            create_operator_state(RequiredStateParams {
                domain_id,
                total_domain_stake: total_stake,
                current_operators: vec![(operator_id, operator_stake)],
                next_operators: vec![operator_id],
                operator_id,
                operator_account,
                operator: Operator {
                    signing_key: pair.public(),
                    current_domain_id: domain_id,
                    next_domain_id: domain_id,
                    minimum_nominator_stake: 10 * SSC,
                    nomination_tax: Default::default(),
                    current_total_stake: total_stake,
                    current_epoch_rewards: rewards,
                    total_shares,
                    is_frozen: false,
                },
                operator_rewards: vec![],
            });

            let mut total_deposit = BalanceOf::<Test>::zero();
            for deposit in &deposits {
                PendingDeposits::<Test>::insert(operator_id, deposit.0, deposit.1);
                total_deposit += deposit.1;
            }

            let current_block = 100;
            do_finalize_domain_pending_transfers::<Test>(domain_id, current_block).unwrap();
            for deposit in deposits {
                assert_eq!(PendingDeposits::<Test>::get(operator_id, deposit.0), None);
                Nominators::<Test>::contains_key(operator_id, deposit.0);
            }

            let total_updated_stake = total_stake + total_deposit + rewards;
            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(operator.current_total_stake, total_updated_stake);
            assert_eq!(operator.current_epoch_rewards, Zero::zero());

            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert_eq!(
                domain_stake_summary.current_total_stake,
                total_updated_stake
            );
            assert_eq!(domain_stake_summary.current_epoch_index, 1);

            // should also store the previous epoch details in-block
            let election_params = LastEpochStakingDistribution::<Test>::get(domain_id).unwrap();
            assert_eq!(
                election_params.operators,
                BTreeMap::from_iter(vec![(operator_id, operator_stake)])
            );
            assert_eq!(election_params.total_domain_stake, total_stake);
        });
    }

    #[test]
    fn finalize_domain_epoch_no_rewards() {
        finalize_domain_epoch(FinalizeDomainParams {
            total_stake: 210 * SSC,
            rewards: 0,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            deposits: vec![(1, 50 * SSC), (3, 10 * SSC)],
        })
    }

    #[test]
    fn finalize_domain_epoch_with_rewards() {
        finalize_domain_epoch(FinalizeDomainParams {
            total_stake: 210 * SSC,
            rewards: 20 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            deposits: vec![(1, 50 * SSC), (3, 10 * SSC)],
        })
    }

    #[test]
    fn operator_tax_and_staking() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_id = 1;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());
        let operator_rewards = 10 * SSC;
        let nominators = vec![(operator_account, 100 * SSC)];
        let total_stake = 100 * SSC;

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let mut total_shares = Zero::zero();
            let nominators = BTreeMap::from_iter(nominators);
            let operator_stake = nominators.get(&operator_id).cloned().unwrap();
            for nominator in nominators {
                total_shares += nominator.1;
                Balances::make_free_balance_be(
                    &nominator.0,
                    nominator.1 + crate::tests::ExistentialDeposit::get(),
                );

                let freeze_id = crate::tests::FreezeIdentifier::staking_freeze_id(operator_id);
                assert_ok!(Balances::set_freeze(&freeze_id, &nominator.0, nominator.1));

                Nominators::<Test>::insert(
                    operator_id,
                    nominator.0,
                    Nominator {
                        shares: nominator.1,
                    },
                );
            }

            // 10% tax
            let nomination_tax = Percent::from_parts(10);
            let expected_operator_tax = nomination_tax.mul_ceil(operator_rewards);

            create_operator_state(RequiredStateParams {
                domain_id,
                total_domain_stake: total_stake,
                current_operators: vec![(operator_id, operator_stake)],
                next_operators: vec![operator_id],
                operator_id,
                operator_account,
                operator: Operator {
                    signing_key: pair.public(),
                    current_domain_id: domain_id,
                    next_domain_id: domain_id,
                    minimum_nominator_stake: 10 * SSC,
                    nomination_tax,
                    current_total_stake: total_stake,
                    current_epoch_rewards: Zero::zero(),
                    total_shares,
                    is_frozen: false,
                },
                operator_rewards: vec![(operator_account, operator_rewards)],
            });

            operator_take_reward_tax_and_stake::<Test>(domain_id).unwrap();
            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(
                operator.current_epoch_rewards,
                (10 * SSC - expected_operator_tax)
            );

            let deposit = PendingDeposits::<Test>::get(operator_id, operator_account).unwrap();
            assert_eq!(deposit, expected_operator_tax);

            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert!(domain_stake_summary.current_epoch_rewards.is_empty())
        });
    }
}

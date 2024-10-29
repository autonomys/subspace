//! Staking epoch transition for domain
use crate::bundle_storage_fund::deposit_reserve_for_storage_fund;
use crate::pallet::{
    AccumulatedTreasuryFunds, Deposits, DomainStakingSummary, LastEpochStakingDistribution,
    NominatorCount, OperatorIdOwner, Operators, PendingSlashes, PendingStakingOperationCount,
    Withdrawals,
};
use crate::staking::{
    do_cleanup_operator, do_convert_previous_epoch_deposits, do_convert_previous_epoch_withdrawal,
    DomainEpoch, Error as TransitionError, OperatorStatus, SharePrice, WithdrawalInShares,
};
use crate::{
    bundle_storage_fund, BalanceOf, Config, DepositOnHold, ElectionVerificationParams, Event,
    HoldIdentifier, OperatorEpochSharePrice, Pallet,
};
use codec::{Decode, Encode};
use frame_support::traits::fungible::{Inspect, Mutate, MutateHold};
use frame_support::traits::tokens::{
    DepositConsequence, Fortitude, Precision, Provenance, Restriction,
};
use frame_support::PalletError;
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::{DomainId, EpochIndex, OperatorId};
use sp_runtime::traits::{CheckedAdd, CheckedSub, One, Zero};
use sp_runtime::Saturating;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::btree_set::BTreeSet;

#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum Error {
    FinalizeDomainEpochStaking(TransitionError),
    OperatorRewardStaking(TransitionError),
}

pub(crate) struct EpochTransitionResult {
    pub rewarded_operator_count: u32,
    pub finalized_operator_count: u32,
    pub completed_epoch_index: EpochIndex,
}

/// Finalizes the domain's current epoch and begins the next epoch.
/// Returns true of the epoch indeed was finished and the number of operator processed.
pub(crate) fn do_finalize_domain_current_epoch<T: Config>(
    domain_id: DomainId,
) -> Result<EpochTransitionResult, Error> {
    // Reset pending staking operation count to 0
    PendingStakingOperationCount::<T>::set(domain_id, 0);

    // re stake operator's tax from the rewards
    let rewarded_operator_count = operator_take_reward_tax_and_stake::<T>(domain_id)?;

    // finalize any withdrawals and then deposits
    let (completed_epoch_index, finalized_operator_count) =
        do_finalize_domain_epoch_staking::<T>(domain_id)?;

    Ok(EpochTransitionResult {
        rewarded_operator_count,
        finalized_operator_count,
        completed_epoch_index,
    })
}

/// Operator takes `NominationTax` of the current epoch rewards and stake them.
pub(crate) fn operator_take_reward_tax_and_stake<T: Config>(
    domain_id: DomainId,
) -> Result<u32, Error> {
    let mut rewarded_operator_count = 0;
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
                let operator_tax_amount = operator.nomination_tax.mul_floor(reward);
                if !operator_tax_amount.is_zero() {
                    let nominator_id = OperatorIdOwner::<T>::get(operator_id)
                        .ok_or(TransitionError::MissingOperatorOwner)?;
                    T::Currency::mint_into(&nominator_id, operator_tax_amount)
                        .map_err(|_| TransitionError::MintBalance)?;

                    // Reserve for the bundle storage fund
                    let operator_tax_deposit =
                        deposit_reserve_for_storage_fund::<T>(operator_id, &nominator_id, operator_tax_amount)
                            .map_err(TransitionError::BundleStorageFund)?;

                    crate::staking::hold_deposit::<T>(
                        &nominator_id,
                        operator_id,
                        operator_tax_deposit.staking,
                    )?;

                    // increment total deposit for operator pool within this epoch
                    operator.deposits_in_epoch = operator
                        .deposits_in_epoch
                        .checked_add(&operator_tax_deposit.staking)
                        .ok_or(TransitionError::BalanceOverflow)?;

                    // Increase total storage fee deposit as there is new deposit to the storage fund
                    operator.total_storage_fee_deposit = operator
                        .total_storage_fee_deposit
                        .checked_add(&operator_tax_deposit.storage_fee_deposit)
                        .ok_or(TransitionError::BalanceOverflow)?;

                    let current_domain_epoch = (domain_id, stake_summary.current_epoch_index).into();
                    crate::staking::do_calculate_previous_epoch_deposit_shares_and_add_new_deposit::<T>(
                            operator_id,
                            nominator_id,
                            current_domain_epoch,
                            operator_tax_deposit,
                        )?;

                    Pallet::<T>::deposit_event(Event::OperatorTaxCollected {
                        operator_id,
                        tax: operator_tax_amount,
                    });
                }

                // add remaining rewards to nominators to be distributed during the epoch transition
                let rewards = reward
                    .checked_sub(&operator_tax_amount)
                    .ok_or(TransitionError::BalanceUnderflow)?;

                operator.current_epoch_rewards = operator
                    .current_epoch_rewards
                    .checked_add(&rewards)
                    .ok_or(TransitionError::BalanceOverflow)?;

                rewarded_operator_count += 1;

                Ok(())
            })?;
        }

        Ok(())
    })
    .map_err(Error::OperatorRewardStaking)?;

    Ok(rewarded_operator_count)
}

pub(crate) fn do_finalize_domain_epoch_staking<T: Config>(
    domain_id: DomainId,
) -> Result<(EpochIndex, u32), Error> {
    let mut finalized_operator_count = 0;
    DomainStakingSummary::<T>::try_mutate(domain_id, |maybe_stake_summary| {
        let stake_summary = maybe_stake_summary
            .as_mut()
            .ok_or(TransitionError::DomainNotInitialized)?;

        let previous_epoch = stake_summary.current_epoch_index;
        let next_epoch = previous_epoch
            .checked_add(One::one())
            .ok_or(TransitionError::EpochOverflow)?;

        let mut total_domain_stake = BalanceOf::<T>::zero();
        let mut current_operators = BTreeMap::new();
        let mut next_operators = BTreeSet::new();
        for next_operator_id in &stake_summary.next_operators {
            // If an operator is pending to slash then similar to the slashed operator it should not be added
            // into the `next_operators/current_operators` and we should not `do_finalize_operator_epoch_staking`
            // for it.
            if Pallet::<T>::is_operator_pending_to_slash(domain_id, *next_operator_id) {
                continue;
            }

            let (operator_stake, stake_changed) = do_finalize_operator_epoch_staking::<T>(
                domain_id,
                *next_operator_id,
                previous_epoch,
            )?;

            total_domain_stake = total_domain_stake
                .checked_add(&operator_stake)
                .ok_or(TransitionError::BalanceOverflow)?;
            current_operators.insert(*next_operator_id, operator_stake);
            next_operators.insert(*next_operator_id);

            if stake_changed {
                finalized_operator_count += 1;
            }
        }

        let election_verification_params = ElectionVerificationParams {
            operators: stake_summary.current_operators.clone(),
            total_domain_stake: stake_summary.current_total_stake,
        };

        LastEpochStakingDistribution::<T>::insert(domain_id, election_verification_params);

        let previous_epoch = stake_summary.current_epoch_index;
        stake_summary.current_epoch_index = next_epoch;
        stake_summary.current_total_stake = total_domain_stake;
        stake_summary.current_operators = current_operators;
        stake_summary.next_operators = next_operators;

        Ok((previous_epoch, finalized_operator_count))
    })
    .map_err(Error::FinalizeDomainEpochStaking)
}

/// Finalize the epoch for the operator
///
/// Return the new total stake of the operator and a bool indicate if its total stake
/// is changed due to deposit/withdraw/reward happened in the previous epoch
pub(crate) fn do_finalize_operator_epoch_staking<T: Config>(
    domain_id: DomainId,
    operator_id: OperatorId,
    previous_epoch: EpochIndex,
) -> Result<(BalanceOf<T>, bool), TransitionError> {
    let mut operator = match Operators::<T>::get(operator_id) {
        Some(op) => op,
        None => return Err(TransitionError::UnknownOperator),
    };

    if *operator.status::<T>(operator_id) != OperatorStatus::Registered {
        return Err(TransitionError::OperatorNotRegistered);
    }

    // if there are no deposits, withdrawls, and epoch rewards for this operator
    // then short-circuit and return early.
    if operator.deposits_in_epoch.is_zero()
        && operator.withdrawals_in_epoch.is_zero()
        && operator.current_epoch_rewards.is_zero()
    {
        return Ok((operator.current_total_stake, false));
    }

    let total_stake = operator
        .current_total_stake
        .checked_add(&operator.current_epoch_rewards)
        .ok_or(TransitionError::BalanceOverflow)?;

    let total_shares = operator.current_total_shares;

    let share_price = SharePrice::new::<T>(total_shares, total_stake);

    // calculate and subtract total withdrew shares from previous epoch
    let (total_stake, total_shares) = if !operator.withdrawals_in_epoch.is_zero() {
        let withdraw_stake = share_price.shares_to_stake::<T>(operator.withdrawals_in_epoch);
        let total_stake = total_stake
            .checked_sub(&withdraw_stake)
            .ok_or(TransitionError::BalanceUnderflow)?;
        let total_shares = total_shares
            .checked_sub(&operator.withdrawals_in_epoch)
            .ok_or(TransitionError::ShareUnderflow)?;

        operator.withdrawals_in_epoch = Zero::zero();
        (total_stake, total_shares)
    } else {
        (total_stake, total_shares)
    };

    // calculate and add total deposits from the previous epoch
    let (total_stake, total_shares) = if !operator.deposits_in_epoch.is_zero() {
        let deposited_shares = share_price.stake_to_shares::<T>(operator.deposits_in_epoch);
        let total_stake = total_stake
            .checked_add(&operator.deposits_in_epoch)
            .ok_or(TransitionError::BalanceOverflow)?;
        let total_shares = total_shares
            .checked_add(&deposited_shares)
            .ok_or(TransitionError::ShareOverflow)?;
        operator.deposits_in_epoch = Zero::zero();
        (total_stake, total_shares)
    } else {
        (total_stake, total_shares)
    };

    // update operator pool epoch share price
    // TODO: once we have reference counting, we do not need to
    //  store this for every epoch for every operator but instead
    //  store only those share prices of operators which has either a deposit or withdraw
    OperatorEpochSharePrice::<T>::insert(
        operator_id,
        DomainEpoch::from((domain_id, previous_epoch)),
        share_price,
    );

    // update operator state
    operator.current_total_shares = total_shares;
    operator.current_total_stake = total_stake;
    operator.current_epoch_rewards = Zero::zero();
    Operators::<T>::set(operator_id, Some(operator));

    Ok((total_stake, true))
}

pub(crate) fn mint_funds<T: Config>(
    account_id: &T::AccountId,
    amount_to_mint: BalanceOf<T>,
) -> Result<(), TransitionError> {
    if !amount_to_mint.is_zero() {
        T::Currency::mint_into(account_id, amount_to_mint)
            .map_err(|_| TransitionError::MintBalance)?;
    }

    Ok(())
}

pub(crate) fn mint_into_treasury<T: Config>(amount: BalanceOf<T>) -> Option<()> {
    let existing_funds = AccumulatedTreasuryFunds::<T>::get();
    let total_funds = existing_funds.checked_add(&amount)?;
    if total_funds.is_zero() {
        return Some(());
    }

    match T::Currency::can_deposit(&T::TreasuryAccount::get(), total_funds, Provenance::Minted) {
        // Deposit is possible, so we mint the funds into treasury.
        DepositConsequence::Success => {
            T::Currency::mint_into(&T::TreasuryAccount::get(), total_funds).ok()?;
            AccumulatedTreasuryFunds::<T>::kill();
        }
        // Deposit cannot be done to treasury, so hold the funds until we can.
        _ => AccumulatedTreasuryFunds::<T>::set(total_funds),
    }
    Some(())
}

/// Slashes any pending slashed operators.
/// At max slashes the `max_nominator_count` under given operator
pub(crate) fn do_slash_operator<T: Config>(
    domain_id: DomainId,
    max_nominator_count: u32,
) -> Result<u32, TransitionError> {
    let mut slashed_nominator_count = 0u32;
    let (operator_id, slashed_operators) = match PendingSlashes::<T>::get(domain_id) {
        None => return Ok(0),
        Some(mut slashed_operators) => match slashed_operators.pop_first() {
            None => {
                PendingSlashes::<T>::remove(domain_id);
                return Ok(0);
            }
            Some(operator_id) => (operator_id, slashed_operators),
        },
    };

    Operators::<T>::try_mutate_exists(operator_id, |maybe_operator| {
        // take the operator so this operator info is removed once we slash the operator.
        let mut operator = maybe_operator
            .take()
            .ok_or(TransitionError::UnknownOperator)?;

        let operator_owner =
            OperatorIdOwner::<T>::get(operator_id).ok_or(TransitionError::UnknownOperator)?;

        let staked_hold_id = T::HoldIdentifier::staking_staked();

        let mut total_stake = operator
            .current_total_stake
            .checked_add(&operator.current_epoch_rewards)
            .ok_or(TransitionError::BalanceOverflow)?;

        operator.current_epoch_rewards = Zero::zero();
        let mut total_shares = operator.current_total_shares;
        let share_price = SharePrice::new::<T>(total_shares, total_stake);

        let mut total_storage_fee_deposit = operator.total_storage_fee_deposit;

        // transfer all the staked funds to the treasury account
        // any gains will be minted to treasury account
        for (nominator_id, mut deposit) in Deposits::<T>::drain_prefix(operator_id) {
            let locked_amount = DepositOnHold::<T>::take((operator_id, nominator_id.clone()));

            // convert any previous epoch deposits
            do_convert_previous_epoch_deposits::<T>(operator_id, &mut deposit)?;

            // there maybe some withdrawals that are initiated in this epoch where operator was slashed
            // then collect and include them to find the final stake amount
            let (
                amount_ready_to_withdraw,
                withdraw_storage_fee_on_hold,
                shares_withdrew_in_current_epoch,
            ) = Withdrawals::<T>::take(operator_id, nominator_id.clone())
                .map(|mut withdrawal| {
                    do_convert_previous_epoch_withdrawal::<T>(operator_id, &mut withdrawal)?;
                    Ok((
                        withdrawal.total_withdrawal_amount,
                        withdrawal.total_storage_fee_withdrawal,
                        withdrawal
                            .withdrawal_in_shares
                            .map(|WithdrawalInShares { shares, .. }| shares)
                            .unwrap_or_default(),
                    ))
                })
                .unwrap_or(Ok((Zero::zero(), Zero::zero(), Zero::zero())))?;

            // include all the known shares and shares that were withdrawn in the current epoch
            let nominator_shares = deposit
                .known
                .shares
                .checked_add(&shares_withdrew_in_current_epoch)
                .ok_or(TransitionError::ShareOverflow)?;

            // current staked amount
            let nominator_staked_amount = share_price.shares_to_stake::<T>(nominator_shares);

            let pending_deposit = deposit
                .pending
                .map(|pending_deposit| pending_deposit.amount)
                .unwrap_or_default();

            // do not slash the deposit that is not staked yet
            let amount_to_slash_in_holding = locked_amount
                .checked_sub(&pending_deposit)
                .ok_or(TransitionError::BalanceUnderflow)?;

            T::Currency::transfer_on_hold(
                &staked_hold_id,
                &nominator_id,
                &T::TreasuryAccount::get(),
                amount_to_slash_in_holding,
                Precision::Exact,
                Restriction::Free,
                Fortitude::Force,
            )
            .map_err(|_| TransitionError::RemoveLock)?;

            // release rest of the deposited un staked amount back to nominator
            T::Currency::release(
                &staked_hold_id,
                &nominator_id,
                pending_deposit,
                Precision::BestEffort,
            )
            .map_err(|_| TransitionError::RemoveLock)?;

            // these are nominator rewards that will be minted to treasury
            // include amount ready to be withdrawn to calculate the final reward
            let nominator_reward = nominator_staked_amount
                .checked_add(&amount_ready_to_withdraw)
                .ok_or(TransitionError::BalanceOverflow)?
                .checked_sub(&amount_to_slash_in_holding)
                .ok_or(TransitionError::BalanceUnderflow)?;

            mint_into_treasury::<T>(nominator_reward).ok_or(TransitionError::MintBalance)?;

            total_stake = total_stake.saturating_sub(nominator_staked_amount);
            total_shares = total_shares.saturating_sub(nominator_shares);

            // Transfer the deposited non-staked storage fee back to nominator
            if let Some(pending_deposit) = deposit.pending {
                let storage_fund_redeem_price = bundle_storage_fund::storage_fund_redeem_price::<T>(
                    operator_id,
                    total_storage_fee_deposit,
                );

                bundle_storage_fund::withdraw_to::<T>(
                    operator_id,
                    &nominator_id,
                    storage_fund_redeem_price.redeem(pending_deposit.storage_fee_deposit),
                )
                .map_err(TransitionError::BundleStorageFund)?;

                total_storage_fee_deposit =
                    total_storage_fee_deposit.saturating_sub(pending_deposit.storage_fee_deposit);
            }

            // Transfer all the storage fee on withdraw to the treasury
            T::Currency::transfer_on_hold(
                &T::HoldIdentifier::storage_fund_withdrawal(),
                &nominator_id,
                &T::TreasuryAccount::get(),
                withdraw_storage_fee_on_hold,
                Precision::Exact,
                Restriction::Free,
                Fortitude::Force,
            )
            .map_err(|_| TransitionError::RemoveLock)?;

            // update nominator count.
            let nominator_count = NominatorCount::<T>::get(operator_id);
            if operator_owner != nominator_id && nominator_count > 0 {
                NominatorCount::<T>::set(operator_id, nominator_count - 1);
            }

            slashed_nominator_count += 1;
            if slashed_nominator_count >= max_nominator_count {
                break;
            }
        }

        let nominator_count = NominatorCount::<T>::get(operator_id);
        let cleanup_operator =
            nominator_count == 0 && !Deposits::<T>::contains_key(operator_id, operator_owner);

        if cleanup_operator {
            do_cleanup_operator::<T>(operator_id, total_stake, operator.signing_key)?;
            if slashed_operators.is_empty() {
                PendingSlashes::<T>::remove(domain_id);
            } else {
                PendingSlashes::<T>::set(domain_id, Some(slashed_operators));
            }
        } else {
            // set update total shares, total stake and total storage fee deposit for operator
            operator.current_total_shares = total_shares;
            operator.current_total_stake = total_stake;
            operator.total_storage_fee_deposit = total_storage_fee_deposit;
            *maybe_operator = Some(operator);
        }

        Ok(slashed_nominator_count)
    })
}

#[cfg(test)]
mod tests {
    use crate::bundle_storage_fund::STORAGE_FEE_RESERVE;
    use crate::pallet::{
        Deposits, DomainStakingSummary, HeadDomainNumber, LastEpochStakingDistribution,
        NominatorCount, OperatorIdOwner, OperatorSigningKey, Operators, Withdrawals,
    };
    use crate::staking::tests::{register_operator, Share};
    use crate::staking::{
        do_deregister_operator, do_nominate_operator, do_reward_operators, do_unlock_nominator,
        do_withdraw_stake, WithdrawStake,
    };
    use crate::staking_epoch::{
        do_finalize_domain_current_epoch, operator_take_reward_tax_and_stake,
    };
    use crate::tests::{new_test_ext, Test};
    use crate::{BalanceOf, Config, HoldIdentifier, NominatorId};
    #[cfg(not(feature = "std"))]
    use alloc::vec;
    use codec::Encode;
    use frame_support::assert_ok;
    use frame_support::traits::fungible::InspectHold;
    use sp_core::{Pair, U256};
    use sp_domains::{
        DomainId, OperatorPair, OperatorRewardSource, OperatorSigningKeyProofOfOwnershipData,
    };
    use sp_runtime::traits::Zero;
    use sp_runtime::{PerThing, Percent};
    use std::collections::BTreeMap;
    use subspace_runtime_primitives::SSC;

    type Balances = pallet_balances::Pallet<Test>;

    fn unlock_nominator(
        nominators: Vec<(NominatorId<Test>, BalanceOf<Test>)>,
        pending_deposits: Vec<(NominatorId<Test>, BalanceOf<Test>)>,
        withdrawals: Vec<(NominatorId<Test>, Share)>,
        expected_usable_balances: Vec<(NominatorId<Test>, BalanceOf<Test>)>,
        rewards: BalanceOf<Test>,
    ) {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());
        let data = OperatorSigningKeyProofOfOwnershipData {
            operator_owner: operator_account,
        };
        let signature = pair.sign(&data.encode());
        let minimum_free_balance = 10 * SSC;
        let mut nominators = BTreeMap::from_iter(
            nominators
                .into_iter()
                .map(|(id, balance)| (id, (balance + minimum_free_balance, balance)))
                .collect::<Vec<(NominatorId<Test>, (BalanceOf<Test>, BalanceOf<Test>))>>(),
        );

        for pending_deposit in &pending_deposits {
            let staked_deposit = nominators
                .get(&pending_deposit.0)
                .cloned()
                .unwrap_or((minimum_free_balance, 0));
            let total_balance = staked_deposit.0 + pending_deposit.1;
            nominators.insert(pending_deposit.0, (total_balance, staked_deposit.1));
        }

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let (operator_free_balance, operator_stake) =
                nominators.remove(&operator_account).unwrap();
            let (operator_id, _) = register_operator(
                domain_id,
                operator_account,
                operator_free_balance,
                operator_stake,
                10 * SSC,
                pair.public(),
                signature,
                BTreeMap::from_iter(nominators.clone()),
            );

            do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();

            // add pending deposits
            for pending_deposit in &pending_deposits {
                do_nominate_operator::<Test>(operator_id, pending_deposit.0, pending_deposit.1)
                    .unwrap();
            }

            for (nominator_id, shares) in withdrawals {
                do_withdraw_stake::<Test>(operator_id, nominator_id, WithdrawStake::Share(shares))
                    .unwrap();
            }

            if !rewards.is_zero() {
                do_reward_operators::<Test>(
                    domain_id,
                    OperatorRewardSource::Dummy,
                    vec![operator_id].into_iter(),
                    rewards,
                )
                .unwrap()
            }

            // de-register operator
            let head_domain_number = HeadDomainNumber::<Test>::get(domain_id);
            do_deregister_operator::<Test>(operator_account, operator_id).unwrap();

            // finalize and add to pending operator unlocks
            do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();

            // Update `HeadDomainNumber` to ensure unlock success
            HeadDomainNumber::<Test>::set(
                domain_id,
                head_domain_number + <Test as crate::Config>::StakeWithdrawalLockingPeriod::get(),
            );

            for (nominator_id, _) in nominators {
                assert_ok!(do_unlock_nominator::<Test>(operator_id, nominator_id));
            }

            assert_ok!(do_unlock_nominator::<Test>(operator_id, operator_account));

            let hold_id = crate::tests::HoldIdentifierWrapper::staking_staked();
            for (nominator_id, mut expected_usable_balance) in expected_usable_balances {
                expected_usable_balance += minimum_free_balance;
                assert_eq!(Deposits::<Test>::get(operator_id, nominator_id), None);
                assert_eq!(Withdrawals::<Test>::get(operator_id, nominator_id), None);
                assert_eq!(
                    Balances::usable_balance(nominator_id),
                    expected_usable_balance
                );
                assert_eq!(
                    Balances::balance_on_hold(&hold_id, &nominator_id),
                    Zero::zero()
                );
            }

            assert_eq!(Operators::<Test>::get(operator_id), None);
            assert_eq!(OperatorIdOwner::<Test>::get(operator_id), None);
            assert_eq!(OperatorSigningKey::<Test>::get(pair.public()), None);
            assert_eq!(NominatorCount::<Test>::get(operator_id), 0);
        });
    }

    #[test]
    fn unlock_operator_with_no_rewards() {
        unlock_nominator(
            vec![(1, 150 * SSC), (2, 50 * SSC), (3, 10 * SSC)],
            vec![(2, 10 * SSC), (4, 10 * SSC)],
            vec![(1, 20 * SSC), (2, 10 * SSC)],
            vec![(1, 150 * SSC), (2, 60 * SSC), (3, 10 * SSC), (4, 10 * SSC)],
            0,
        );
    }

    #[test]
    fn unlock_operator_with_rewards() {
        unlock_nominator(
            vec![(1, 150 * SSC), (2, 50 * SSC), (3, 10 * SSC)],
            vec![(2, 10 * SSC), (4, 10 * SSC)],
            vec![(1, 20 * SSC), (2, 10 * SSC)],
            vec![
                (1, 164285714327278911577),
                (2, 64761904775759637192),
                (3, 10952380955151927438),
                (4, 10 * SSC),
            ],
            20 * SSC,
        );
    }

    struct FinalizeDomainParams {
        total_deposit: BalanceOf<Test>,
        rewards: BalanceOf<Test>,
        nominators: Vec<(NominatorId<Test>, <Test as Config>::Share)>,
        deposits: Vec<(NominatorId<Test>, BalanceOf<Test>)>,
    }

    fn finalize_domain_epoch(params: FinalizeDomainParams) {
        let domain_id = DomainId::new(0);
        let operator_account = 0;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());
        let data = OperatorSigningKeyProofOfOwnershipData {
            operator_owner: operator_account,
        };
        let signature = pair.sign(&data.encode());
        let FinalizeDomainParams {
            total_deposit,
            rewards,
            nominators,
            deposits,
        } = params;

        let minimum_free_balance = 10 * SSC;
        let mut nominators = BTreeMap::from_iter(
            nominators
                .into_iter()
                .map(|(id, balance)| (id, (balance + minimum_free_balance, balance)))
                .collect::<Vec<(NominatorId<Test>, (BalanceOf<Test>, BalanceOf<Test>))>>(),
        );

        for deposit in &deposits {
            let values = nominators
                .remove(&deposit.0)
                .unwrap_or((minimum_free_balance, 0));
            nominators.insert(deposit.0, (deposit.1 + values.0, values.1));
        }

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let (operator_free_balance, operator_stake) =
                nominators.remove(&operator_account).unwrap();
            let (operator_id, _) = register_operator(
                domain_id,
                operator_account,
                operator_free_balance,
                operator_stake,
                10 * SSC,
                pair.public(),
                signature,
                BTreeMap::from_iter(nominators),
            );

            do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();

            let mut total_new_deposit = BalanceOf::<Test>::zero();
            for deposit in &deposits {
                do_nominate_operator::<Test>(operator_id, deposit.0, deposit.1).unwrap();
                total_new_deposit += deposit.1;
            }

            if !rewards.is_zero() {
                do_reward_operators::<Test>(
                    domain_id,
                    OperatorRewardSource::Dummy,
                    vec![operator_id].into_iter(),
                    rewards,
                )
                .unwrap();
            }

            do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();
            for deposit in deposits {
                Deposits::<Test>::contains_key(operator_id, deposit.0);
            }

            // should also store the previous epoch details in-block
            let total_stake = STORAGE_FEE_RESERVE.left_from_one() * total_deposit;
            let election_params = LastEpochStakingDistribution::<Test>::get(domain_id).unwrap();
            assert_eq!(
                election_params.operators,
                BTreeMap::from_iter(vec![(operator_id, total_stake)])
            );
            assert_eq!(election_params.total_domain_stake, total_stake);

            let total_updated_stake = total_deposit + total_new_deposit + rewards;
            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(
                operator.current_total_stake + operator.total_storage_fee_deposit,
                total_updated_stake
            );
            assert_eq!(operator.current_epoch_rewards, Zero::zero());

            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert_eq!(
                domain_stake_summary.current_total_stake,
                total_updated_stake - operator.total_storage_fee_deposit
            );
            // epoch should be 3 since we did 3 epoch transitions
            assert_eq!(domain_stake_summary.current_epoch_index, 3);
        });
    }

    #[test]
    fn finalize_domain_epoch_no_rewards() {
        finalize_domain_epoch(FinalizeDomainParams {
            total_deposit: 210 * SSC,
            rewards: 0,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            deposits: vec![(1, 50 * SSC), (3, 10 * SSC)],
        })
    }

    #[test]
    fn finalize_domain_epoch_with_rewards() {
        finalize_domain_epoch(FinalizeDomainParams {
            total_deposit: 210 * SSC,
            rewards: 20 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            deposits: vec![(1, 50 * SSC), (3, 10 * SSC)],
        })
    }

    #[test]
    fn operator_tax_and_staking() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());
        let data = OperatorSigningKeyProofOfOwnershipData {
            operator_owner: operator_account,
        };
        let signature = pair.sign(&data.encode());
        let operator_rewards = 10 * SSC;
        let mut nominators =
            BTreeMap::from_iter(vec![(1, (110 * SSC, 100 * SSC)), (2, (60 * SSC, 50 * SSC))]);

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let (operator_free_balance, operator_stake) =
                nominators.remove(&operator_account).unwrap();
            let (operator_id, _) = register_operator(
                domain_id,
                operator_account,
                operator_free_balance,
                operator_stake,
                10 * SSC,
                pair.public(),
                signature,
                BTreeMap::from_iter(nominators),
            );

            do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();

            // 10% tax
            let nomination_tax = Percent::from_parts(10);
            let mut operator = Operators::<Test>::get(operator_id).unwrap();
            let pre_storage_fund_deposit = operator.total_storage_fee_deposit;
            operator.nomination_tax = nomination_tax;
            Operators::<Test>::insert(operator_id, operator);
            let expected_operator_tax = nomination_tax.mul_ceil(operator_rewards);

            do_reward_operators::<Test>(
                domain_id,
                OperatorRewardSource::Dummy,
                vec![operator_id].into_iter(),
                operator_rewards,
            )
            .unwrap();

            operator_take_reward_tax_and_stake::<Test>(domain_id).unwrap();
            let operator = Operators::<Test>::get(operator_id).unwrap();
            let new_storage_fund_deposit =
                operator.total_storage_fee_deposit - pre_storage_fund_deposit;
            assert_eq!(
                operator.current_epoch_rewards,
                (10 * SSC - expected_operator_tax)
            );

            let staking_deposit = Deposits::<Test>::get(operator_id, operator_account)
                .unwrap()
                .pending
                .unwrap()
                .amount;
            assert_eq!(
                staking_deposit + new_storage_fund_deposit,
                expected_operator_tax
            );
            assert_eq!(
                staking_deposit,
                STORAGE_FEE_RESERVE.left_from_one() * expected_operator_tax
            );
            assert_eq!(
                new_storage_fund_deposit,
                STORAGE_FEE_RESERVE * expected_operator_tax
            );
            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert!(domain_stake_summary.current_epoch_rewards.is_empty())
        });
    }
}

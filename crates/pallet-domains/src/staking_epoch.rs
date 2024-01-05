//! Staking epoch transition for domain
use crate::pallet::{
    Deposits, DomainEpochCompleteAt, DomainStakingSummary, LastEpochStakingDistribution,
    OperatorIdOwner, Operators, PendingOperatorSwitches, PendingSlashes,
    PendingStakingOperationCount,
};
use crate::staking::{
    calculate_withdraw_share_ssc, do_convert_previous_epoch_deposits, DomainEpoch,
    Error as TransitionError, OperatorStatus,
};
use crate::{
    BalanceOf, Config, DomainBlockNumberFor, ElectionVerificationParams, Event, HoldIdentifier,
    OperatorEpochSharePrice, Pallet,
};
use codec::{Decode, Encode};
use frame_support::traits::fungible::{InspectHold, Mutate, MutateHold};
use frame_support::traits::tokens::{Fortitude, Precision, Restriction};
use frame_support::PalletError;
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::{DomainId, EpochIndex, OperatorId};
use sp_runtime::traits::{CheckedAdd, CheckedSub, One, Zero};
use sp_runtime::{Perbill, Saturating};
use sp_std::collections::btree_map::BTreeMap;

#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum Error {
    FinalizeSwitchOperatorDomain(TransitionError),
    FinalizeDomainEpochStaking(TransitionError),
    OperatorRewardStaking(TransitionError),
    SlashOperator(TransitionError),
}

/// Finalizes the domain's current epoch and begins the next epoch.
/// Returns true of the epoch indeed was finished.
pub(crate) fn do_finalize_domain_current_epoch<T: Config>(
    domain_id: DomainId,
    domain_block_number: DomainBlockNumberFor<T>,
) -> Result<EpochIndex, Error> {
    // Reset pending staking operation count to 0
    PendingStakingOperationCount::<T>::set(domain_id, 0);

    // re stake operator's tax from the rewards
    operator_take_reward_tax_and_stake::<T>(domain_id)?;

    // slash the operators
    do_finalize_slashed_operators::<T>(domain_id).map_err(Error::SlashOperator)?;

    // finalize any operator switches
    do_finalize_switch_operator_domain::<T>(domain_id)?;

    // finalize any withdrawals and then deposits
    do_finalize_domain_epoch_staking::<T>(domain_id, domain_block_number)
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

                    crate::staking::hold_deposit::<T>(
                        &nominator_id,
                        operator_id,
                        operator_tax,
                    )?;

                    let current_domain_epoch = (domain_id, stake_summary.current_epoch_index).into();
                    crate::staking::do_calculate_previous_epoch_deposit_shares_and_maybe_add_new_deposit::<T>(
                            operator_id,
                            nominator_id,
                            current_domain_epoch,
                            Some(operator_tax),
                        )?;

                    Pallet::<T>::deposit_event(Event::OperatorTaxCollected {
                        operator_id,
                        tax: operator_tax,
                    });
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
            switch_operator::<T>(domain_id, operator_id)
                .map_err(Error::FinalizeSwitchOperatorDomain)
        })?;
    }

    Ok(())
}

fn switch_operator<T: Config>(
    domain_id: DomainId,
    operator_id: OperatorId,
) -> Result<(), TransitionError> {
    let previous_domain_summary =
        DomainStakingSummary::<T>::get(domain_id).ok_or(TransitionError::DomainNotInitialized)?;

    // finalize operator staking before moving to next domain
    // this also sets the operator epoch price.
    do_finalize_operator_epoch_staking::<T>(
        domain_id,
        operator_id,
        previous_domain_summary.current_epoch_index,
    )?;

    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator
            .as_mut()
            .ok_or(TransitionError::UnknownOperator)?;

        // operator is not registered, just no-op
        if operator.status != OperatorStatus::Registered {
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

pub(crate) fn do_finalize_domain_epoch_staking<T: Config>(
    domain_id: DomainId,
    domain_block_number: DomainBlockNumberFor<T>,
) -> Result<EpochIndex, Error> {
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
        for next_operator_id in &stake_summary.next_operators {
            let operator_stake = do_finalize_operator_epoch_staking::<T>(
                domain_id,
                *next_operator_id,
                previous_epoch,
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
        DomainEpochCompleteAt::<T>::insert(domain_id, previous_epoch, domain_block_number);

        let previous_epoch = stake_summary.current_epoch_index;
        stake_summary.current_epoch_index = next_epoch;
        stake_summary.current_total_stake = total_domain_stake;
        stake_summary.current_operators = current_operators;

        Ok(previous_epoch)
    })
    .map_err(Error::FinalizeDomainEpochStaking)
}

pub(crate) fn do_finalize_operator_epoch_staking<T: Config>(
    domain_id: DomainId,
    operator_id: OperatorId,
    previous_epoch: EpochIndex,
) -> Result<BalanceOf<T>, TransitionError> {
    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator
            .as_mut()
            .ok_or(TransitionError::UnknownOperator)?;

        if operator.status != OperatorStatus::Registered {
            return Err(TransitionError::OperatorNotRegistered);
        }

        let total_stake = operator
            .current_total_stake
            .checked_add(&operator.current_epoch_rewards)
            .ok_or(TransitionError::BalanceOverflow)?;

        let total_shares = operator.current_total_shares;

        let share_price = {
            if total_stake.is_zero() || total_shares.is_zero() {
                Perbill::one()
            } else {
                Perbill::from_rational(total_shares, total_stake.into())
            }
        };

        // calculate and subtract total withdrew shares from previous epoch
        let withdraw_stake =
            share_price.saturating_reciprocal_mul_floor(operator.withdrawals_in_epoch.into());
        let total_stake = total_stake
            .checked_sub(&withdraw_stake)
            .ok_or(TransitionError::BalanceUnderflow)?;
        let total_shares = total_shares
            .checked_sub(&operator.withdrawals_in_epoch)
            .ok_or(TransitionError::ShareUnderflow)?;

        // calculate and add total deposits from the previous epoch
        let deposited_shares = share_price.mul_floor(operator.deposits_in_epoch.into());
        let total_stake = total_stake
            .checked_add(&operator.deposits_in_epoch)
            .ok_or(TransitionError::BalanceOverflow)?;
        let total_shares = total_shares
            .checked_add(&deposited_shares)
            .ok_or(TransitionError::ShareOverflow)?;

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
        operator.deposits_in_epoch = Zero::zero();
        operator.withdrawals_in_epoch = Zero::zero();

        Ok(total_stake)
    })
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

pub(crate) fn do_finalize_slashed_operators<T: Config>(
    domain_id: DomainId,
) -> Result<(), TransitionError> {
    let domain_staking_summary =
        DomainStakingSummary::<T>::get(domain_id).ok_or(TransitionError::DomainNotInitialized)?;
    let domain_epoch = (domain_id, domain_staking_summary.current_epoch_index).into();
    for operator_id in PendingSlashes::<T>::take(domain_id).unwrap_or_default() {
        Operators::<T>::try_mutate_exists(operator_id, |maybe_operator| {
            // take the operator so this operator info is removed once we slash the operator.
            let operator = maybe_operator
                .take()
                .ok_or(TransitionError::UnknownOperator)?;

            // remove OperatorOwner Details
            OperatorIdOwner::<T>::remove(operator_id);

            let staked_hold_id = T::HoldIdentifier::staking_staked(operator_id);
            let mut total_stake = operator
                .current_total_stake
                .checked_add(&operator.current_epoch_rewards)
                .ok_or(TransitionError::BalanceOverflow)?;
            let total_shares = operator.current_total_shares;
            let share_price = Perbill::from_rational(total_shares, total_stake.into());

            // transfer all the staked funds to the treasury account
            // any gains will be minted to treasury account
            Deposits::<T>::drain_prefix(operator_id).try_for_each(
                |(nominator_id, mut deposit)| {
                    let locked_amount =
                        T::Currency::balance_on_hold(&staked_hold_id, &nominator_id);

                    // convert any previous epoch deposits
                    deposit.pending = do_convert_previous_epoch_deposits::<T>(
                        operator_id,
                        &mut deposit,
                        domain_epoch,
                    )?;

                    // there maybe some withdrawals that are initiated in this epoch where operator was slashed
                    // then collect and include them to find the final stake amount
                    let (amount_ready_to_withdraw, shares_withdrew_in_current_epoch) =
                        calculate_withdraw_share_ssc::<T>(operator_id, nominator_id.clone());

                    // include all the known shares and shares that were withdrawn in the current epoch
                    let nominator_shares = if shares_withdrew_in_current_epoch.is_zero() {
                        deposit.known.shares
                    } else {
                        deposit
                            .known
                            .shares
                            .checked_add(&shares_withdrew_in_current_epoch)
                            .ok_or(TransitionError::ShareOverflow)?
                    };

                    // current staked amount
                    let nominator_staked_amount = if share_price.is_one() {
                        nominator_shares.into()
                    } else {
                        share_price
                            .saturating_reciprocal_mul_floor(nominator_shares)
                            .into()
                    };

                    // do not slash the deposit that is not staked yet
                    let amount_to_slash_in_holding = locked_amount
                        .checked_sub(
                            &deposit
                                .pending
                                .map(|pending_deposit| pending_deposit.amount)
                                .unwrap_or_default(),
                        )
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

                    // these are nominator rewards that will be minted to treasury
                    // include amount ready to be withdrawn to calculate the final reward
                    let nominator_reward = nominator_staked_amount
                        .checked_add(&amount_ready_to_withdraw)
                        .ok_or(TransitionError::BalanceOverflow)?
                        .checked_sub(&amount_to_slash_in_holding)
                        .ok_or(TransitionError::BalanceUnderflow)?;
                    mint_funds::<T>(&T::TreasuryAccount::get(), nominator_reward)?;

                    total_stake = total_stake.saturating_sub(nominator_staked_amount);

                    // release rest of the deposited un staked amount back to nominator
                    T::Currency::release_all(&staked_hold_id, &nominator_id, Precision::BestEffort)
                        .map_err(|_| TransitionError::RemoveLock)?;

                    Ok(())
                },
            )?;

            // mint any gains to treasury account
            mint_funds::<T>(&T::TreasuryAccount::get(), total_stake)?;

            Ok(())
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::domain_registry::{DomainConfig, DomainObject};
    use crate::pallet::{
        Deposits, DomainRegistry, DomainStakingSummary, HeadReceiptNumber,
        LastEpochStakingDistribution, NominatorCount, OperatorIdOwner, OperatorSigningKey,
        Operators, PendingOperatorSwitches, Withdrawals,
    };
    use crate::staking::tests::{register_operator, Share};
    use crate::staking::{
        do_deregister_operator, do_nominate_operator, do_reward_operators, do_unlock_operator,
        do_withdraw_stake, StakingSummary, Withdraw,
    };
    use crate::staking_epoch::{
        do_finalize_domain_current_epoch, do_finalize_switch_operator_domain,
        operator_take_reward_tax_and_stake,
    };
    use crate::tests::{new_test_ext, RuntimeOrigin, Test};
    use crate::{BalanceOf, Config, HoldIdentifier, NominatorId};
    use frame_support::assert_ok;
    use frame_support::traits::fungible::InspectHold;
    use frame_support::weights::Weight;
    use sp_core::{Pair, U256};
    use sp_domains::{DomainId, OperatorAllowList, OperatorPair};
    use sp_runtime::traits::Zero;
    use sp_runtime::Percent;
    use std::collections::{BTreeMap, BTreeSet};
    use subspace_runtime_primitives::SSC;

    type Balances = pallet_balances::Pallet<Test>;
    type Domains = crate::Pallet<Test>;

    #[test]
    fn finalize_operator_domain_switch() {
        let old_domain_id = DomainId::new(0);
        let new_domain_id = DomainId::new(1);
        let operator_account = 1;
        let operator_free_balance = 200 * SSC;
        let operator_stake = 100 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let (operator_id, _) = register_operator(
                old_domain_id,
                operator_account,
                operator_free_balance,
                operator_stake,
                100 * SSC,
                pair.public(),
                BTreeMap::new(),
            );

            let domain_config = DomainConfig {
                domain_name: String::from_utf8(vec![0; 1024]).unwrap(),
                runtime_id: 0,
                max_block_size: u32::MAX,
                max_block_weight: Weight::MAX,
                bundle_slot_probability: (0, 0),
                target_bundles_per_block: 0,
                operator_allow_list: OperatorAllowList::Anyone,
            };

            let domain_obj = DomainObject {
                owner_account_id: 0,
                created_at: 0,
                genesis_receipt_hash: Default::default(),
                domain_config,
                domain_runtime_info: Default::default(),
            };

            DomainRegistry::<Test>::insert(new_domain_id, domain_obj);

            DomainStakingSummary::<Test>::insert(
                new_domain_id,
                StakingSummary {
                    current_epoch_index: 0,
                    current_total_stake: 0,
                    current_operators: BTreeMap::new(),
                    next_operators: BTreeSet::new(),
                    current_epoch_rewards: BTreeMap::new(),
                },
            );
            let res = Domains::switch_domain(
                RuntimeOrigin::signed(operator_account),
                operator_id,
                new_domain_id,
            );
            assert_ok!(res);

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
        withdrawals: Vec<(NominatorId<Test>, Share)>,
        expected_usable_balances: Vec<(NominatorId<Test>, BalanceOf<Test>)>,
        rewards: BalanceOf<Test>,
    ) {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());
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
                BTreeMap::from_iter(nominators.clone()),
            );

            do_finalize_domain_current_epoch::<Test>(domain_id, Zero::zero()).unwrap();

            // add pending deposits
            for pending_deposit in &pending_deposits {
                do_nominate_operator::<Test>(operator_id, pending_deposit.0, pending_deposit.1)
                    .unwrap();
            }

            for (nominator_id, shares) in withdrawals {
                do_withdraw_stake::<Test>(operator_id, nominator_id, Withdraw::Some(shares))
                    .unwrap();
            }

            if !rewards.is_zero() {
                do_reward_operators::<Test>(domain_id, vec![operator_id].into_iter(), rewards)
                    .unwrap()
            }

            // de-register operator
            do_deregister_operator::<Test>(operator_account, operator_id).unwrap();

            // finalize and add to pending operator unlocks
            let domain_block_number = 100;
            do_finalize_domain_current_epoch::<Test>(domain_id, domain_block_number).unwrap();

            // staking withdrawal is 5 blocks, and block pruning depth is 16
            // to unlock funds, confirmed block should be atleast 106 so +1 in the end
            HeadReceiptNumber::<Test>::insert(
                domain_id,
                domain_block_number
                    + crate::tests::StakeWithdrawalLockingPeriod::get()
                    + crate::tests::BlockTreePruningDepth::get()
                    + 1,
            );

            assert_ok!(do_unlock_operator::<Test>(operator_id));

            let hold_id = crate::tests::HoldIdentifier::staking_staked(operator_id);
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
        unlock_operator(
            vec![(1, 150 * SSC), (2, 50 * SSC), (3, 10 * SSC)],
            vec![(2, 10 * SSC), (4, 10 * SSC)],
            vec![(1, 20 * SSC), (2, 10 * SSC)],
            vec![(1, 150 * SSC), (2, 60 * SSC), (3, 10 * SSC), (4, 10 * SSC)],
            0,
        );
    }

    #[test]
    fn unlock_operator_with_rewards() {
        unlock_operator(
            vec![(1, 150 * SSC), (2, 50 * SSC), (3, 10 * SSC)],
            vec![(2, 10 * SSC), (4, 10 * SSC)],
            vec![(1, 20 * SSC), (2, 10 * SSC)],
            vec![
                (1, 164285714332653061237),
                (2, 64761904777551020412),
                (3, 10952380955510204082),
                (4, 10 * SSC),
            ],
            20 * SSC,
        );
    }

    struct FinalizeDomainParams {
        total_stake: BalanceOf<Test>,
        rewards: BalanceOf<Test>,
        nominators: Vec<(NominatorId<Test>, <Test as Config>::Share)>,
        deposits: Vec<(NominatorId<Test>, BalanceOf<Test>)>,
    }

    fn finalize_domain_epoch(params: FinalizeDomainParams) {
        let domain_id = DomainId::new(0);
        let operator_account = 0;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let FinalizeDomainParams {
            total_stake,
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
                BTreeMap::from_iter(nominators),
            );

            do_finalize_domain_current_epoch::<Test>(domain_id, Zero::zero()).unwrap();

            let mut total_deposit = BalanceOf::<Test>::zero();
            for deposit in &deposits {
                do_nominate_operator::<Test>(operator_id, deposit.0, deposit.1).unwrap();
                total_deposit += deposit.1;
            }

            if !rewards.is_zero() {
                do_reward_operators::<Test>(domain_id, vec![operator_id].into_iter(), rewards)
                    .unwrap();
            }

            let current_block = 100;
            do_finalize_domain_current_epoch::<Test>(domain_id, current_block).unwrap();
            for deposit in deposits {
                Deposits::<Test>::contains_key(operator_id, deposit.0);
            }

            // should also store the previous epoch details in-block
            let election_params = LastEpochStakingDistribution::<Test>::get(domain_id).unwrap();
            assert_eq!(
                election_params.operators,
                BTreeMap::from_iter(vec![(operator_id, total_stake)])
            );
            assert_eq!(election_params.total_domain_stake, total_stake);

            let total_updated_stake = total_stake + total_deposit + rewards;
            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(operator.current_total_stake, total_updated_stake);
            assert_eq!(operator.current_epoch_rewards, Zero::zero());

            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert_eq!(
                domain_stake_summary.current_total_stake,
                total_updated_stake
            );
            // epoch should be 3 since we did 3 epoch transitions
            assert_eq!(domain_stake_summary.current_epoch_index, 3);
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
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());
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
                BTreeMap::from_iter(nominators),
            );

            do_finalize_domain_current_epoch::<Test>(domain_id, Zero::zero()).unwrap();

            // 10% tax
            let nomination_tax = Percent::from_parts(10);
            let mut operator = Operators::<Test>::get(operator_id).unwrap();
            operator.nomination_tax = nomination_tax;
            Operators::<Test>::insert(operator_id, operator);
            let expected_operator_tax = nomination_tax.mul_ceil(operator_rewards);

            do_reward_operators::<Test>(domain_id, vec![operator_id].into_iter(), operator_rewards)
                .unwrap();

            operator_take_reward_tax_and_stake::<Test>(domain_id).unwrap();
            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(
                operator.current_epoch_rewards,
                (10 * SSC - expected_operator_tax)
            );

            let deposit = Deposits::<Test>::get(operator_id, operator_account)
                .unwrap()
                .pending
                .unwrap()
                .amount;
            assert_eq!(deposit, expected_operator_tax);

            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert!(domain_stake_summary.current_epoch_rewards.is_empty())
        });
    }
}

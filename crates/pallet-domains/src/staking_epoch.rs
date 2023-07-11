//! Staking epoch transition for domain

use crate::pallet::{
    DomainStakingSummary, Nominators, Operators, PendingDeposits, PendingNominatorUnlocks,
    PendingOperatorDeregistrations, PendingOperatorSwitches, PendingOperatorUnlocks,
    PendingUnlocks, PendingWithdrawals,
};
use crate::staking::{Nominator, Withdraw};
use crate::{BalanceOf, Config, FreezeIdentifier, FungibleFreezeId, NominatorId};
use codec::{Decode, Encode};
use frame_support::dispatch::TypeInfo;
use frame_support::traits::fungible::{InspectFreeze, Mutate, MutateFreeze};
use frame_support::PalletError;
use sp_core::Get;
use sp_domains::{DomainId, OperatorId};
use sp_runtime::traits::{CheckedAdd, CheckedSub, One, Zero};
use sp_runtime::Perbill;
use sp_std::vec;

#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum TransitionError {
    MissingOperator,
    MissingNomination,
    OperatorFrozen,
    MissingDomainStakeSummary,
    BalanceOverflow,
    BalanceUnderflow,
    ShareUnderflow,
    ShareOverflow,
    RemoveLock,
    UpdateLock,
    MintBalance,
    BlockNumberOverflow,
    EpochOverflow,
}

#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum Error {
    FinalizeSwitchOperatorDomain(TransitionError),
    FinalizeOperatorDeregistration(TransitionError),
    UnlockOperator(TransitionError),
    FinalizeDomainPendingTransfers(TransitionError),
    UnlockNominator(TransitionError),
}

/// Finalizes the domain's current epoch and begins the next epoch.
/// Returns true of the epoch indeed was finished.
// TODO: remove once connected with block tree
#[allow(dead_code)]
pub(crate) fn do_finalize_domain_current_epoch<T: Config>(
    domain_id: DomainId,
    domain_block_number: T::DomainNumber,
    current_consensus_block_number: T::BlockNumber,
) -> Result<bool, Error> {
    if domain_block_number % T::StakeEpochDuration::get() != Zero::zero() {
        return Ok(false);
    }

    // finalize any operator switches
    do_finalize_switch_operator_domain::<T>(domain_id)?;

    // finalize operator deregistrations
    do_finalize_operator_deregistrations::<T>(domain_id, current_consensus_block_number)?;

    // finalize any withdrawals and then deposits
    do_finalize_domain_pending_transfers::<T>(domain_id, current_consensus_block_number)?;
    Ok(true)
}

pub(crate) fn do_unlock_pending_withdrawals<T: Config>(
    consensus_block_number: T::BlockNumber,
) -> Result<(), Error> {
    if let Some(operator_ids) = PendingUnlocks::<T>::take(consensus_block_number) {
        PendingOperatorUnlocks::<T>::mutate(|unlocking_operator_ids| {
            for operator_id in operator_ids {
                if unlocking_operator_ids.contains(&operator_id) {
                    unlock_operator::<T>(operator_id)?;
                    unlocking_operator_ids
                        .retain(|existing_operator_ids| *existing_operator_ids != operator_id);
                } else {
                    unlock_nominator_withdrawals::<T>(operator_id, consensus_block_number)?;
                }
            }

            Ok(())
        })?;
    }
    Ok(())
}

/// Add all the switched operators to new domain.
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
            .ok_or(TransitionError::MissingOperator)?;

        if operator.is_frozen {
            return Err(TransitionError::OperatorFrozen);
        }

        operator.current_domain_id = operator.next_domain_id;
        DomainStakingSummary::<T>::try_mutate(operator.current_domain_id, |maybe_stake_summary| {
            let stake_summary = maybe_stake_summary
                .as_mut()
                .ok_or(TransitionError::MissingDomainStakeSummary)?;

            stake_summary.next_operators.push(operator_id);

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
                stored_operator_ids
                    .retain(|existing_operator_id| *existing_operator_id != operator_id);
                stored_operator_ids.push(operator_id);
            });
            *maybe_stored_operator_ids = Some(stored_operator_ids)
        })
    }

    Ok(())
}

fn unlock_operator<T: Config>(operator_id: OperatorId) -> Result<(), Error> {
    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator
            .as_mut()
            .ok_or(TransitionError::MissingOperator)?;

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
            T::Currency::mint_into(&nominator_id, amount_to_mint)
                .map_err(|_| TransitionError::MintBalance)?;

            // update pool's remaining shares and stake
            total_shares = total_shares
                .checked_sub(&nominator.shares)
                .ok_or(TransitionError::ShareUnderflow)?;
            total_stake = total_stake
                .checked_sub(&nominator_staked_amount)
                .ok_or(TransitionError::BalanceUnderflow)?;

            Ok(())
        })?;

        // TODO: transfer any remaining amount to treasury

        // reset operator
        operator.total_shares = Zero::zero();
        operator.current_total_stake = Zero::zero();
        operator.current_epoch_rewards = Zero::zero();

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
            .ok_or(TransitionError::MissingDomainStakeSummary)?;

        stake_summary.current_epoch_index = stake_summary
            .current_epoch_index
            .checked_add(One::one())
            .ok_or(TransitionError::EpochOverflow)?;

        let mut total_domain_stake = BalanceOf::<T>::zero();
        for next_operator_id in &stake_summary.next_operators {
            let total_operator_stake = finalize_operator_pending_transfers::<T>(
                *next_operator_id,
                current_consensus_block,
            )?;
            total_domain_stake = total_domain_stake
                .checked_add(&total_operator_stake)
                .ok_or(TransitionError::BalanceOverflow)?;
        }

        stake_summary.current_total_stake = total_domain_stake;
        stake_summary.current_operators = stake_summary.next_operators.clone();

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
            .ok_or(TransitionError::MissingOperator)?;

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
                .ok_or(TransitionError::MissingNomination)?;

            let nominator_share = Perbill::from_rational(nominator.shares, *total_shares);
            let nominator_staked_amount = nominator_share.mul_floor(*total_stake);

            let locked_amount = T::Currency::balance_frozen(freeze_identifier, &nominator_id);
            let amount_to_mint = nominator_staked_amount
                .checked_sub(&locked_amount)
                .unwrap_or(Zero::zero());

            // mint any gains and then update the lock
            T::Currency::mint_into(&nominator_id, amount_to_mint)
                .map_err(|_| TransitionError::MintBalance)?;
            T::Currency::set_freeze(freeze_identifier, &nominator_id, nominator_staked_amount)
                .map_err(|_| TransitionError::UpdateLock)?;
            (nominator_staked_amount, nominator.shares)
        }
        Withdraw::Some(withdraw_amount) => {
            Nominators::<T>::try_mutate(operator_id, nominator_id.clone(), |maybe_nominator| {
                let nominator = maybe_nominator
                    .as_mut()
                    .ok_or(TransitionError::MissingNomination)?;

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
                T::Currency::mint_into(&nominator_id, amount_to_mint)
                    .map_err(|_| TransitionError::MintBalance)?;
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

    let mut operator_ids = PendingUnlocks::<T>::get(unlock_at).unwrap_or(vec![]);
    operator_ids.retain(|existing_operator_id| *existing_operator_id != operator_id);
    operator_ids.push(operator_id);
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

#[cfg(test)]
mod tests {
    use crate::pallet::{
        DomainStakingSummary, Nominators, OperatorIdOwner, Operators, PendingDeposits,
        PendingOperatorDeregistrations, PendingOperatorSwitches, PendingOperatorUnlocks,
        PendingUnlocks,
    };
    use crate::staking::{Nominator, Operator, StakingSummary};
    use crate::staking_epoch::{
        do_finalize_domain_pending_transfers, do_finalize_operator_deregistrations,
        do_finalize_switch_operator_domain, do_unlock_pending_withdrawals,
    };
    use crate::tests::{new_test_ext, Test};
    use crate::{BalanceOf, Config, FreezeIdentifier as FreezeIdentifierT, NominatorId};
    use frame_support::assert_ok;
    use frame_support::traits::fungible::MutateFreeze;
    use frame_support::traits::Currency;
    use sp_core::{Pair, U256};
    use sp_domains::{DomainId, OperatorId, OperatorPair};
    use sp_runtime::traits::Zero;
    use subspace_runtime_primitives::SSC;

    type Balances = pallet_balances::Pallet<Test>;
    type ShareOf<T> = <T as Config>::Share;

    struct RequiredStateParams {
        domain_id: DomainId,
        total_domain_stake: BalanceOf<Test>,
        current_operators: Vec<OperatorId>,
        next_operators: Vec<OperatorId>,
        operator_id: OperatorId,
        operator_account: <Test as frame_system::Config>::AccountId,
        operator: Operator<BalanceOf<Test>, ShareOf<Test>>,
    }

    fn create_required_state(params: RequiredStateParams) {
        let RequiredStateParams {
            domain_id,
            total_domain_stake,
            current_operators,
            next_operators,
            operator_id,
            operator_account,
            operator,
        } = params;

        DomainStakingSummary::<Test>::insert(
            domain_id,
            StakingSummary {
                current_epoch_index: 0,
                current_total_stake: total_domain_stake,
                current_operators,
                next_operators,
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
            create_required_state(RequiredStateParams {
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
        rewards: BalanceOf<Test>,
    ) {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_id = 1;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());
        let minimum_free_balance = 10 * SSC;

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let mut total_stake = Zero::zero();
            let mut total_shares = Zero::zero();
            let freeze_id = crate::tests::FreezeIdentifier::staking_freeze_id(operator_id);
            for nominator in &nominators {
                total_stake += nominator.1;
                total_shares += nominator.1;
                Balances::make_free_balance_be(&nominator.0, nominator.1 + minimum_free_balance);
                assert_ok!(Balances::set_freeze(&freeze_id, &nominator.0, nominator.1));
                assert_eq!(Balances::usable_balance(nominator.0), minimum_free_balance);
                Nominators::<Test>::insert(
                    operator_id,
                    nominator.0,
                    Nominator {
                        shares: nominator.1,
                    },
                )
            }
            create_required_state(RequiredStateParams {
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
                    current_epoch_rewards: rewards,
                    total_shares,
                    is_frozen: true,
                },
            });

            let consensus_block_number = 100;
            PendingUnlocks::<Test>::append(consensus_block_number, operator_id);
            PendingOperatorUnlocks::<Test>::append(operator_id);
            assert!(do_unlock_pending_withdrawals::<Test>(consensus_block_number).is_ok());

            for nominator in &nominators {
                let mut required_minimum_free_balance = minimum_free_balance + nominator.1;
                if rewards.is_zero() {
                    // subtracted 1 SSC to account for any rounding errors if there are not rewards
                    required_minimum_free_balance -= SSC;
                }
                assert_eq!(Nominators::<Test>::get(operator_id, nominator.0), None);
                assert!(Balances::usable_balance(nominator.0) > required_minimum_free_balance);
            }

            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert!(operator.is_frozen);
            assert_eq!(operator.total_shares, Zero::zero());
            assert_eq!(operator.current_epoch_rewards, Zero::zero());
            assert_eq!(operator.current_total_stake, Zero::zero());
            assert!(PendingOperatorUnlocks::<Test>::get().is_empty())
        });
    }

    #[test]
    fn unlock_operator_with_no_rewards() {
        unlock_operator(vec![(1, 150 * SSC), (2, 50 * SSC), (3, 10 * SSC)], 0);
    }

    #[test]
    fn unlock_operator_with_rewards() {
        unlock_operator(vec![(1, 150 * SSC), (2, 50 * SSC), (3, 10 * SSC)], 20 * SSC);
    }

    #[test]
    fn finalize_operator_deregistration() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_id = 1;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            create_required_state(RequiredStateParams {
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
            });

            PendingOperatorDeregistrations::<Test>::append(domain_id, operator_id);
            let current_consensus_block_number = 100;
            assert!(do_finalize_operator_deregistrations::<Test>(
                domain_id,
                current_consensus_block_number,
            )
            .is_ok());

            let expected_unlock = 100 + crate::tests::StakeWithdrawalLockingPeriod::get();
            assert_eq!(PendingOperatorUnlocks::<Test>::get(), vec![operator_id]);
            assert_eq!(
                PendingUnlocks::<Test>::get(expected_unlock),
                Some(vec![operator_id])
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
            create_required_state(RequiredStateParams {
                domain_id,
                total_domain_stake: total_stake,
                current_operators: vec![operator_id],
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
            assert_eq!(domain_stake_summary.current_epoch_index, 1)
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
}

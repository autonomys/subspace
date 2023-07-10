//! Staking epoch transition for domain
// TODO: remove once pieces are connected.
#![allow(dead_code)]

use crate::pallet::{
    DomainStakingSummary, Nominators, Operators, PendingOperatorDeregistrations,
    PendingOperatorSwitches, PendingOperatorUnlocks,
};
use crate::{Config, FreezeIdentifier, NominatorId};
use frame_support::log::error;
use frame_support::traits::fungible::{InspectFreeze, Mutate, MutateFreeze};
use sp_core::Get;
use sp_domains::{DomainId, OperatorId};
use sp_runtime::traits::{CheckedAdd, CheckedSub, Zero};
use sp_runtime::Perbill;
use sp_std::vec::Vec;

#[derive(Debug)]
enum Error {
    MissingOperator,
    OperatorFrozen,
    MissingDomainStakeSummary,
    BalanceOverflow,
    BalanceUnderflow,
    ShareUnderflow,
    RemoveLock,
    MintBalance,
}

/// Add all the switched operators to new domain.
pub(crate) fn do_finalize_switch_operator_domain<T: Config>(domain_id: DomainId) {
    if let Some(operators) = PendingOperatorSwitches::<T>::take(domain_id) {
        for operator_id in operators {
            if let Err(err) = switch_operator::<T>(operator_id) {
                error!("Failed to switch operator[{operator_id:?}]: {err:?}",)
            }
        }
    }
}

fn switch_operator<T: Config>(operator_id: OperatorId) -> Result<(), Error> {
    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator.as_mut().ok_or(Error::MissingOperator)?;

        if operator.is_frozen {
            return Err(Error::OperatorFrozen);
        }

        operator.current_domain_id = operator.next_domain_id;
        DomainStakingSummary::<T>::try_mutate(operator.current_domain_id, |maybe_stake_summary| {
            let stake_summary = maybe_stake_summary
                .as_mut()
                .ok_or(Error::MissingDomainStakeSummary)?;

            stake_summary.next_operators.push(operator_id);

            Ok(())
        })
    })
}

pub(crate) fn do_finalize_operator_deregistrations<T: Config>(
    domain_id: DomainId,
    consensus_block_number: T::BlockNumber,
) {
    let stake_withdrawal_locking_period = T::StakeWithdrawalLockingPeriod::get();
    let unlock_block_number = match consensus_block_number
        .checked_add(&stake_withdrawal_locking_period)
    {
        None => {
            error!("Failed to compute unlock domain block number: {consensus_block_number:?} + {stake_withdrawal_locking_period:?}",);
            return;
        }
        Some(unlock_block_number) => unlock_block_number,
    };

    if let Some(operators) = PendingOperatorDeregistrations::<T>::take(domain_id) {
        PendingOperatorUnlocks::<T>::insert(domain_id, unlock_block_number, operators)
    }
}

pub(crate) fn do_unlock_operators<T: Config>(
    domain_id: DomainId,
    domain_block_number: T::BlockNumber,
) {
    if let Some(operators) = PendingOperatorUnlocks::<T>::take(domain_id, domain_block_number) {
        for operator_id in operators {
            if let Err(err) = unlock_operator::<T>(operator_id) {
                error!("Failed to unlock operator pool[{operator_id:?}]: {err:?}",)
            }
        }
    }
}

fn unlock_operator<T: Config>(operator_id: OperatorId) -> Result<(), Error> {
    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator.as_mut().ok_or(Error::MissingOperator)?;

        let mut total_shares = operator.total_shares;
        let mut total_stake = operator
            .current_total_stake
            .checked_add(&operator.current_epoch_rewards)
            .ok_or(Error::BalanceOverflow)?;

        let nominator_ids =
            Nominators::<T>::iter_key_prefix(operator_id).collect::<Vec<NominatorId<T>>>();

        let freeze_identifier = T::FreezeIdentifier::staking_freeze_id(operator_id);
        for nominator_id in nominator_ids {
            // defensively read the the Nominator stake and then clear it once processed
            if let Some(nominator) = Nominators::<T>::get(operator_id, nominator_id.clone()) {
                let nominator_share = Perbill::from_rational(nominator.shares, total_shares);
                let nominator_staked_amount = nominator_share * total_stake;

                let locked_amount = T::Currency::balance_frozen(&freeze_identifier, &nominator_id);
                let amount_to_mint = nominator_staked_amount
                    .checked_sub(&locked_amount)
                    .unwrap_or(Zero::zero());

                // remove the lock and mint any gains
                T::Currency::thaw(&freeze_identifier, &nominator_id)
                    .map_err(|_| Error::RemoveLock)?;
                T::Currency::mint_into(&nominator_id, amount_to_mint)
                    .map_err(|_| Error::MintBalance)?;

                // update pool's remaining shares and stake
                total_shares = total_shares
                    .checked_sub(&nominator.shares)
                    .ok_or(Error::ShareUnderflow)?;
                total_stake = total_stake
                    .checked_sub(&nominator_staked_amount)
                    .ok_or(Error::BalanceUnderflow)?;

                // remove nominator
                Nominators::<T>::remove(operator_id, nominator_id)
            }
        }

        // TODO: transfer any remaining amount to treasury

        // reset operator pool
        operator.total_shares = Zero::zero();
        operator.current_total_stake = Zero::zero();
        operator.current_epoch_rewards = Zero::zero();

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use crate::pallet::{
        DomainStakingSummary, Nominators, OperatorIdOwner, Operators,
        PendingOperatorDeregistrations, PendingOperatorSwitches, PendingOperatorUnlocks,
    };
    use crate::staking::{Nominator, Operator, StakingSummary};
    use crate::staking_epoch::{
        do_finalize_operator_deregistrations, do_finalize_switch_operator_domain,
        do_unlock_operators,
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
    type Domains = crate::Pallet<Test>;
    type ShareOf<T> = <T as Config>::Share;

    struct RequiredStateParams {
        domain_id: DomainId,
        total_domain_stake: BalanceOf<Test>,
        current_operators: Vec<OperatorId>,
        operator_id: OperatorId,
        operator_account: <Test as frame_system::Config>::AccountId,
        operator: Operator<BalanceOf<Test>, ShareOf<Test>>,
    }

    fn create_required_state(params: RequiredStateParams) {
        let RequiredStateParams {
            domain_id,
            total_domain_stake,
            current_operators,
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
                next_operators: vec![],
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
            do_finalize_switch_operator_domain::<Test>(old_domain_id);

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

            let domain_block_number = 100;
            PendingOperatorUnlocks::<Test>::append(domain_id, domain_block_number, operator_id);
            do_unlock_operators::<Test>(domain_id, domain_block_number);

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
            assert_eq!(
                PendingOperatorUnlocks::<Test>::get(domain_id, domain_block_number),
                None
            )
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
            do_finalize_operator_deregistrations::<Test>(domain_id, current_consensus_block_number);

            let expected_unlock = 100 + crate::tests::StakeWithdrawalLockingPeriod::get();
            assert_eq!(
                PendingOperatorUnlocks::<Test>::get(domain_id, expected_unlock),
                Some(vec![operator_id])
            )
        });
    }
}

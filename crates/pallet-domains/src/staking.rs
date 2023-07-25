//! Staking for domains

use crate::pallet::{
    DomainStakingSummary, NextOperatorId, Nominators, OperatorIdOwner, Operators, PendingDeposits,
    PendingOperatorDeregistrations, PendingOperatorSwitches, PendingSlashes, PendingWithdrawals,
};
use crate::{BalanceOf, Config, FreezeIdentifier, NominatorId};
use codec::{Decode, Encode};
use frame_support::traits::fungible::{Inspect, InspectFreeze, MutateFreeze};
use frame_support::traits::tokens::{Fortitude, Preservation};
use frame_support::{ensure, PalletError};
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::{DomainId, EpochIndex, OperatorId, OperatorPublicKey};
use sp_runtime::traits::{CheckedAdd, CheckedSub, One, Zero};
use sp_runtime::{Perbill, Percent};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::btree_set::BTreeSet;
use sp_std::vec::IntoIter;

/// Type that represents an operator details.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct Operator<Balance, Share> {
    pub signing_key: OperatorPublicKey,
    pub current_domain_id: DomainId,
    pub next_domain_id: DomainId,
    pub minimum_nominator_stake: Balance,
    pub nomination_tax: Percent,
    /// Total active stake of combined nominators under this operator.
    pub current_total_stake: Balance,
    /// Total rewards this operator received this current epoch.
    pub current_epoch_rewards: Balance,
    /// Total shares of all the nominators under this operator.
    pub total_shares: Share,
    pub is_frozen: bool,
}

/// Type that represents a nominator's details under a specific operator.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct Nominator<Share> {
    pub shares: Share,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum Withdraw<Balance> {
    All,
    Some(Balance),
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct StakingSummary<OperatorId, Balance> {
    /// Current epoch index for the domain.
    pub current_epoch_index: EpochIndex,
    /// Total active stake for the current epoch.
    pub current_total_stake: Balance,
    /// Current operators for this epoch
    pub current_operators: BTreeMap<OperatorId, Balance>,
    /// Operators for the next epoch.
    pub next_operators: BTreeSet<OperatorId>,
    /// Operator's current Epoch rewards
    pub current_epoch_rewards: BTreeMap<OperatorId, Balance>,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct OperatorConfig<Balance> {
    pub signing_key: OperatorPublicKey,
    pub minimum_nominator_stake: Balance,
    pub nomination_tax: Percent,
}

#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum Error {
    MaximumOperatorId,
    DomainNotInitialized,
    PendingOperatorSwitch,
    InsufficientBalance,
    BalanceFreeze,
    MinimumOperatorStake,
    UnknownOperator,
    MinimumNominatorStake,
    BalanceOverflow,
    BalanceUnderflow,
    NotOperatorOwner,
    OperatorFrozen,
    UnknownNominator,
    ExistingFullWithdraw,
    MissingOperatorOwner,
    MintBalance,
    BlockNumberOverflow,
    RemoveLock,
    UpdateLock,
    EpochOverflow,
    ShareUnderflow,
    ShareOverflow,
}

pub(crate) fn do_register_operator<T: Config>(
    operator_owner: T::AccountId,
    domain_id: DomainId,
    amount: BalanceOf<T>,
    config: OperatorConfig<BalanceOf<T>>,
) -> Result<OperatorId, Error> {
    DomainStakingSummary::<T>::try_mutate(domain_id, |maybe_domain_stake_summary| {
        let operator_id = NextOperatorId::<T>::get();
        let next_operator_id = operator_id.checked_add(1).ok_or(Error::MaximumOperatorId)?;
        NextOperatorId::<T>::set(next_operator_id);

        OperatorIdOwner::<T>::insert(operator_id, operator_owner.clone());

        // reserve stake balance
        ensure!(
            amount >= T::MinOperatorStake::get(),
            Error::MinimumOperatorStake
        );

        freeze_account_balance_to_operator::<T>(&operator_owner, operator_id, amount)?;

        let domain_stake_summary = maybe_domain_stake_summary
            .as_mut()
            .ok_or(Error::DomainNotInitialized)?;

        let OperatorConfig {
            signing_key,
            minimum_nominator_stake,
            nomination_tax,
        } = config;

        let operator = Operator {
            signing_key,
            current_domain_id: domain_id,
            next_domain_id: domain_id,
            minimum_nominator_stake,
            nomination_tax,
            current_total_stake: Zero::zero(),
            current_epoch_rewards: Zero::zero(),
            total_shares: Zero::zero(),
            is_frozen: false,
        };
        Operators::<T>::insert(operator_id, operator);
        // update stake summary to include new operator for next epoch
        domain_stake_summary.next_operators.insert(operator_id);
        // update pending transfers
        PendingDeposits::<T>::insert(operator_id, operator_owner, amount);

        Ok(operator_id)
    })
}

pub(crate) fn do_nominate_operator<T: Config>(
    operator_id: OperatorId,
    nominator_id: T::AccountId,
    amount: BalanceOf<T>,
) -> Result<(), Error> {
    let operator = Operators::<T>::get(operator_id).ok_or(Error::UnknownOperator)?;

    ensure!(!operator.is_frozen, Error::OperatorFrozen);

    let updated_total_deposit = match PendingDeposits::<T>::get(operator_id, nominator_id.clone()) {
        None => amount,
        Some(existing_deposit) => existing_deposit
            .checked_add(&amount)
            .ok_or(Error::BalanceOverflow)?,
    };

    // if not a nominator, then ensure amount >= operator's minimum nominator stake amount
    if !Nominators::<T>::contains_key(operator_id, nominator_id.clone()) {
        ensure!(
            updated_total_deposit >= operator.minimum_nominator_stake,
            Error::MinimumNominatorStake
        );
    }

    freeze_account_balance_to_operator::<T>(&nominator_id, operator_id, amount)?;
    PendingDeposits::<T>::insert(operator_id, nominator_id, updated_total_deposit);

    Ok(())
}

pub(crate) fn freeze_account_balance_to_operator<T: Config>(
    who: &T::AccountId,
    operator_id: OperatorId,
    amount: BalanceOf<T>,
) -> Result<(), Error> {
    // ensure there is enough free balance to lock
    ensure!(
        T::Currency::reducible_balance(who, Preservation::Preserve, Fortitude::Polite) >= amount,
        Error::InsufficientBalance
    );

    let freeze_id = T::FreezeIdentifier::staking_freeze_id(operator_id);
    // lock any previous locked balance + new deposit
    let current_locked_balance = T::Currency::balance_frozen(&freeze_id, who);
    let balance_to_be_locked = current_locked_balance
        .checked_add(&amount)
        .ok_or(Error::BalanceOverflow)?;

    T::Currency::set_freeze(&freeze_id, who, balance_to_be_locked)
        .map_err(|_| Error::BalanceFreeze)?;

    Ok(())
}

pub(crate) fn do_switch_operator_domain<T: Config>(
    operator_owner: T::AccountId,
    operator_id: OperatorId,
    new_domain_id: DomainId,
) -> Result<DomainId, Error> {
    ensure!(
        OperatorIdOwner::<T>::get(operator_id) == Some(operator_owner),
        Error::NotOperatorOwner
    );

    ensure!(
        DomainStakingSummary::<T>::contains_key(new_domain_id),
        Error::DomainNotInitialized
    );

    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator.as_mut().ok_or(Error::UnknownOperator)?;

        ensure!(!operator.is_frozen, Error::OperatorFrozen);

        // noop when switch is for same domain
        if operator.current_domain_id == new_domain_id {
            return Ok(operator.current_domain_id);
        }

        // check if there is any ongoing pending switch, if so reject
        ensure!(
            operator.current_domain_id == operator.next_domain_id,
            Error::PendingOperatorSwitch
        );

        operator.next_domain_id = new_domain_id;

        // remove operator from next_operators from current domains.
        // operator is added to the next_operators of the new domain once the
        // current domain epoch is finished.
        DomainStakingSummary::<T>::try_mutate(
            operator.current_domain_id,
            |maybe_domain_stake_summary| {
                let stake_summary = maybe_domain_stake_summary
                    .as_mut()
                    .ok_or(Error::DomainNotInitialized)?;
                stake_summary.next_operators.remove(&operator_id);
                Ok(())
            },
        )?;

        PendingOperatorSwitches::<T>::append(operator.current_domain_id, operator_id);

        Ok(operator.current_domain_id)
    })
}

pub(crate) fn do_deregister_operator<T: Config>(
    operator_owner: T::AccountId,
    operator_id: OperatorId,
) -> Result<(), Error> {
    ensure!(
        OperatorIdOwner::<T>::get(operator_id) == Some(operator_owner),
        Error::NotOperatorOwner
    );

    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator.as_mut().ok_or(Error::UnknownOperator)?;

        ensure!(!operator.is_frozen, Error::OperatorFrozen);
        operator.is_frozen = true;

        PendingOperatorDeregistrations::<T>::append(operator.current_domain_id, operator_id);
        DomainStakingSummary::<T>::try_mutate(
            operator.current_domain_id,
            |maybe_domain_stake_summary| {
                let stake_summary = maybe_domain_stake_summary
                    .as_mut()
                    .ok_or(Error::DomainNotInitialized)?;

                stake_summary.next_operators.remove(&operator_id);
                Ok(())
            },
        )
    })
}

pub(crate) fn do_withdraw_stake<T: Config>(
    operator_id: OperatorId,
    nominator_id: NominatorId<T>,
    withdraw: Withdraw<BalanceOf<T>>,
) -> Result<(), Error> {
    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator.as_mut().ok_or(Error::UnknownOperator)?;
        ensure!(!operator.is_frozen, Error::OperatorFrozen);

        let nominator = Nominators::<T>::get(operator_id, nominator_id.clone())
            .ok_or(Error::UnknownNominator)?;

        let operator_owner =
            OperatorIdOwner::<T>::get(operator_id).ok_or(Error::UnknownOperator)?;

        let withdraw = match PendingWithdrawals::<T>::get(operator_id, nominator_id.clone()) {
            None => withdraw,
            Some(existing_withdraw) => match (existing_withdraw, withdraw) {
                (Withdraw::All, _) => {
                    // there is an existing full withdraw, error out
                    return Err(Error::ExistingFullWithdraw);
                }
                (_, Withdraw::All) => {
                    // there is exisiting withdrawal with specific amount,
                    // since the new intent is complete withdrawl, use this instead
                    Withdraw::All
                }
                (Withdraw::Some(previous_withdraw), Withdraw::Some(new_withdraw)) => {
                    // combine both withdrawls into single one
                    Withdraw::Some(
                        previous_withdraw
                            .checked_add(&new_withdraw)
                            .ok_or(Error::BalanceOverflow)?,
                    )
                }
            },
        };

        match withdraw {
            Withdraw::All => {
                // if nominator is the operator owner and trying to withdraw all, then error out
                if operator_owner == nominator_id {
                    return Err(Error::MinimumOperatorStake);
                }

                PendingWithdrawals::<T>::insert(operator_id, nominator_id, withdraw);
            }
            Withdraw::Some(withdraw_amount) => {
                if withdraw_amount.is_zero() {
                    return Ok(());
                }

                let total_stake = operator
                    .current_total_stake
                    .checked_add(&operator.current_epoch_rewards)
                    .ok_or(Error::BalanceOverflow)?;

                let nominator_share =
                    Perbill::from_rational(nominator.shares, operator.total_shares);

                let nominator_staked_amount = nominator_share.mul_floor(total_stake);

                let nominator_remaining_amount = nominator_staked_amount
                    .checked_sub(&withdraw_amount)
                    .ok_or(Error::BalanceUnderflow)?;

                if operator_owner == nominator_id {
                    // for operator owner, the remaining amount should not be less than MinimumOperatorStake,
                    if nominator_remaining_amount < T::MinOperatorStake::get() {
                        return Err(Error::MinimumOperatorStake);
                    }

                    PendingWithdrawals::<T>::insert(operator_id, nominator_id, withdraw);

                    // for just a nominator, if remaining amount falls below MinimumNominator stake, then withdraw all
                    // else withdraw the asked amount only
                } else if nominator_remaining_amount < operator.minimum_nominator_stake {
                    PendingWithdrawals::<T>::insert(operator_id, nominator_id, Withdraw::All);
                } else {
                    PendingWithdrawals::<T>::insert(operator_id, nominator_id, withdraw);
                }
            }
        }

        Ok(())
    })
}

/// Distribute the reward to the operators equally and drop any dust to treasury.
pub(crate) fn do_reward_operators<T: Config>(
    domain_id: DomainId,
    operators: IntoIter<OperatorId>,
    rewards: BalanceOf<T>,
) -> Result<(), Error> {
    DomainStakingSummary::<T>::mutate(domain_id, |maybe_stake_summary| {
        let stake_summary = maybe_stake_summary
            .as_mut()
            .ok_or(Error::DomainNotInitialized)?;

        let distribution = Perbill::from_rational(One::one(), operators.len() as u32);
        let reward_per_operator = distribution.mul_floor(rewards);
        for operator_id in operators {
            let total_reward = match stake_summary.current_epoch_rewards.get(&operator_id) {
                None => reward_per_operator,
                Some(rewards) => rewards
                    .checked_add(&reward_per_operator)
                    .ok_or(Error::BalanceOverflow)?,
            };

            stake_summary
                .current_epoch_rewards
                .insert(operator_id, total_reward);
        }

        // TODO: move remaining rewards to treasury

        Ok(())
    })
}

#[allow(dead_code)]
// TODO: remove once fraud proof is done
/// Freezes the slashed operators and moves the operator to be removed once the domain they are
/// operating finishes the epoch.
pub(crate) fn do_slash_operators<T: Config>(
    operator_ids: IntoIter<OperatorId>,
) -> Result<(), Error> {
    for operator_id in operator_ids {
        Operators::<T>::try_mutate(operator_id, |maybe_operator| {
            let operator = maybe_operator.as_mut().ok_or(Error::UnknownOperator)?;
            DomainStakingSummary::<T>::try_mutate(
                operator.current_domain_id,
                |maybe_domain_stake_summary| {
                    let stake_summary = maybe_domain_stake_summary
                        .as_mut()
                        .ok_or(Error::DomainNotInitialized)?;

                    operator.is_frozen = true;

                    stake_summary.next_operators.remove(&operator_id);

                    PendingSlashes::<T>::append(operator.current_domain_id, operator_id);

                    Ok(())
                },
            )
        })?
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::pallet::{
        DomainStakingSummary, NextOperatorId, Nominators, OperatorIdOwner, Operators,
        PendingDeposits, PendingNominatorUnlocks, PendingOperatorDeregistrations,
        PendingOperatorSwitches, PendingSlashes, PendingUnlocks, PendingWithdrawals,
    };
    use crate::staking::{
        do_slash_operators, Error as StakingError, Nominator, Operator, OperatorConfig,
        StakingSummary, Withdraw,
    };
    use crate::staking_epoch::{do_finalize_domain_current_epoch, do_unlock_pending_withdrawals};
    use crate::tests::{new_test_ext, RuntimeOrigin, Test};
    use crate::{BalanceOf, Error, NominatorId};
    use frame_support::traits::fungible::Mutate;
    use frame_support::{assert_err, assert_ok};
    use sp_core::{Pair, U256};
    use sp_domains::{DomainId, OperatorPair};
    use sp_runtime::traits::Zero;
    use std::collections::{BTreeMap, BTreeSet};
    use std::vec;
    use subspace_runtime_primitives::SSC;

    type Balances = pallet_balances::Pallet<Test>;
    type Domains = crate::Pallet<Test>;

    #[test]
    fn register_operator() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_free_balance = 1500 * SSC;
        let operator_stake = 1000 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            Balances::set_balance(&operator_account, operator_free_balance);
            assert!(Balances::usable_balance(operator_account) == operator_free_balance);

            DomainStakingSummary::<Test>::insert(
                domain_id,
                StakingSummary {
                    current_epoch_index: 0,
                    current_total_stake: 0,
                    current_operators: BTreeMap::new(),
                    next_operators: BTreeSet::new(),
                    current_epoch_rewards: BTreeMap::new(),
                },
            );

            let operator_config = OperatorConfig {
                signing_key: pair.public(),
                minimum_nominator_stake: 0,
                nomination_tax: Default::default(),
            };

            let res = Domains::register_operator(
                RuntimeOrigin::signed(operator_account),
                domain_id,
                operator_stake,
                operator_config.clone(),
            );
            assert_ok!(res);

            assert_eq!(NextOperatorId::<Test>::get(), 1);
            // operator_id should be 0 and be registered
            assert_eq!(OperatorIdOwner::<Test>::get(0).unwrap(), operator_account);
            assert_eq!(
                Operators::<Test>::get(0).unwrap(),
                Operator {
                    signing_key: pair.public(),
                    current_domain_id: domain_id,
                    next_domain_id: domain_id,
                    minimum_nominator_stake: 0,
                    nomination_tax: Default::default(),
                    current_total_stake: 0,
                    current_epoch_rewards: 0,
                    total_shares: 0,
                    is_frozen: false,
                }
            );
            let pending_deposit = PendingDeposits::<Test>::get(0, operator_account).unwrap();
            assert_eq!(pending_deposit, operator_stake);

            let stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert!(stake_summary.next_operators.contains(&0));

            assert_eq!(
                Balances::usable_balance(operator_account),
                operator_free_balance - operator_stake
            );

            // cannot use the locked funds to register a new operator
            let res = Domains::register_operator(
                RuntimeOrigin::signed(operator_account),
                domain_id,
                operator_stake,
                operator_config,
            );
            assert_err!(
                res,
                Error::<Test>::Staking(crate::staking::Error::InsufficientBalance)
            )
        });
    }

    #[test]
    fn nominate_operator() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_free_balance = 1500 * SSC;
        let operator_stake = 1000 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let nominator_account = 2;
        let nominator_free_balance = 150 * SSC;
        let nominator_stake = 100 * SSC;

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            Balances::set_balance(&operator_account, operator_free_balance);
            Balances::set_balance(&nominator_account, nominator_free_balance);
            assert!(Balances::usable_balance(nominator_account) == nominator_free_balance);

            DomainStakingSummary::<Test>::insert(
                domain_id,
                StakingSummary {
                    current_epoch_index: 0,
                    current_total_stake: 0,
                    current_operators: BTreeMap::new(),
                    next_operators: BTreeSet::new(),
                    current_epoch_rewards: BTreeMap::new(),
                },
            );

            let operator_config = OperatorConfig {
                signing_key: pair.public(),
                minimum_nominator_stake: 100 * SSC,
                nomination_tax: Default::default(),
            };

            let res = Domains::register_operator(
                RuntimeOrigin::signed(operator_account),
                domain_id,
                operator_stake,
                operator_config,
            );
            assert_ok!(res);

            let operator_id = 0;
            let res = Domains::nominate_operator(
                RuntimeOrigin::signed(nominator_account),
                operator_id,
                nominator_stake,
            );
            assert_ok!(res);

            let pending_deposit = PendingDeposits::<Test>::get(0, operator_account).unwrap();
            assert_eq!(pending_deposit, operator_stake);
            let pending_deposit = PendingDeposits::<Test>::get(0, nominator_account).unwrap();
            assert_eq!(pending_deposit, nominator_stake);

            assert_eq!(
                Balances::usable_balance(nominator_account),
                nominator_free_balance - nominator_stake
            );

            // another transfer with an existing transfer in place should lead to single
            let res = Domains::nominate_operator(
                RuntimeOrigin::signed(nominator_account),
                operator_id,
                40 * SSC,
            );
            assert_ok!(res);
            let pending_deposit = PendingDeposits::<Test>::get(0, nominator_account).unwrap();
            assert_eq!(pending_deposit, nominator_stake + 40 * SSC);
        });
    }

    #[test]
    fn switch_domain_operator() {
        let old_domain_id = DomainId::new(0);
        let new_domain_id = DomainId::new(1);
        let operator_account = 1;
        let operator_id = 1;
        let operator_stake = 200 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            DomainStakingSummary::<Test>::insert(
                old_domain_id,
                StakingSummary {
                    current_epoch_index: 0,
                    current_total_stake: 0,
                    current_operators: BTreeMap::from_iter(vec![(operator_id, operator_stake)]),
                    next_operators: BTreeSet::from_iter(vec![operator_id]),
                    current_epoch_rewards: BTreeMap::new(),
                },
            );

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

            OperatorIdOwner::<Test>::insert(operator_id, operator_account);
            Operators::<Test>::insert(
                operator_id,
                Operator {
                    signing_key: pair.public(),
                    current_domain_id: old_domain_id,
                    next_domain_id: old_domain_id,
                    minimum_nominator_stake: 100 * SSC,
                    nomination_tax: Default::default(),
                    current_total_stake: Zero::zero(),
                    current_epoch_rewards: Zero::zero(),
                    total_shares: Zero::zero(),
                    is_frozen: false,
                },
            );

            let res = Domains::switch_domain(
                RuntimeOrigin::signed(operator_account),
                operator_id,
                new_domain_id,
            );
            assert_ok!(res);

            let old_domain_stake_summary =
                DomainStakingSummary::<Test>::get(old_domain_id).unwrap();
            assert!(!old_domain_stake_summary
                .next_operators
                .contains(&operator_id));

            let new_domain_stake_summary =
                DomainStakingSummary::<Test>::get(new_domain_id).unwrap();
            assert!(!new_domain_stake_summary
                .next_operators
                .contains(&operator_id));

            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(operator.current_domain_id, old_domain_id);
            assert_eq!(operator.next_domain_id, new_domain_id);
            assert_eq!(
                PendingOperatorSwitches::<Test>::get(old_domain_id).unwrap(),
                vec![operator_id]
            );

            let res = Domains::switch_domain(
                RuntimeOrigin::signed(operator_account),
                operator_id,
                new_domain_id,
            );
            assert_err!(
                res,
                Error::<Test>::Staking(crate::staking::Error::PendingOperatorSwitch)
            )
        });
    }

    #[test]
    fn operator_deregistration() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_id = 1;
        let operator_stake = 200 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            DomainStakingSummary::<Test>::insert(
                domain_id,
                StakingSummary {
                    current_epoch_index: 0,
                    current_total_stake: 0,
                    current_operators: BTreeMap::from_iter(vec![(operator_id, operator_stake)]),
                    next_operators: BTreeSet::from_iter(vec![operator_id]),
                    current_epoch_rewards: BTreeMap::new(),
                },
            );

            OperatorIdOwner::<Test>::insert(operator_id, operator_account);
            Operators::<Test>::insert(
                operator_id,
                Operator {
                    signing_key: pair.public(),
                    current_domain_id: domain_id,
                    next_domain_id: domain_id,
                    minimum_nominator_stake: 100 * SSC,
                    nomination_tax: Default::default(),
                    current_total_stake: Zero::zero(),
                    current_epoch_rewards: Zero::zero(),
                    total_shares: Zero::zero(),
                    is_frozen: false,
                },
            );

            let res =
                Domains::deregister_operator(RuntimeOrigin::signed(operator_account), operator_id);
            assert_ok!(res);

            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert!(!domain_stake_summary.next_operators.contains(&operator_id));

            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert!(operator.is_frozen);

            assert!(PendingOperatorDeregistrations::<Test>::get(domain_id)
                .unwrap()
                .contains(&operator_id));

            // domain switch will not work since the operator is frozen
            let new_domain_id = DomainId::new(1);
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
            assert_err!(
                res,
                Error::<Test>::Staking(crate::staking::Error::OperatorFrozen)
            );

            // nominations will not work since the is frozen
            let nominator_account = 100;
            let nominator_stake = 100 * SSC;
            let res = Domains::nominate_operator(
                RuntimeOrigin::signed(nominator_account),
                operator_id,
                nominator_stake,
            );
            assert_err!(
                res,
                Error::<Test>::Staking(crate::staking::Error::OperatorFrozen)
            );
        });
    }

    type WithdrawWithResult = Vec<(Withdraw<BalanceOf<Test>>, Result<(), StakingError>)>;

    struct WithdrawParams {
        minimum_nominator_stake: BalanceOf<Test>,
        total_stake: BalanceOf<Test>,
        nominators: Vec<(NominatorId<Test>, BalanceOf<Test>)>,
        operator_reward: BalanceOf<Test>,
        nominator_id: NominatorId<Test>,
        withdraws: WithdrawWithResult,
        expected_withdraw: Option<Withdraw<BalanceOf<Test>>>,
    }

    fn withdraw_stake(params: WithdrawParams) {
        let WithdrawParams {
            minimum_nominator_stake,
            total_stake,
            nominators,
            operator_reward,
            nominator_id,
            withdraws,
            expected_withdraw,
        } = params;
        let domain_id = DomainId::new(0);
        let operator_account = 0;
        let operator_id = 0;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());
        let nominators = BTreeMap::from_iter(nominators);

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let operator_stake = nominators.get(&operator_id).cloned().unwrap();
            DomainStakingSummary::<Test>::insert(
                domain_id,
                StakingSummary {
                    current_epoch_index: 0,
                    current_total_stake: total_stake,
                    current_operators: BTreeMap::from_iter(vec![(operator_id, operator_stake)]),
                    next_operators: BTreeSet::from_iter(vec![operator_id]),
                    current_epoch_rewards: BTreeMap::new(),
                },
            );

            OperatorIdOwner::<Test>::insert(operator_id, operator_account);

            let mut total_shares = Zero::zero();
            for (nominator_id, shares) in nominators {
                Nominators::<Test>::insert(operator_id, nominator_id, Nominator { shares });
                total_shares += shares
            }

            Operators::<Test>::insert(
                operator_id,
                Operator {
                    signing_key: pair.public(),
                    current_domain_id: domain_id,
                    next_domain_id: domain_id,
                    minimum_nominator_stake,
                    nomination_tax: Default::default(),
                    current_total_stake: total_stake,
                    current_epoch_rewards: operator_reward,
                    total_shares,
                    is_frozen: false,
                },
            );

            for (withdraw, expected_result) in withdraws {
                let res = Domains::withdraw_stake(
                    RuntimeOrigin::signed(nominator_id),
                    operator_id,
                    withdraw,
                );
                assert_eq!(
                    res,
                    expected_result.map_err(|err| Error::<Test>::Staking(err).into())
                );
            }

            assert_eq!(
                PendingWithdrawals::<Test>::get(operator_id, nominator_id),
                expected_withdraw
            );

            if let Some(withdraw) = expected_withdraw {
                // finalize pending withdrawals
                let current_consensus_block = 100;
                let domain_block = 100;
                let expected_unlock_at =
                    current_consensus_block + crate::tests::StakeWithdrawalLockingPeriod::get();
                do_finalize_domain_current_epoch::<Test>(
                    domain_id,
                    domain_block,
                    current_consensus_block,
                )
                .unwrap();
                assert_eq!(
                    PendingWithdrawals::<Test>::get(operator_id, nominator_id),
                    None
                );

                let pending_unlocks_at =
                    PendingNominatorUnlocks::<Test>::get(operator_id, expected_unlock_at).unwrap();
                assert_eq!(pending_unlocks_at.len(), 1);
                assert_eq!(pending_unlocks_at[0].nominator_id, nominator_id);

                assert_eq!(
                    PendingUnlocks::<Test>::get(expected_unlock_at),
                    Some(BTreeSet::from_iter(vec![operator_id]))
                );

                let previous_usable_balance = Balances::usable_balance(nominator_id);
                do_unlock_pending_withdrawals::<Test>(expected_unlock_at).unwrap();

                let withdrew_amount = match withdraw {
                    Withdraw::All => {
                        let operator = Operators::<Test>::get(operator_id).unwrap();
                        total_stake + operator_reward - operator.current_total_stake
                    }
                    Withdraw::Some(withdrew_amount) => withdrew_amount,
                };

                assert_eq!(
                    Balances::usable_balance(nominator_id),
                    previous_usable_balance + withdrew_amount
                )
            }
        });
    }

    #[test]
    fn withdraw_stake_operator_all() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 0,
            withdraws: vec![(Withdraw::All, Err(StakingError::MinimumOperatorStake))],
            expected_withdraw: None,
        })
    }

    #[test]
    fn withdraw_stake_operator_below_minimum() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 0,
            withdraws: vec![(
                Withdraw::Some(65 * SSC),
                Err(StakingError::MinimumOperatorStake),
            )],
            expected_withdraw: None,
        })
    }

    #[test]
    fn withdraw_stake_operator_below_minimum_no_rewards() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 0,
            withdraws: vec![(
                Withdraw::Some(51 * SSC),
                Err(StakingError::MinimumOperatorStake),
            )],
            expected_withdraw: None,
        })
    }

    #[test]
    fn withdraw_stake_operator_above_minimum() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 0,
            withdraws: vec![(Withdraw::Some(64 * SSC), Ok(()))],
            expected_withdraw: Some(Withdraw::Some(64 * SSC)),
        })
    }

    #[test]
    fn withdraw_stake_operator_above_minimum_multiple_withdraws_error() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 0,
            withdraws: vec![
                (Withdraw::Some(60 * SSC), Ok(())),
                (
                    Withdraw::Some(5 * SSC),
                    Err(StakingError::MinimumOperatorStake),
                ),
            ],
            expected_withdraw: Some(Withdraw::Some(60 * SSC)),
        })
    }

    #[test]
    fn withdraw_stake_operator_above_minimum_multiple_withdraws() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 0,
            withdraws: vec![
                (Withdraw::Some(60 * SSC), Ok(())),
                (Withdraw::Some(4 * SSC), Ok(())),
            ],
            expected_withdraw: Some(Withdraw::Some(64 * SSC)),
        })
    }

    #[test]
    fn withdraw_stake_operator_above_minimum_no_rewards() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 0,
            withdraws: vec![(Withdraw::Some(49 * SSC), Ok(()))],
            expected_withdraw: Some(Withdraw::Some(49 * SSC)),
        })
    }

    #[test]
    fn withdraw_stake_nominator_below_minimum() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![(Withdraw::Some(45 * SSC), Ok(()))],
            expected_withdraw: Some(Withdraw::All),
        })
    }

    #[test]
    fn withdraw_stake_nominator_below_minimum_no_reward() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 1,
            withdraws: vec![(Withdraw::Some(45 * SSC), Ok(()))],
            expected_withdraw: Some(Withdraw::All),
        })
    }

    #[test]
    fn withdraw_stake_nominator_above_minimum() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![(Withdraw::Some(44 * SSC), Ok(()))],
            expected_withdraw: Some(Withdraw::Some(44 * SSC)),
        })
    }

    #[test]
    fn withdraw_stake_nominator_above_minimum_multiple_withdraw_all() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![
                (Withdraw::Some(40 * SSC), Ok(())),
                (Withdraw::Some(5 * SSC), Ok(())),
            ],
            expected_withdraw: Some(Withdraw::All),
        })
    }

    #[test]
    fn withdraw_stake_nominator_withdraw_all() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![(Withdraw::All, Ok(()))],
            expected_withdraw: Some(Withdraw::All),
        })
    }

    #[test]
    fn withdraw_stake_nominator_withdraw_all_multiple_withdraws_error() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![
                (Withdraw::All, Ok(())),
                (
                    Withdraw::Some(10 * SSC),
                    Err(StakingError::ExistingFullWithdraw),
                ),
            ],
            expected_withdraw: Some(Withdraw::All),
        })
    }

    #[test]
    fn withdraw_stake_nominator_above_minimum_no_rewards() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 1,
            withdraws: vec![(Withdraw::Some(39 * SSC), Ok(()))],
            expected_withdraw: Some(Withdraw::Some(39 * SSC)),
        })
    }

    #[test]
    fn withdraw_stake_nominator_zero_amount() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            total_stake: 210 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 1,
            withdraws: vec![(Withdraw::Some(0), Ok(()))],
            expected_withdraw: None,
        })
    }

    #[test]
    fn slash_operator() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_id = 1;
        let operator_stake = 200 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            DomainStakingSummary::<Test>::insert(
                domain_id,
                StakingSummary {
                    current_epoch_index: 0,
                    current_total_stake: 0,
                    current_operators: BTreeMap::from_iter(vec![(operator_id, operator_stake)]),
                    next_operators: BTreeSet::from_iter(vec![operator_id]),
                    current_epoch_rewards: BTreeMap::new(),
                },
            );

            OperatorIdOwner::<Test>::insert(operator_id, operator_account);
            Operators::<Test>::insert(
                operator_id,
                Operator {
                    signing_key: pair.public(),
                    current_domain_id: domain_id,
                    next_domain_id: domain_id,
                    minimum_nominator_stake: 100 * SSC,
                    nomination_tax: Default::default(),
                    current_total_stake: Zero::zero(),
                    current_epoch_rewards: Zero::zero(),
                    total_shares: Zero::zero(),
                    is_frozen: false,
                },
            );

            do_slash_operators::<Test>(vec![operator_id].into_iter()).unwrap();

            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert!(!domain_stake_summary.next_operators.contains(&operator_id));

            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert!(operator.is_frozen);

            assert!(PendingSlashes::<Test>::get(domain_id)
                .unwrap()
                .contains(&operator_id));
        });
    }
}

//! Staking for domains

use crate::pallet::{
    DomainRegistry, DomainStakingSummary, NextOperatorId, NominatorCount, Nominators,
    OperatorIdOwner, OperatorSigningKey, Operators, PendingDeposits, PendingNominatorUnlocks,
    PendingOperatorDeregistrations, PendingOperatorSwitches, PendingOperatorUnlocks,
    PendingSlashes, PendingStakingOperationCount, PendingWithdrawals,
};
use crate::staking_epoch::{mint_funds, PendingNominatorUnlock, PendingOperatorSlashInfo};
use crate::{
    BalanceOf, Config, DomainBlockNumberFor, Event, HoldIdentifier, NominatorId, Pallet,
    ReceiptHashFor, SlashedReason,
};
use codec::{Decode, Encode};
use frame_support::traits::fungible::{Inspect, MutateHold};
use frame_support::traits::tokens::{Fortitude, Preservation};
use frame_support::{ensure, PalletError};
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::{DomainId, EpochIndex, OperatorId, OperatorPublicKey, ZERO_OPERATOR_SIGNING_KEY};
use sp_runtime::traits::{CheckedAdd, CheckedSub, One, Zero};
use sp_runtime::{Perbill, Percent};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::btree_set::BTreeSet;
use sp_std::iter::Iterator;
use sp_std::vec::{IntoIter, Vec};

/// Type that represents an operator status.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum OperatorStatus {
    Registered,
    Deregistered,
    Slashed,
}

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
    pub status: OperatorStatus,
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
    OperatorNotRegistered,
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
    TryDepositWithPendingWithdraw,
    TryWithdrawWithPendingDeposit,
    TooManyPendingStakingOperation,
    OperatorNotAllowed,
    InvalidOperatorSigningKey,
    MaximumNominators,
    DuplicateOperatorSigningKey,
}

// Increase `PendingStakingOperationCount` by one and check if the `MaxPendingStakingOperation`
// limit is exceeded
fn note_pending_staking_operation<T: Config>(domain_id: DomainId) -> Result<(), Error> {
    let pending_op_count = PendingStakingOperationCount::<T>::get(domain_id);

    ensure!(
        pending_op_count < T::MaxPendingStakingOperation::get(),
        Error::TooManyPendingStakingOperation
    );

    PendingStakingOperationCount::<T>::set(domain_id, pending_op_count.saturating_add(1));

    Ok(())
}

pub(crate) fn do_register_operator<T: Config>(
    operator_owner: T::AccountId,
    domain_id: DomainId,
    amount: BalanceOf<T>,
    config: OperatorConfig<BalanceOf<T>>,
) -> Result<(OperatorId, EpochIndex), Error> {
    note_pending_staking_operation::<T>(domain_id)?;

    DomainStakingSummary::<T>::try_mutate(domain_id, |maybe_domain_stake_summary| {
        ensure!(
            config.signing_key != OperatorPublicKey::from(ZERO_OPERATOR_SIGNING_KEY),
            Error::InvalidOperatorSigningKey
        );

        ensure!(
            !OperatorSigningKey::<T>::contains_key(config.signing_key.clone()),
            Error::DuplicateOperatorSigningKey
        );

        ensure!(
            config.minimum_nominator_stake >= T::MinNominatorStake::get(),
            Error::MinimumNominatorStake
        );

        let domain_obj = DomainRegistry::<T>::get(domain_id).ok_or(Error::DomainNotInitialized)?;
        ensure!(
            domain_obj
                .domain_config
                .operator_allow_list
                .is_operator_allowed(&operator_owner),
            Error::OperatorNotAllowed
        );

        let operator_id = NextOperatorId::<T>::get();
        let next_operator_id = operator_id.checked_add(1).ok_or(Error::MaximumOperatorId)?;
        NextOperatorId::<T>::set(next_operator_id);

        OperatorIdOwner::<T>::insert(operator_id, operator_owner.clone());

        // reserve stake balance
        ensure!(
            amount >= T::MinOperatorStake::get(),
            Error::MinimumOperatorStake
        );

        hold_pending_deposit::<T>(&operator_owner, operator_id, amount)?;

        let domain_stake_summary = maybe_domain_stake_summary
            .as_mut()
            .ok_or(Error::DomainNotInitialized)?;

        let OperatorConfig {
            signing_key,
            minimum_nominator_stake,
            nomination_tax,
        } = config;

        let operator = Operator {
            signing_key: signing_key.clone(),
            current_domain_id: domain_id,
            next_domain_id: domain_id,
            minimum_nominator_stake,
            nomination_tax,
            current_total_stake: Zero::zero(),
            current_epoch_rewards: Zero::zero(),
            total_shares: Zero::zero(),
            status: OperatorStatus::Registered,
        };
        Operators::<T>::insert(operator_id, operator);
        OperatorSigningKey::<T>::insert(signing_key, operator_id);
        // update stake summary to include new operator for next epoch
        domain_stake_summary.next_operators.insert(operator_id);
        // update pending transfers
        PendingDeposits::<T>::insert(operator_id, operator_owner, amount);

        Ok((operator_id, domain_stake_summary.current_epoch_index))
    })
}

pub(crate) fn do_nominate_operator<T: Config>(
    operator_id: OperatorId,
    nominator_id: T::AccountId,
    amount: BalanceOf<T>,
) -> Result<(), Error> {
    let operator = Operators::<T>::get(operator_id).ok_or(Error::UnknownOperator)?;

    note_pending_staking_operation::<T>(operator.current_domain_id)?;

    ensure!(
        operator.status == OperatorStatus::Registered,
        Error::OperatorNotRegistered
    );

    ensure!(
        !PendingWithdrawals::<T>::contains_key(operator_id, nominator_id.clone()),
        Error::TryDepositWithPendingWithdraw,
    );

    let (updated_total_deposit, first_nomination) =
        match PendingDeposits::<T>::get(operator_id, nominator_id.clone()) {
            None => (amount, true),
            Some(existing_deposit) => (
                existing_deposit
                    .checked_add(&amount)
                    .ok_or(Error::BalanceOverflow)?,
                false,
            ),
        };

    // if not a nominator, then ensure
    // - amount >= operator's minimum nominator stake amount.
    // - nominator count does not exceed max nominators.
    // - if first nomination, then increment the nominator count.
    if !Nominators::<T>::contains_key(operator_id, nominator_id.clone()) {
        ensure!(
            updated_total_deposit >= operator.minimum_nominator_stake,
            Error::MinimumNominatorStake
        );

        if first_nomination {
            NominatorCount::<T>::try_mutate(operator_id, |count| {
                *count += 1;
                ensure!(*count <= T::MaxNominators::get(), Error::MaximumNominators);
                Ok(())
            })?;
        }
    }

    hold_pending_deposit::<T>(&nominator_id, operator_id, amount)?;
    PendingDeposits::<T>::insert(operator_id, nominator_id, updated_total_deposit);

    Ok(())
}

pub(crate) fn hold_pending_deposit<T: Config>(
    who: &T::AccountId,
    operator_id: OperatorId,
    amount: BalanceOf<T>,
) -> Result<(), Error> {
    // ensure there is enough free balance to lock
    ensure!(
        T::Currency::reducible_balance(who, Preservation::Preserve, Fortitude::Polite) >= amount,
        Error::InsufficientBalance
    );

    let pending_deposit_hold_id = T::HoldIdentifier::staking_pending_deposit(operator_id);
    T::Currency::hold(&pending_deposit_hold_id, who, amount).map_err(|_| Error::BalanceFreeze)?;

    Ok(())
}

pub(crate) fn do_switch_operator_domain<T: Config>(
    operator_owner: T::AccountId,
    operator_id: OperatorId,
    new_domain_id: DomainId,
) -> Result<DomainId, Error> {
    let domain_obj = DomainRegistry::<T>::get(new_domain_id).ok_or(Error::DomainNotInitialized)?;
    ensure!(
        domain_obj
            .domain_config
            .operator_allow_list
            .is_operator_allowed(&operator_owner),
        Error::OperatorNotAllowed
    );

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

        note_pending_staking_operation::<T>(operator.current_domain_id)?;

        ensure!(
            operator.status == OperatorStatus::Registered,
            Error::OperatorNotRegistered
        );

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

        note_pending_staking_operation::<T>(operator.current_domain_id)?;

        ensure!(
            operator.status == OperatorStatus::Registered,
            Error::OperatorNotRegistered
        );
        operator.status = OperatorStatus::Deregistered;

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
    ensure!(
        !PendingDeposits::<T>::contains_key(operator_id, nominator_id.clone()),
        Error::TryWithdrawWithPendingDeposit,
    );
    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator.as_mut().ok_or(Error::UnknownOperator)?;

        note_pending_staking_operation::<T>(operator.current_domain_id)?;

        ensure!(
            operator.status == OperatorStatus::Registered,
            Error::OperatorNotRegistered
        );

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

                // reduce nominator count if withdraw all
                NominatorCount::<T>::mutate(operator_id, |count| {
                    *count -= 1;
                });
            }
            Withdraw::Some(withdraw_amount) => {
                if withdraw_amount.is_zero() {
                    return Ok(());
                }

                let domain_stake_summary =
                    DomainStakingSummary::<T>::get(operator.current_domain_id)
                        .ok_or(Error::DomainNotInitialized)?;

                let total_stake = match domain_stake_summary.current_epoch_rewards.get(&operator_id)
                {
                    None => operator.current_total_stake,
                    Some(rewards) => {
                        let operator_tax = operator.nomination_tax.mul_floor(*rewards);
                        operator
                            .current_total_stake
                            .checked_add(rewards)
                            .ok_or(Error::BalanceOverflow)?
                            // deduct operator tax
                            .checked_sub(&operator_tax)
                            .ok_or(Error::BalanceUnderflow)?
                    }
                };

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
                    // reduce nominator count if withdraw all
                    NominatorCount::<T>::mutate(operator_id, |count| {
                        *count -= 1;
                    });
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
    mut rewards: BalanceOf<T>,
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

            Pallet::<T>::deposit_event(Event::OperatorRewarded {
                operator_id,
                reward: reward_per_operator,
            });

            rewards = rewards
                .checked_sub(&reward_per_operator)
                .ok_or(Error::BalanceUnderflow)?;
        }

        mint_funds::<T>(&T::TreasuryAccount::get(), rewards)
    })
}

/// Freezes the slashed operators and moves the operator to be removed once the domain they are
/// operating finishes the epoch.
pub(crate) fn do_slash_operators<T: Config, Iter>(operator_ids: Iter) -> Result<(), Error>
where
    Iter: Iterator<
        Item = (
            OperatorId,
            SlashedReason<DomainBlockNumberFor<T>, ReceiptHashFor<T>>,
        ),
    >,
{
    for (operator_id, reason) in operator_ids {
        Operators::<T>::try_mutate(operator_id, |maybe_operator| {
            let operator = match maybe_operator.as_mut() {
                // If the operator is already slashed and removed due to fraud proof, when the operator
                // is slash again due to invalid bundle, which happen after the ER is confirmed, we can
                // not find the operator here thus just return.
                None => return Ok(()),
                Some(operator) => operator,
            };
            let mut pending_slashes =
                PendingSlashes::<T>::get(operator.current_domain_id).unwrap_or_default();

            if pending_slashes.contains_key(&operator_id) {
                return Ok(());
            }

            DomainStakingSummary::<T>::try_mutate(
                operator.current_domain_id,
                |maybe_domain_stake_summary| {
                    let stake_summary = maybe_domain_stake_summary
                        .as_mut()
                        .ok_or(Error::DomainNotInitialized)?;

                    // slash and remove operator from next epoch set
                    operator.status = OperatorStatus::Slashed;
                    stake_summary.next_operators.remove(&operator_id);

                    // remove any current operator switches
                    PendingOperatorSwitches::<T>::mutate(
                        operator.current_domain_id,
                        |maybe_switching_operators| {
                            if let Some(switching_operators) = maybe_switching_operators.as_mut() {
                                switching_operators.remove(&operator_id);
                            }
                        },
                    );

                    // remove any current operator de-registrations
                    PendingOperatorDeregistrations::<T>::mutate(
                        operator.current_domain_id,
                        |maybe_deregistering_operators| {
                            if let Some(deregistering_operators) =
                                maybe_deregistering_operators.as_mut()
                            {
                                deregistering_operators.remove(&operator_id);
                            }
                        },
                    );

                    // remove from operator unlocks
                    PendingOperatorUnlocks::<T>::mutate(|unlocking_operators| {
                        unlocking_operators.remove(&operator_id)
                    });

                    // remove from nominator unlocks
                    let unlocking_nominators =
                        PendingNominatorUnlocks::<T>::drain_prefix(operator_id)
                            .flat_map(|(_, nominator_unlocks)| nominator_unlocks)
                            .collect::<Vec<PendingNominatorUnlock<NominatorId<T>, BalanceOf<T>>>>();

                    // update pending slashed
                    pending_slashes.insert(
                        operator_id,
                        PendingOperatorSlashInfo {
                            unlocking_nominators,
                        },
                    );

                    PendingSlashes::<T>::insert(operator.current_domain_id, pending_slashes);
                    Pallet::<T>::deposit_event(Event::OperatorSlashed {
                        operator_id,
                        reason,
                    });
                    Ok(())
                },
            )
        })?
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::domain_registry::{DomainConfig, DomainObject};
    use crate::pallet::{
        Config, DomainRegistry, DomainStakingSummary, NextOperatorId, NominatorCount,
        OperatorIdOwner, Operators, PendingDeposits, PendingNominatorUnlocks,
        PendingOperatorDeregistrations, PendingOperatorSwitches, PendingSlashes,
        PendingStakingOperationCount, PendingUnlocks, PendingWithdrawals,
    };
    use crate::staking::{
        do_nominate_operator, do_reward_operators, do_slash_operators, do_withdraw_stake,
        Error as StakingError, Operator, OperatorConfig, OperatorStatus, StakingSummary, Withdraw,
    };
    use crate::staking_epoch::{
        do_finalize_domain_current_epoch, do_finalize_slashed_operators,
        do_unlock_pending_withdrawals, PendingNominatorUnlock,
    };
    use crate::tests::{new_test_ext, ExistentialDeposit, RuntimeOrigin, Test};
    use crate::{BalanceOf, Error, NominatorId, SlashedReason};
    use frame_support::traits::fungible::Mutate;
    use frame_support::traits::Currency;
    use frame_support::weights::Weight;
    use frame_support::{assert_err, assert_ok};
    use sp_core::{Pair, U256};
    use sp_domains::{
        DomainId, OperatorAllowList, OperatorId, OperatorPair, OperatorPublicKey,
        ZERO_OPERATOR_SIGNING_KEY,
    };
    use sp_runtime::traits::Zero;
    use std::collections::{BTreeMap, BTreeSet};
    use std::vec;
    use subspace_runtime_primitives::SSC;

    type Balances = pallet_balances::Pallet<Test>;
    type Domains = crate::Pallet<Test>;

    pub(crate) fn register_operator(
        domain_id: DomainId,
        operator_account: <Test as frame_system::Config>::AccountId,
        operator_free_balance: BalanceOf<Test>,
        operator_stake: BalanceOf<Test>,
        minimum_nominator_stake: BalanceOf<Test>,
        signing_key: OperatorPublicKey,
        mut nominators: BTreeMap<NominatorId<Test>, (BalanceOf<Test>, BalanceOf<Test>)>,
    ) -> (OperatorId, OperatorConfig<BalanceOf<Test>>) {
        nominators.insert(operator_account, (operator_free_balance, operator_stake));
        for nominator in &nominators {
            Balances::set_balance(nominator.0, nominator.1 .0);
            assert_eq!(Balances::usable_balance(nominator.0), nominator.1 .0);
        }
        nominators.remove(&operator_account);

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

        DomainRegistry::<Test>::insert(domain_id, domain_obj);

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
            signing_key,
            minimum_nominator_stake,
            nomination_tax: Default::default(),
        };

        let res = Domains::register_operator(
            RuntimeOrigin::signed(operator_account),
            domain_id,
            operator_stake,
            operator_config.clone(),
        );
        assert_ok!(res);

        let operator_id = 0;
        let mut expected_nominator_count = 0;
        for nominator in nominators {
            if nominator.1 .1.is_zero() {
                continue;
            }

            expected_nominator_count += 1;
            let res = Domains::nominate_operator(
                RuntimeOrigin::signed(nominator.0),
                operator_id,
                nominator.1 .1,
            );
            assert_ok!(res);
        }

        let nominator_count = NominatorCount::<Test>::get(operator_id) as usize;
        assert_eq!(nominator_count, expected_nominator_count);

        (operator_id, operator_config)
    }

    #[test]
    fn test_register_operator_invalid_signing_key() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let operator_config = OperatorConfig {
                signing_key: OperatorPublicKey::from(ZERO_OPERATOR_SIGNING_KEY),
                minimum_nominator_stake: Default::default(),
                nomination_tax: Default::default(),
            };

            let res = Domains::register_operator(
                RuntimeOrigin::signed(operator_account),
                domain_id,
                Default::default(),
                operator_config,
            );
            assert_err!(
                res,
                Error::<Test>::Staking(StakingError::InvalidOperatorSigningKey)
            );
        });
    }

    #[test]
    fn test_register_operator_minimum_nominator_stake() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let operator_config = OperatorConfig {
                signing_key: pair.public(),
                minimum_nominator_stake: Default::default(),
                nomination_tax: Default::default(),
            };

            let res = Domains::register_operator(
                RuntimeOrigin::signed(operator_account),
                domain_id,
                Default::default(),
                operator_config,
            );
            assert_err!(
                res,
                Error::<Test>::Staking(StakingError::MinimumNominatorStake)
            );
        });
    }

    #[test]
    fn test_register_operator() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_free_balance = 1500 * SSC;
        let operator_stake = 1000 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let (operator_id, mut operator_config) = register_operator(
                domain_id,
                operator_account,
                operator_free_balance,
                operator_stake,
                SSC,
                pair.public(),
                BTreeMap::new(),
            );

            assert_eq!(NextOperatorId::<Test>::get(), 1);
            // operator_id should be 0 and be registered
            assert_eq!(
                OperatorIdOwner::<Test>::get(operator_id).unwrap(),
                operator_account
            );
            assert_eq!(
                Operators::<Test>::get(operator_id).unwrap(),
                Operator {
                    signing_key: pair.public(),
                    current_domain_id: domain_id,
                    next_domain_id: domain_id,
                    minimum_nominator_stake: SSC,
                    nomination_tax: Default::default(),
                    current_total_stake: operator_stake,
                    current_epoch_rewards: 0,
                    total_shares: operator_stake,
                    status: OperatorStatus::Registered,
                }
            );

            let stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert!(stake_summary.next_operators.contains(&operator_id));

            assert_eq!(
                Balances::usable_balance(operator_account),
                operator_free_balance - operator_stake - ExistentialDeposit::get()
            );

            // cannot register with same operator key
            let res = Domains::register_operator(
                RuntimeOrigin::signed(operator_account),
                domain_id,
                operator_stake,
                operator_config.clone(),
            );
            assert_err!(
                res,
                Error::<Test>::Staking(crate::staking::Error::DuplicateOperatorSigningKey)
            );

            // cannot use the locked funds to register a new operator
            let new_pair = OperatorPair::from_seed(&U256::from(1u32).into());
            operator_config.signing_key = new_pair.public();
            let res = Domains::register_operator(
                RuntimeOrigin::signed(operator_account),
                domain_id,
                operator_stake,
                operator_config,
            );
            assert_err!(
                res,
                Error::<Test>::Staking(crate::staking::Error::InsufficientBalance)
            );

            let nominator_count = NominatorCount::<Test>::get(operator_id);
            assert_eq!(nominator_count, 0);
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
            let (operator_id, _) = register_operator(
                domain_id,
                operator_account,
                operator_free_balance,
                operator_stake,
                10 * SSC,
                pair.public(),
                BTreeMap::from_iter(vec![(
                    nominator_account,
                    (nominator_free_balance, nominator_stake),
                )]),
            );

            let pending_deposit = PendingDeposits::<Test>::get(0, nominator_account).unwrap();
            assert_eq!(pending_deposit, nominator_stake);

            assert_eq!(
                Balances::usable_balance(nominator_account),
                nominator_free_balance - nominator_stake - ExistentialDeposit::get()
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

            let nominator_count = NominatorCount::<Test>::get(operator_id);
            assert_eq!(nominator_count, 1);
        });
    }

    #[test]
    fn nominate_operator_max_nominators() {
        let domain_id = DomainId::new(0);
        let operator_account = 0;
        let operator_free_balance = 1500 * SSC;
        let operator_stake = 1000 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let nominator_account = 7;
        let nominator_free_balance = 150 * SSC;
        let nominator_stake = 100 * SSC;

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let (operator_id, _) = register_operator(
                domain_id,
                operator_account,
                operator_free_balance,
                operator_stake,
                10 * SSC,
                pair.public(),
                BTreeMap::from_iter(vec![
                    (1, (nominator_free_balance, nominator_stake)),
                    (2, (nominator_free_balance, nominator_stake)),
                    (3, (nominator_free_balance, nominator_stake)),
                    (4, (nominator_free_balance, nominator_stake)),
                    (5, (nominator_free_balance, nominator_stake)),
                ]),
            );

            Balances::set_balance(&nominator_account, nominator_free_balance);
            let nominator_count = NominatorCount::<Test>::get(operator_id);

            // nomination should fail since Max nominators number has reached.
            let res = Domains::nominate_operator(
                RuntimeOrigin::signed(nominator_account),
                operator_id,
                40 * SSC,
            );
            assert_err!(
                res,
                Error::<Test>::Staking(crate::staking::Error::MaximumNominators)
            );

            // should not update nominator count.
            assert_eq!(nominator_count, NominatorCount::<Test>::get(operator_id));
        });
    }

    #[test]
    fn switch_domain_operator() {
        let old_domain_id = DomainId::new(0);
        let new_domain_id = DomainId::new(1);
        let operator_account = 1;
        let operator_free_balance = 250 * SSC;
        let operator_stake = 200 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let (operator_id, _) = register_operator(
                old_domain_id,
                operator_account,
                operator_free_balance,
                operator_stake,
                SSC,
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
                BTreeSet::from_iter(vec![operator_id])
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
        let operator_stake = 200 * SSC;
        let operator_free_balance = 250 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let (operator_id, _) = register_operator(
                domain_id,
                operator_account,
                operator_free_balance,
                operator_stake,
                SSC,
                pair.public(),
                BTreeMap::new(),
            );

            let res =
                Domains::deregister_operator(RuntimeOrigin::signed(operator_account), operator_id);
            assert_ok!(res);

            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert!(!domain_stake_summary.next_operators.contains(&operator_id));

            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(operator.status, OperatorStatus::Deregistered);

            assert!(PendingOperatorDeregistrations::<Test>::get(domain_id)
                .unwrap()
                .contains(&operator_id));

            // domain switch will not work since the operator is frozen
            let new_domain_id = DomainId::new(1);
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
            assert_err!(
                res,
                Error::<Test>::Staking(crate::staking::Error::OperatorNotRegistered)
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
                Error::<Test>::Staking(crate::staking::Error::OperatorNotRegistered)
            );
        });
    }

    type WithdrawWithResult = Vec<(Withdraw<BalanceOf<Test>>, Result<(), StakingError>)>;

    struct WithdrawParams {
        minimum_nominator_stake: BalanceOf<Test>,
        nominators: Vec<(NominatorId<Test>, BalanceOf<Test>)>,
        operator_reward: BalanceOf<Test>,
        nominator_id: NominatorId<Test>,
        withdraws: WithdrawWithResult,
        expected_withdraw: Option<Withdraw<BalanceOf<Test>>>,
        expected_nominator_count_reduced_by: u32,
    }

    fn withdraw_stake(params: WithdrawParams) {
        let WithdrawParams {
            minimum_nominator_stake,
            nominators,
            operator_reward,
            nominator_id,
            withdraws,
            expected_withdraw,
            expected_nominator_count_reduced_by,
        } = params;
        let domain_id = DomainId::new(0);
        let operator_account = 0;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut nominators = BTreeMap::from_iter(
            nominators
                .into_iter()
                .map(|(id, bal)| (id, (bal + ExistentialDeposit::get(), bal)))
                .collect::<Vec<(NominatorId<Test>, (BalanceOf<Test>, BalanceOf<Test>))>>(),
        );

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let (operator_free_balance, operator_stake) =
                nominators.remove(&operator_account).unwrap();
            let (operator_id, _) = register_operator(
                domain_id,
                operator_account,
                operator_free_balance,
                operator_stake,
                minimum_nominator_stake,
                pair.public(),
                nominators,
            );

            do_finalize_domain_current_epoch::<Test>(domain_id, Zero::zero()).unwrap();

            if !operator_reward.is_zero() {
                do_reward_operators::<Test>(
                    domain_id,
                    vec![operator_id].into_iter(),
                    operator_reward,
                )
                .unwrap();
            }

            let nominator_count = NominatorCount::<Test>::get(operator_id);
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
                let domain_block = 100;
                let expected_unlock_at =
                    domain_block + crate::tests::StakeWithdrawalLockingPeriod::get();
                do_finalize_domain_current_epoch::<Test>(domain_id, domain_block).unwrap();
                assert_eq!(
                    PendingWithdrawals::<Test>::get(operator_id, nominator_id),
                    None
                );

                let pending_unlocks_at =
                    PendingNominatorUnlocks::<Test>::get(operator_id, expected_unlock_at).unwrap();
                assert_eq!(pending_unlocks_at.len(), 1);
                assert_eq!(pending_unlocks_at[0].nominator_id, nominator_id);

                assert_eq!(
                    PendingUnlocks::<Test>::get((domain_id, expected_unlock_at)),
                    Some(BTreeSet::from_iter(vec![operator_id]))
                );

                let previous_usable_balance = Balances::usable_balance(nominator_id);

                do_unlock_pending_withdrawals::<Test>(domain_id, expected_unlock_at).unwrap();

                let mut withdrew_amount = pending_unlocks_at[0].balance;
                if withdraw == Withdraw::All {
                    // since there are no holds, ED is not considered untouchable
                    withdrew_amount += ExistentialDeposit::get();
                }
                assert_eq!(
                    Balances::usable_balance(nominator_id),
                    previous_usable_balance + withdrew_amount
                )
            }

            let new_nominator_count = NominatorCount::<Test>::get(operator_id);
            assert_eq!(
                nominator_count - expected_nominator_count_reduced_by,
                new_nominator_count
            );
        });
    }

    #[test]
    fn withdraw_stake_operator_all() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 0,
            withdraws: vec![(Withdraw::All, Err(StakingError::MinimumOperatorStake))],
            expected_withdraw: None,
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_operator_below_minimum() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 0,
            withdraws: vec![(
                Withdraw::Some(65 * SSC),
                Err(StakingError::MinimumOperatorStake),
            )],
            expected_withdraw: None,
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_operator_below_minimum_no_rewards() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 0,
            withdraws: vec![(
                Withdraw::Some(51 * SSC),
                Err(StakingError::MinimumOperatorStake),
            )],
            expected_withdraw: None,
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_operator_above_minimum() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 0,
            withdraws: vec![(Withdraw::Some(64 * SSC), Ok(()))],
            expected_withdraw: Some(Withdraw::Some(64 * SSC)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_operator_above_minimum_multiple_withdraws_error() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
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
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_operator_above_minimum_multiple_withdraws() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 0,
            withdraws: vec![
                (Withdraw::Some(60 * SSC), Ok(())),
                (Withdraw::Some(4 * SSC), Ok(())),
            ],
            expected_withdraw: Some(Withdraw::Some(64 * SSC)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_operator_above_minimum_no_rewards() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 0,
            withdraws: vec![(Withdraw::Some(49 * SSC), Ok(()))],
            expected_withdraw: Some(Withdraw::Some(49 * SSC)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_nominator_below_minimum() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![(Withdraw::Some(45 * SSC), Ok(()))],
            expected_withdraw: Some(Withdraw::All),
            expected_nominator_count_reduced_by: 1,
        })
    }

    #[test]
    fn withdraw_stake_nominator_below_minimum_no_reward() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 1,
            withdraws: vec![(Withdraw::Some(45 * SSC), Ok(()))],
            expected_withdraw: Some(Withdraw::All),
            expected_nominator_count_reduced_by: 1,
        })
    }

    #[test]
    fn withdraw_stake_nominator_above_minimum() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![(Withdraw::Some(44 * SSC), Ok(()))],
            expected_withdraw: Some(Withdraw::Some(44 * SSC)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_nominator_above_minimum_multiple_withdraw_all() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![
                (Withdraw::Some(40 * SSC), Ok(())),
                (Withdraw::Some(5 * SSC), Ok(())),
            ],
            expected_withdraw: Some(Withdraw::All),
            expected_nominator_count_reduced_by: 1,
        })
    }

    #[test]
    fn withdraw_stake_nominator_withdraw_all() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![(Withdraw::All, Ok(()))],
            expected_withdraw: Some(Withdraw::All),
            expected_nominator_count_reduced_by: 1,
        })
    }

    #[test]
    fn withdraw_stake_nominator_withdraw_all_multiple_withdraws_error() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
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
            expected_nominator_count_reduced_by: 1,
        })
    }

    #[test]
    fn withdraw_stake_nominator_above_minimum_no_rewards() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 1,
            withdraws: vec![(Withdraw::Some(39 * SSC), Ok(()))],
            expected_withdraw: Some(Withdraw::Some(39 * SSC)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_nominator_zero_amount() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 1,
            withdraws: vec![(Withdraw::Some(0), Ok(()))],
            expected_withdraw: None,
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn slash_operator() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_free_balance = 250 * SSC;
        let operator_stake = 200 * SSC;
        let operator_extra_deposit = 40 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let nominator_account = 2;
        let nominator_free_balance = 150 * SSC;
        let nominator_stake = 100 * SSC;
        let nominator_extra_deposit = 40 * SSC;

        let nominators = vec![
            (operator_account, (operator_free_balance, operator_stake)),
            (nominator_account, (nominator_free_balance, nominator_stake)),
        ];

        let unlocking = vec![(operator_account, 10 * SSC), (nominator_account, 10 * SSC)];

        let deposits = vec![
            (operator_account, operator_extra_deposit),
            (nominator_account, nominator_extra_deposit),
        ];

        let mut ext = new_test_ext();
        ext.execute_with(|| {
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

            for unlock in &unlocking {
                do_withdraw_stake::<Test>(operator_id, unlock.0, Withdraw::Some(unlock.1)).unwrap();
            }
            do_finalize_domain_current_epoch::<Test>(domain_id, Zero::zero()).unwrap();

            for deposit in deposits {
                do_nominate_operator::<Test>(operator_id, deposit.0, deposit.1).unwrap();
            }

            do_slash_operators::<Test, _>(
                vec![(operator_id, SlashedReason::InvalidBundle(1))].into_iter(),
            )
            .unwrap();

            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert!(!domain_stake_summary.next_operators.contains(&operator_id));

            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(operator.status, OperatorStatus::Slashed);

            let pending_slashes = PendingSlashes::<Test>::get(domain_id).unwrap();
            assert!(pending_slashes.contains_key(&operator_id));
            let slash_info = pending_slashes.get(&operator_id).cloned().unwrap();
            for unlock in &unlocking {
                assert!(slash_info
                    .unlocking_nominators
                    .contains(&PendingNominatorUnlock {
                        nominator_id: unlock.0,
                        balance: unlock.1,
                    }))
            }

            do_finalize_slashed_operators::<Test>(domain_id).unwrap();
            assert_eq!(PendingSlashes::<Test>::get(domain_id), None);
            assert_eq!(Operators::<Test>::get(operator_id), None);
            assert_eq!(OperatorIdOwner::<Test>::get(operator_id), None);

            assert_eq!(
                Balances::total_balance(&operator_account),
                operator_free_balance - operator_stake
            );
            assert_eq!(
                Balances::total_balance(&nominator_account),
                nominator_free_balance - nominator_stake
            );
        });
    }

    #[test]
    fn slash_operators() {
        let domain_id = DomainId::new(0);
        let operator_free_balance = 250 * SSC;
        let operator_stake = 200 * SSC;

        let operator_account_1 = 1;
        let operator_account_2 = 2;
        let operator_account_3 = 3;

        let pair_1 = OperatorPair::from_seed(&U256::from(0u32).into());
        let pair_2 = OperatorPair::from_seed(&U256::from(1u32).into());
        let pair_3 = OperatorPair::from_seed(&U256::from(2u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let (operator_id_1, _) = register_operator(
                domain_id,
                operator_account_1,
                operator_free_balance,
                operator_stake,
                10 * SSC,
                pair_1.public(),
                Default::default(),
            );

            let (operator_id_2, _) = register_operator(
                domain_id,
                operator_account_2,
                operator_free_balance,
                operator_stake,
                10 * SSC,
                pair_2.public(),
                Default::default(),
            );

            let (operator_id_3, _) = register_operator(
                domain_id,
                operator_account_3,
                operator_free_balance,
                operator_stake,
                10 * SSC,
                pair_3.public(),
                Default::default(),
            );

            do_finalize_domain_current_epoch::<Test>(domain_id, Zero::zero()).unwrap();

            do_slash_operators::<Test, _>(
                vec![
                    (operator_id_1, SlashedReason::InvalidBundle(1)),
                    (operator_id_2, SlashedReason::InvalidBundle(2)),
                    (operator_id_3, SlashedReason::InvalidBundle(3)),
                ]
                .into_iter(),
            )
            .unwrap();

            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert!(!domain_stake_summary.next_operators.contains(&operator_id_1));
            assert!(!domain_stake_summary.next_operators.contains(&operator_id_2));
            assert!(!domain_stake_summary.next_operators.contains(&operator_id_3));

            let operator = Operators::<Test>::get(operator_id_1).unwrap();
            assert_eq!(operator.status, OperatorStatus::Slashed);

            let operator = Operators::<Test>::get(operator_id_2).unwrap();
            assert_eq!(operator.status, OperatorStatus::Slashed);

            let operator = Operators::<Test>::get(operator_id_3).unwrap();
            assert_eq!(operator.status, OperatorStatus::Slashed);
        });
    }

    #[test]
    fn nominator_withdraw_while_pending_deposit_exist() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_free_balance = 1500 * SSC;
        let operator_stake = 1000 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let nominator_account = 2;
        let nominator_free_balance = 150 * SSC;
        let nominator_stake = 100 * SSC;
        let nominators = BTreeMap::from_iter(vec![(
            nominator_account,
            (nominator_free_balance, nominator_stake),
        )]);
        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let (operator_id, _) = register_operator(
                domain_id,
                operator_account,
                operator_free_balance,
                operator_stake,
                100 * SSC,
                pair.public(),
                nominators,
            );

            let pending_deposit =
                PendingDeposits::<Test>::get(operator_id, nominator_account).unwrap();
            assert_eq!(pending_deposit, nominator_stake);

            // It is okay to deposit more while there is pending deposit
            let additional_deposit = 10 * SSC;
            let res = Domains::nominate_operator(
                RuntimeOrigin::signed(nominator_account),
                operator_id,
                additional_deposit,
            );
            assert_ok!(res);
            let pending_deposit =
                PendingDeposits::<Test>::get(operator_id, nominator_account).unwrap();
            assert_eq!(pending_deposit, nominator_stake + additional_deposit);

            let nominator_count = NominatorCount::<Test>::get(operator_id);

            // Withdraw will be rejected while there is pending deposit
            let res = Domains::withdraw_stake(
                RuntimeOrigin::signed(nominator_account),
                operator_id,
                Withdraw::All,
            );
            assert_err!(
                res,
                Error::<Test>::Staking(crate::staking::Error::TryWithdrawWithPendingDeposit)
            );

            // count should remain same
            assert_eq!(NominatorCount::<Test>::get(operator_id), nominator_count);
        });
    }

    #[test]
    fn nominator_deposit_while_pending_withdraw_exist() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_free_balance = 1500 * SSC;
        let operator_stake = 1000 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let nominator_account = 2;
        let nominator_free_balance = 150 * SSC;
        let nominator_stake = 100 * SSC;
        let nominators = BTreeMap::from_iter(vec![(
            nominator_account,
            (nominator_free_balance, nominator_stake),
        )]);

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let (operator_id, _) = register_operator(
                domain_id,
                operator_account,
                operator_free_balance,
                operator_stake,
                10 * SSC,
                pair.public(),
                nominators,
            );

            // Finalize pending deposit
            do_finalize_domain_current_epoch::<Test>(domain_id, 0).unwrap();
            assert!(!PendingDeposits::<Test>::contains_key(
                operator_id,
                nominator_account,
            ));

            // Issue a withdraw
            let res = Domains::withdraw_stake(
                RuntimeOrigin::signed(nominator_account),
                operator_id,
                Withdraw::Some(nominator_stake / 3),
            );
            assert_ok!(res);
            let pending_withdrawal =
                PendingWithdrawals::<Test>::get(operator_id, nominator_account).unwrap();
            assert_eq!(pending_withdrawal, Withdraw::Some(nominator_stake / 3));

            // It is okay to withdraw more while there is pending withdraw
            let res = Domains::withdraw_stake(
                RuntimeOrigin::signed(nominator_account),
                operator_id,
                Withdraw::Some(nominator_stake / 3),
            );
            assert_ok!(res);
            let pending_withdrawal =
                PendingWithdrawals::<Test>::get(operator_id, nominator_account).unwrap();
            assert_eq!(pending_withdrawal, Withdraw::Some(nominator_stake * 2 / 3));

            let nominator_count = NominatorCount::<Test>::get(operator_id);

            // Deposit will be rejected while there is pending withdraw
            let res = Domains::nominate_operator(
                RuntimeOrigin::signed(nominator_account),
                operator_id,
                10 * SSC,
            );
            assert_err!(
                res,
                Error::<Test>::Staking(crate::staking::Error::TryDepositWithPendingWithdraw)
            );

            // count should remain same
            assert_eq!(NominatorCount::<Test>::get(operator_id), nominator_count);
        });
    }

    #[test]
    fn pending_staking_operation_limit() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_free_balance = 1500 * SSC;
        let operator_stake = 1000 * SSC;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let nominator_account = 2;
        let nominator_free_balance = 1500 * SSC;
        let nominator_stake = 100 * SSC;
        let nominators = BTreeMap::from_iter(vec![(
            nominator_account,
            (nominator_free_balance, nominator_stake),
        )]);

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            let (operator_id, _) = register_operator(
                domain_id,
                operator_account,
                operator_free_balance,
                operator_stake,
                SSC,
                pair.public(),
                nominators,
            );

            // Finalize pending registration
            do_finalize_domain_current_epoch::<Test>(domain_id, 0).unwrap();
            assert!(!PendingDeposits::<Test>::contains_key(
                operator_id,
                nominator_account,
            ));

            // Create pending staking op
            for i in 0..<Test as Config>::MaxPendingStakingOperation::get() {
                assert_ok!(Domains::nominate_operator(
                    RuntimeOrigin::signed(nominator_account),
                    operator_id,
                    SSC,
                ));
                let pending_deposit =
                    PendingDeposits::<Test>::get(operator_id, nominator_account).unwrap();
                assert_eq!(pending_deposit, (i as u128 + 1) * SSC);
                assert_eq!(PendingStakingOperationCount::<Test>::get(domain_id), i + 1);
            }

            // Creating more pending staking op will fail due to the limit
            let res = Domains::nominate_operator(
                RuntimeOrigin::signed(nominator_account),
                operator_id,
                SSC,
            );
            assert_err!(
                res,
                Error::<Test>::Staking(crate::staking::Error::TooManyPendingStakingOperation)
            );

            // Epoch transition will reset the pending op count
            do_finalize_domain_current_epoch::<Test>(
                domain_id,
                <Test as Config>::StakeEpochDuration::get(),
            )
            .unwrap();
            assert_eq!(PendingStakingOperationCount::<Test>::get(domain_id), 0);

            assert_ok!(Domains::nominate_operator(
                RuntimeOrigin::signed(nominator_account),
                operator_id,
                SSC,
            ));
        });
    }
}

//! Staking for domains

use crate::pallet::{
    Deposits, DomainRegistry, DomainStakingSummary, LatestConfirmedDomainBlockNumber,
    NextOperatorId, NominatorCount, OperatorIdOwner, OperatorSigningKey, Operators,
    PendingOperatorSwitches, PendingSlashes, PendingStakingOperationCount, Withdrawals,
};
use crate::staking_epoch::mint_funds;
use crate::{
    BalanceOf, Config, DomainBlockNumberFor, Event, HoldIdentifier, NominatorId,
    OperatorEpochSharePrice, Pallet, ReceiptHashFor, SlashedReason,
};
use codec::{Decode, Encode};
use frame_support::traits::fungible::{Inspect, InspectHold, MutateHold};
use frame_support::traits::tokens::{Fortitude, Precision, Preservation};
use frame_support::{ensure, PalletError};
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::{DomainId, EpochIndex, OperatorId, OperatorPublicKey, ZERO_OPERATOR_SIGNING_KEY};
use sp_runtime::traits::{CheckedAdd, CheckedSub, One, Zero};
use sp_runtime::{Perbill, Percent, Saturating};
use sp_std::collections::btree_map::BTreeMap;
use sp_std::collections::btree_set::BTreeSet;
use sp_std::iter::Iterator;
use sp_std::vec::IntoIter;

/// A nominators deposit.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq, Default)]
pub(crate) struct Deposit<Share: Copy, Balance: Copy> {
    pub(crate) known: KnownDeposit<Share>,
    pub(crate) pending: Option<PendingDeposit<Balance>>,
}

/// A share price is parts per billion of shares/ssc.
/// Note: Shares must always be equal to or lower than ssc.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq, Default)]
pub struct SharePrice(Perbill);

impl SharePrice {
    /// Creates a new instance of share price from shares and stake.
    pub(crate) fn new<T: Config>(shares: T::Share, stake: BalanceOf<T>) -> Self {
        SharePrice(if shares.is_zero() || stake.is_zero() {
            Perbill::one()
        } else {
            Perbill::from_rational(shares, stake.into())
        })
    }

    /// Converts stake to shares based on the share price
    pub(crate) fn stake_to_shares<T: Config>(&self, stake: BalanceOf<T>) -> T::Share {
        self.0.mul_floor(stake).into()
    }

    /// Converts shares to stake based on the share price
    pub(crate) fn shares_to_stake<T: Config>(&self, shares: T::Share) -> BalanceOf<T> {
        self.0.saturating_reciprocal_mul_floor(shares.into())
    }

    /// Returns true if the share price is one
    pub(crate) fn is_one(&self) -> bool {
        self.0.is_one()
    }
}

/// Unique epoch identifier across all domains. A combination of Domain and its epoch.
#[derive(TypeInfo, Debug, Encode, Decode, Copy, Clone, PartialEq, Eq)]
pub struct DomainEpoch(DomainId, EpochIndex);

impl DomainEpoch {
    pub(crate) fn deconstruct(self) -> (DomainId, EpochIndex) {
        (self.0, self.1)
    }
}

impl From<(DomainId, EpochIndex)> for DomainEpoch {
    fn from((domain_id, epoch_idx): (DomainId, EpochIndex)) -> Self {
        Self(domain_id, epoch_idx)
    }
}

/// A nominator's shares against their deposits to given operator pool.
#[derive(TypeInfo, Debug, Encode, Decode, Copy, Clone, PartialEq, Eq, Default)]
pub(crate) struct KnownDeposit<Share: Copy> {
    pub(crate) shares: Share,
}

/// A nominators pending deposit in SSC that needs to be converted to shares once domain epoch is complete.
#[derive(TypeInfo, Debug, Encode, Decode, Copy, Clone, PartialEq, Eq)]
pub(crate) struct PendingDeposit<Balance: Copy> {
    pub(crate) effective_domain_epoch: DomainEpoch,
    pub(crate) amount: Balance,
}

/// A nominator's withdrawal from a given operator pool.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub(crate) struct Withdrawal<Share, DomainBlockNumber> {
    pub(crate) allowed_since_domain_epoch: DomainEpoch,
    pub(crate) unlock_at_confirmed_domain_block_number: DomainBlockNumber,
    pub(crate) shares: Share,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct OperatorDeregisteredInfo<DomainBlockNumber> {
    pub domain_epoch: DomainEpoch,
    pub unlock_at_confirmed_domain_block_number: DomainBlockNumber,
}

impl<DomainBlockNumber> From<(DomainId, EpochIndex, DomainBlockNumber)>
    for OperatorDeregisteredInfo<DomainBlockNumber>
{
    fn from(value: (DomainId, EpochIndex, DomainBlockNumber)) -> Self {
        OperatorDeregisteredInfo {
            domain_epoch: (value.0, value.1).into(),
            unlock_at_confirmed_domain_block_number: value.2,
        }
    }
}

/// Type that represents an operator status.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum OperatorStatus<DomainBlockNumber> {
    Registered,
    /// De-registered at given domain epoch.
    Deregistered(OperatorDeregisteredInfo<DomainBlockNumber>),
    Slashed,
}

/// Type that represents an operator details.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct Operator<Balance, Share, DomainBlockNumber> {
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
    pub current_total_shares: Share,
    pub status: OperatorStatus<DomainBlockNumber>,
    /// Total deposits during the previous epoch
    pub deposits_in_epoch: Balance,
    /// Total withdrew shares during the previous epoch
    pub withdrawals_in_epoch: Share,
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
    InsufficientShares,
    ZeroWithdrawShares,
    BalanceFreeze,
    MinimumOperatorStake,
    UnknownOperator,
    MinimumNominatorStake,
    BalanceOverflow,
    BalanceUnderflow,
    NotOperatorOwner,
    OperatorNotRegistered,
    UnknownNominator,
    MissingOperatorOwner,
    MintBalance,
    BlockNumberOverflow,
    RemoveLock,
    EpochOverflow,
    ShareUnderflow,
    ShareOverflow,
    TooManyPendingStakingOperation,
    OperatorNotAllowed,
    InvalidOperatorSigningKey,
    MaximumNominators,
    DuplicateOperatorSigningKey,
    MissingOperatorEpochSharePrice,
    MissingWithdrawal,
    EpochNotComplete,
    UnlockPeriodNotComplete,
    OperatorNotDeregistered,
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

        hold_deposit::<T>(&operator_owner, operator_id, amount)?;

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
            current_total_shares: Zero::zero(),
            status: OperatorStatus::Registered,
            // sum total deposits added during this epoch.
            deposits_in_epoch: amount,
            withdrawals_in_epoch: Zero::zero(),
        };
        Operators::<T>::insert(operator_id, operator);
        OperatorSigningKey::<T>::insert(signing_key, operator_id);
        // update stake summary to include new operator for next epoch
        domain_stake_summary.next_operators.insert(operator_id);
        // update pending transfers
        let current_domain_epoch = (domain_id, domain_stake_summary.current_epoch_index).into();
        do_calculate_previous_epoch_deposit_shares_and_add_new_deposit::<T>(
            operator_id,
            operator_owner,
            current_domain_epoch,
            amount,
        )?;

        Ok((operator_id, domain_stake_summary.current_epoch_index))
    })
}

pub(crate) struct DepositInfo<Balance> {
    /// If this nominator is currently nominating the operator.
    /// If there are multiple deposits in same epoch, still returns true
    nominating: bool,
    /// Final current deposit in this epoch.
    total_deposit: Balance,
    /// If this is the first deposit in this epoch.
    first_deposit_in_epoch: bool,
}

/// Calculates shares for any pending deposit for previous epoch using the the epoch share price and
/// then create a new pending deposit in the current epoch.
/// If there is a pending deposit for the current epoch, then simply increment the amount.
/// Returns updated deposit info
pub(crate) fn do_calculate_previous_epoch_deposit_shares_and_add_new_deposit<T: Config>(
    operator_id: OperatorId,
    nominator_id: NominatorId<T>,
    current_domain_epoch: DomainEpoch,
    new_deposit: BalanceOf<T>,
) -> Result<DepositInfo<BalanceOf<T>>, Error> {
    Deposits::<T>::try_mutate(operator_id, nominator_id, |maybe_deposit| {
        let mut deposit = maybe_deposit.take().unwrap_or_default();
        do_convert_previous_epoch_deposits::<T>(operator_id, &mut deposit, current_domain_epoch)?;

        // add or create new pending deposit
        let (pending_deposit, deposit_info) = match deposit.pending {
            None => {
                let pending_deposit = PendingDeposit {
                    effective_domain_epoch: current_domain_epoch,
                    amount: new_deposit,
                };

                let deposit_info = DepositInfo {
                    nominating: !deposit.known.shares.is_zero(),
                    total_deposit: new_deposit,
                    first_deposit_in_epoch: true,
                };

                (pending_deposit, deposit_info)
            }
            Some(pending_deposit) => {
                let pending_deposit = PendingDeposit {
                    effective_domain_epoch: current_domain_epoch,
                    amount: pending_deposit
                        .amount
                        .checked_add(&new_deposit)
                        .ok_or(Error::BalanceOverflow)?,
                };

                let deposit_info = DepositInfo {
                    nominating: !deposit.known.shares.is_zero(),
                    total_deposit: pending_deposit.amount,
                    first_deposit_in_epoch: false,
                };

                (pending_deposit, deposit_info)
            }
        };

        deposit.pending = Some(pending_deposit);
        *maybe_deposit = Some(deposit);
        Ok(deposit_info)
    })
}

pub(crate) fn do_convert_previous_epoch_deposits<T: Config>(
    operator_id: OperatorId,
    deposit: &mut Deposit<T::Share, BalanceOf<T>>,
    current_domain_epoch: DomainEpoch,
) -> Result<(), Error> {
    let maybe_pending_deposit = deposit.pending.take();
    // if it is one of the previous domain epoch, then calculate shares for the epoch and update known deposit
    deposit.pending = if let Some(PendingDeposit {
                                                effective_domain_epoch,
                                                amount,
                                            }) = maybe_pending_deposit && effective_domain_epoch != current_domain_epoch
    {
        let epoch_share_price =
            OperatorEpochSharePrice::<T>::get(operator_id, effective_domain_epoch)
                .ok_or(Error::MissingOperatorEpochSharePrice)?;

        let new_shares = epoch_share_price.stake_to_shares::<T>(amount);
        deposit.known.shares = deposit
            .known
            .shares
            .checked_add(&new_shares)
            .ok_or(Error::ShareOverflow)?;
        None
    } else {
        maybe_pending_deposit
    };

    Ok(())
}

pub(crate) fn do_nominate_operator<T: Config>(
    operator_id: OperatorId,
    nominator_id: T::AccountId,
    amount: BalanceOf<T>,
) -> Result<(), Error> {
    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator.as_mut().ok_or(Error::UnknownOperator)?;

        ensure!(
            operator.status == OperatorStatus::Registered,
            Error::OperatorNotRegistered
        );

        let domain_stake_summary = DomainStakingSummary::<T>::get(operator.current_domain_id)
            .ok_or(Error::DomainNotInitialized)?;

        hold_deposit::<T>(&nominator_id, operator_id, amount)?;

        // increment total deposit for operator pool within this epoch
        operator.deposits_in_epoch = operator
            .deposits_in_epoch
            .checked_add(&amount)
            .ok_or(Error::BalanceOverflow)?;

        let current_domain_epoch = (
            operator.current_domain_id,
            domain_stake_summary.current_epoch_index,
        )
            .into();

        let DepositInfo {
            nominating,
            total_deposit,
            first_deposit_in_epoch,
        } = do_calculate_previous_epoch_deposit_shares_and_add_new_deposit::<T>(
            operator_id,
            nominator_id,
            current_domain_epoch,
            amount,
        )?;

        // if not a nominator, then ensure
        // - amount >= operator's minimum nominator stake amount.
        // - nominator count does not exceed max nominators.
        // - if first nomination, then increment the nominator count.
        if !nominating {
            ensure!(
                total_deposit >= operator.minimum_nominator_stake,
                Error::MinimumNominatorStake
            );

            if first_deposit_in_epoch {
                NominatorCount::<T>::try_mutate(operator_id, |count| {
                    *count += 1;
                    ensure!(*count <= T::MaxNominators::get(), Error::MaximumNominators);
                    Ok(())
                })?;
            }
        }

        Ok(())
    })
}

pub(crate) fn hold_deposit<T: Config>(
    who: &T::AccountId,
    operator_id: OperatorId,
    amount: BalanceOf<T>,
) -> Result<(), Error> {
    // ensure there is enough free balance to lock
    ensure!(
        T::Currency::reducible_balance(who, Preservation::Preserve, Fortitude::Polite) >= amount,
        Error::InsufficientBalance
    );

    let pending_deposit_hold_id = T::HoldIdentifier::staking_staked(operator_id);
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

        DomainStakingSummary::<T>::try_mutate(
            operator.current_domain_id,
            |maybe_domain_stake_summary| {
                let stake_summary = maybe_domain_stake_summary
                    .as_mut()
                    .ok_or(Error::DomainNotInitialized)?;

                let latest_confirmed_domain_block_number =
                    LatestConfirmedDomainBlockNumber::<T>::get(operator.current_domain_id);
                let unlock_operator_at_domain_block_number = latest_confirmed_domain_block_number
                    .checked_add(&T::StakeWithdrawalLockingPeriod::get())
                    .ok_or(Error::BlockNumberOverflow)?;
                let operator_deregister_info = (
                    operator.current_domain_id,
                    stake_summary.current_epoch_index,
                    unlock_operator_at_domain_block_number,
                )
                    .into();

                operator.status = OperatorStatus::Deregistered(operator_deregister_info);

                stake_summary.next_operators.remove(&operator_id);
                Ok(())
            },
        )
    })
}

pub(crate) fn do_withdraw_stake<T: Config>(
    operator_id: OperatorId,
    nominator_id: NominatorId<T>,
    shares_withdrew: T::Share,
) -> Result<(), Error> {
    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator.as_mut().ok_or(Error::UnknownOperator)?;
        ensure!(
            operator.status == OperatorStatus::Registered,
            Error::OperatorNotRegistered
        );

        ensure!(!shares_withdrew.is_zero(), Error::ZeroWithdrawShares);

        // calculate shares for any previous epoch
        let domain_stake_summary = DomainStakingSummary::<T>::get(operator.current_domain_id)
            .ok_or(Error::DomainNotInitialized)?;
        let domain_current_epoch = (
            operator.current_domain_id,
            domain_stake_summary.current_epoch_index,
        )
            .into();

        Deposits::<T>::try_mutate(operator_id, nominator_id.clone(), |maybe_deposit| {
            let deposit = maybe_deposit.as_mut().ok_or(Error::InsufficientShares)?;
            do_convert_previous_epoch_deposits::<T>(operator_id, deposit, domain_current_epoch)?;
            Ok(())
        })?;

        let operator_owner =
            OperatorIdOwner::<T>::get(operator_id).ok_or(Error::UnknownOperator)?;

        let is_operator_owner = operator_owner == nominator_id;

        Deposits::<T>::try_mutate(operator_id, nominator_id.clone(), |maybe_deposit| {
            let deposit = maybe_deposit.as_mut().ok_or(Error::UnknownNominator)?;
            let known_shares = deposit.known.shares;

            let (remaining_shares, shares_withdrew) = {
                let remaining_shares = known_shares
                    .checked_sub(&shares_withdrew)
                    .ok_or(Error::InsufficientShares)?;

                // short circuit to check if remaining shares can be zero
                if remaining_shares.is_zero() {
                    if is_operator_owner {
                        return Err(Error::MinimumOperatorStake);
                    }

                    (remaining_shares, shares_withdrew)
                } else {
                    // total stake including any reward within this epoch.
                    // used to calculate the share price at this instant.
                    let total_stake = domain_stake_summary
                        .current_epoch_rewards
                        .get(&operator_id)
                        .and_then(|rewards| {
                            let operator_tax = operator.nomination_tax.mul_floor(*rewards);
                            operator
                                .current_total_stake
                                .checked_add(rewards)?
                                // deduct operator tax
                                .checked_sub(&operator_tax)
                        })
                        .unwrap_or(operator.current_total_stake);

                    let share_price =
                        SharePrice::new::<T>(operator.current_total_shares, total_stake);
                    let remaining_stake = share_price.shares_to_stake::<T>(remaining_shares);

                    // ensure the remaining share value is atleast the defined minimum
                    // MinOperatorStake if a nominator is operator pool owner
                    if is_operator_owner && remaining_stake.lt(&T::MinOperatorStake::get()) {
                        return Err(Error::MinimumOperatorStake);
                    }

                    // if not an owner, if remaining balance < MinNominatorStake, then withdraw all shares.
                    if !is_operator_owner && remaining_stake.lt(&operator.minimum_nominator_stake) {
                        (T::Share::zero(), known_shares)
                    } else {
                        (remaining_shares, shares_withdrew)
                    }
                }
            };

            // update operator pool to note withdrew shares in the epoch
            operator.withdrawals_in_epoch = operator
                .withdrawals_in_epoch
                .checked_add(&shares_withdrew)
                .ok_or(Error::ShareOverflow)?;

            deposit.known.shares = remaining_shares;
            if remaining_shares.is_zero() {
                if let Some(pending_deposit) = deposit.pending {
                    // if there is a pending deposit, then ensure
                    // the new deposit is atleast minimum nominator stake
                    ensure!(
                        pending_deposit.amount >= operator.minimum_nominator_stake,
                        Error::MinimumNominatorStake
                    );
                } else {
                    // reduce nominator count if withdraw all and there are no pending deposits
                    NominatorCount::<T>::mutate(operator_id, |count| {
                        *count -= 1;
                    });
                }
            }

            let latest_confirmed_domain_block_number =
                LatestConfirmedDomainBlockNumber::<T>::get(operator.current_domain_id);
            let unlock_at_confirmed_domain_block_number = latest_confirmed_domain_block_number
                .checked_add(&T::StakeWithdrawalLockingPeriod::get())
                .ok_or(Error::BlockNumberOverflow)?;

            Withdrawals::<T>::try_mutate(operator_id, nominator_id, |maybe_withdrawals| {
                let mut withdrawals = maybe_withdrawals.take().unwrap_or_default();
                // if there is an existing withdrawal within the same epoch, then update it instead
                if let Some(withdrawal) = withdrawals.back_mut() && withdrawal.allowed_since_domain_epoch == domain_current_epoch {
                    withdrawal.shares = withdrawal.shares.checked_add(&shares_withdrew).ok_or(Error::ShareOverflow)?;
                    withdrawal.unlock_at_confirmed_domain_block_number = unlock_at_confirmed_domain_block_number;
                } else {
                    withdrawals.push_back(Withdrawal {
                        allowed_since_domain_epoch: domain_current_epoch,
                        unlock_at_confirmed_domain_block_number,
                        shares: shares_withdrew,
                    });
                }

                *maybe_withdrawals = Some(withdrawals);
                Ok(())
            })
        })
    })
}

/// Unlocks any withdraws that are ready to be unlocked.
pub(crate) fn do_unlock_funds<T: Config>(
    operator_id: OperatorId,
    nominator_id: NominatorId<T>,
) -> Result<BalanceOf<T>, Error> {
    let operator = Operators::<T>::get(operator_id).ok_or(Error::UnknownOperator)?;
    ensure!(
        operator.status == OperatorStatus::Registered,
        Error::OperatorNotRegistered
    );

    Withdrawals::<T>::try_mutate_exists(operator_id, nominator_id.clone(), |maybe_withdrawals| {
        let withdrawals = maybe_withdrawals.as_mut().ok_or(Error::MissingWithdrawal)?;
        let Withdrawal {
            allowed_since_domain_epoch,
            unlock_at_confirmed_domain_block_number,
            shares,
        } = withdrawals.pop_front().ok_or(Error::MissingWithdrawal)?;

        let (domain_id, _) = allowed_since_domain_epoch.deconstruct();
        let latest_confirmed_block_number = LatestConfirmedDomainBlockNumber::<T>::get(domain_id);
        ensure!(
            unlock_at_confirmed_domain_block_number <= latest_confirmed_block_number,
            Error::UnlockPeriodNotComplete
        );

        let staked_hold_id = T::HoldIdentifier::staking_staked(operator_id);
        let locked_amount = T::Currency::balance_on_hold(&staked_hold_id, &nominator_id);
        let amount_to_unlock: BalanceOf<T> = {
            let epoch_share_price =
                OperatorEpochSharePrice::<T>::get(operator_id, allowed_since_domain_epoch)
                    .ok_or(Error::MissingOperatorEpochSharePrice)?;

            // if the share price is one, just convert shares to ssc
            let amount_to_unlock = if epoch_share_price.is_one() {
                shares.into()
            } else {
                epoch_share_price.shares_to_stake::<T>(shares)
            };

            // if the amount to release is more than currently locked,
            // mint the diff and release the rest
            if let Some(amount_to_mint) = amount_to_unlock.checked_sub(&locked_amount) {
                // mint any gains
                mint_funds::<T>(&nominator_id, amount_to_mint)?;
                locked_amount
            } else {
                amount_to_unlock
            }
        };

        T::Currency::release(
            &staked_hold_id,
            &nominator_id,
            amount_to_unlock,
            Precision::Exact,
        )
        .map_err(|_| Error::RemoveLock)?;

        // if there are no withdrawals, then delete the storage as well
        if withdrawals.is_empty() {
            *maybe_withdrawals = None;
            // if there is no deposit or pending deposits, then clean up the deposit state as well
            Deposits::<T>::mutate_exists(operator_id, nominator_id, |maybe_deposit| {
                if let Some(deposit) = maybe_deposit && deposit.known.shares.is_zero() && deposit.pending.is_none() {
                    *maybe_deposit = None
                }
            });
        }

        Ok(amount_to_unlock)
    })
}

/// Converts shares to ssc based on the OPerator epoch share price
/// if the share price is not available, then return the shares as is
fn convert_shares_to_ssc<T: Config>(
    operator_id: OperatorId,
    domain_epoch: DomainEpoch,
    shares: T::Share,
) -> (BalanceOf<T>, T::Share) {
    match OperatorEpochSharePrice::<T>::get(operator_id, domain_epoch) {
        None => (Zero::zero(), shares),
        Some(epoch_share_price) => {
            // if the share price is one, just convert shares to ssc
            (
                if epoch_share_price.is_one() {
                    shares.into()
                } else {
                    epoch_share_price.shares_to_stake::<T>(shares)
                },
                Zero::zero(),
            )
        }
    }
}
// If there are any withdrawals for previous epoch, then calculate the SSC for those shares
// using the share price at which the withdraw was initiated.
// If there are any withdrawals during the current epoch, it share price is not calculated yet
// so just return the shares as is
pub(crate) fn calculate_withdraw_share_ssc<T: Config>(
    operator_id: OperatorId,
    nominator_id: NominatorId<T>,
) -> (BalanceOf<T>, T::Share) {
    let withdrawals = Withdrawals::<T>::take(operator_id, nominator_id.clone()).unwrap_or_default();
    withdrawals.into_iter().fold(
        (BalanceOf::<T>::zero(), T::Share::zero()),
        |(total_amount, total_shares), withdraw| {
            let (amount, shares) = convert_shares_to_ssc::<T>(
                operator_id,
                withdraw.allowed_since_domain_epoch,
                withdraw.shares,
            );

            (
                amount.saturating_add(total_amount),
                shares.saturating_add(total_shares),
            )
        },
    )
}

/// Unlocks an already de-registered operator given unlock wait period is complete.
pub(crate) fn do_unlock_operator<T: Config>(operator_id: OperatorId) -> Result<(), Error> {
    Operators::<T>::try_mutate_exists(operator_id, |maybe_operator| {
        // take the operator so this operator info is removed once we unlock the operator.
        let operator = maybe_operator.take().ok_or(Error::UnknownOperator)?;
        let OperatorDeregisteredInfo {
            domain_epoch,
            unlock_at_confirmed_domain_block_number,
        } = match operator.status {
            OperatorStatus::Deregistered(operator_deregistered_info) => operator_deregistered_info,
            _ => return Err(Error::OperatorNotDeregistered),
        };

        let (domain_id, _) = domain_epoch.deconstruct();
        let latest_confirmed_block_number = LatestConfirmedDomainBlockNumber::<T>::get(domain_id);
        ensure!(
            unlock_at_confirmed_domain_block_number <= latest_confirmed_block_number,
            Error::UnlockPeriodNotComplete
        );

        let total_shares = operator.current_total_shares;
        let mut total_stake = operator
            .current_total_stake
            .checked_add(&operator.current_epoch_rewards)
            .ok_or(Error::BalanceOverflow)?;

        let share_price = SharePrice::new::<T>(total_shares, total_stake);

        let staked_hold_id = T::HoldIdentifier::staking_staked(operator_id);
        Deposits::<T>::drain_prefix(operator_id).try_for_each(|(nominator_id, mut deposit)| {
            // convert any deposits from the previous epoch to shares
            do_convert_previous_epoch_deposits::<T>(operator_id, &mut deposit, domain_epoch)?;

            let current_locked_amount =
                T::Currency::balance_on_hold(&staked_hold_id, &nominator_id);

            // if there are any withdrawals from this operator, account for them
            // if the withdrawals has share price noted, then convert them to SSC
            // if no share price, then it must be intitated in the epoch when operator was slashed,
            // so get the shares as is and include them in the total staked shares.
            let (amount_ready_withdraw, shares_withdrew_in_current_epoch) =
                calculate_withdraw_share_ssc::<T>(operator_id, nominator_id.clone());

            // include all the known shares and shares that were withdrawn in the current epoch
            let nominator_shares = if shares_withdrew_in_current_epoch.is_zero() {
                deposit.known.shares
            } else {
                deposit
                    .known
                    .shares
                    .checked_add(&shares_withdrew_in_current_epoch)
                    .ok_or(Error::ShareOverflow)?
            };

            // current staked amount
            let nominator_staked_amount = if share_price.is_one() {
                nominator_shares.into()
            } else {
                share_price.shares_to_stake::<T>(nominator_shares)
            };

            let amount_deposited_in_previous_epoch = deposit
                .pending
                .map(|pending_deposit| pending_deposit.amount)
                .unwrap_or_default();

            let total_amount_to_unlock = nominator_staked_amount
                .checked_add(&amount_ready_withdraw)
                .and_then(|amount| amount.checked_add(&amount_deposited_in_previous_epoch))
                .ok_or(Error::BalanceOverflow)?;

            let amount_to_mint = total_amount_to_unlock
                .checked_sub(&current_locked_amount)
                .unwrap_or(Zero::zero());

            // remove the lock and mint any gains
            mint_funds::<T>(&nominator_id, amount_to_mint)?;
            T::Currency::release(
                &staked_hold_id,
                &nominator_id,
                current_locked_amount,
                Precision::Exact,
            )
            .map_err(|_| Error::RemoveLock)?;

            total_stake = total_stake.saturating_sub(nominator_staked_amount);

            Ok(())
        })?;

        // transfer any remaining amount to treasury
        mint_funds::<T>(&T::TreasuryAccount::get(), total_stake)?;

        // remove OperatorOwner Details
        OperatorIdOwner::<T>::remove(operator_id);

        // remove operator signing key
        OperatorSigningKey::<T>::remove(operator.signing_key.clone());

        // remove operator epoch share prices
        let _ = OperatorEpochSharePrice::<T>::clear_prefix(operator_id, u32::MAX, None);

        // remove nominator count for this operator.
        NominatorCount::<T>::remove(operator_id);

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

            if pending_slashes.contains(&operator_id) {
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

                    pending_slashes.insert(operator_id);
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
        Config, Deposits, DomainRegistry, DomainStakingSummary, LatestConfirmedDomainBlockNumber,
        NextOperatorId, NominatorCount, OperatorIdOwner, Operators, PendingOperatorSwitches,
        PendingSlashes, Withdrawals,
    };
    use crate::staking::{
        do_nominate_operator, do_reward_operators, do_slash_operators, do_unlock_funds,
        do_withdraw_stake, Error as StakingError, Operator, OperatorConfig, OperatorStatus,
        StakingSummary,
    };
    use crate::staking_epoch::do_finalize_domain_current_epoch;
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

        if !DomainRegistry::<Test>::contains_key(domain_id) {
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
        }

        if !DomainStakingSummary::<Test>::contains_key(domain_id) {
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
        }

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

        let operator_id = NextOperatorId::<Test>::get() - 1;
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
                    current_total_shares: operator_stake,
                    status: OperatorStatus::Registered,
                    deposits_in_epoch: 0,
                    withdrawals_in_epoch: 0,
                }
            );

            let stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert!(stake_summary.next_operators.contains(&operator_id));
            assert_eq!(stake_summary.current_total_stake, operator_stake);

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

            let domain_staking_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert_eq!(domain_staking_summary.current_total_stake, operator_stake);

            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(operator.current_total_stake, operator_stake);
            assert_eq!(operator.current_total_shares, operator_stake);
            assert_eq!(operator.deposits_in_epoch, nominator_stake);

            let pending_deposit = Deposits::<Test>::get(0, nominator_account)
                .unwrap()
                .pending
                .unwrap()
                .amount;
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
            let pending_deposit = Deposits::<Test>::get(0, nominator_account)
                .unwrap()
                .pending
                .unwrap()
                .amount;
            assert_eq!(pending_deposit, nominator_stake + 40 * SSC);

            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(operator.current_total_stake, operator_stake);
            assert_eq!(operator.deposits_in_epoch, nominator_stake + 40 * SSC);

            let nominator_count = NominatorCount::<Test>::get(operator_id);
            assert_eq!(nominator_count, 1);

            // do epoch transition
            do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();

            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(
                operator.current_total_stake,
                operator_stake + nominator_stake + 40 * SSC
            );

            let domain_staking_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert_eq!(
                domain_staking_summary.current_total_stake,
                operator_stake + nominator_stake + 40 * SSC
            );
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
            assert_eq!(
                operator.status,
                OperatorStatus::Deregistered(
                    (
                        domain_id,
                        domain_stake_summary.current_epoch_index,
                        // since the Withdrawals locking period is 5 and confirmed domain block is 0
                        5
                    )
                        .into()
                )
            );

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

    type WithdrawWithResult = Vec<(Share, Result<(), StakingError>)>;

    /// Expected withdrawal amount.
    /// Bool indicates to include exisitential deposit while asserting the final balance
    /// since ED is not holded back from usable balance when there are no holds on the account.
    type ExpectedWithdrawAmount = Option<(BalanceOf<Test>, bool)>;

    pub(crate) type Share = <Test as Config>::Share;

    struct WithdrawParams {
        minimum_nominator_stake: BalanceOf<Test>,
        nominators: Vec<(NominatorId<Test>, BalanceOf<Test>)>,
        operator_reward: BalanceOf<Test>,
        nominator_id: NominatorId<Test>,
        withdraws: WithdrawWithResult,
        maybe_deposit: Option<BalanceOf<Test>>,
        expected_withdraw: ExpectedWithdrawAmount,
        expected_nominator_count_reduced_by: u32,
    }

    fn withdraw_stake(params: WithdrawParams) {
        let WithdrawParams {
            minimum_nominator_stake,
            nominators,
            operator_reward,
            nominator_id,
            withdraws,
            maybe_deposit,
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

            do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();

            if !operator_reward.is_zero() {
                do_reward_operators::<Test>(
                    domain_id,
                    vec![operator_id].into_iter(),
                    operator_reward,
                )
                .unwrap();
            }

            let nominator_count = NominatorCount::<Test>::get(operator_id);
            let confirmed_domain_block = 100;
            LatestConfirmedDomainBlockNumber::<Test>::insert(domain_id, confirmed_domain_block);

            if let Some(deposit_amount) = maybe_deposit {
                Balances::mint_into(&nominator_id, deposit_amount).unwrap();
                let res = Domains::nominate_operator(
                    RuntimeOrigin::signed(nominator_id),
                    operator_id,
                    deposit_amount,
                );
                assert_ok!(res);
            }

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

            if let Some((withdraw, include_ed)) = expected_withdraw {
                let previous_usable_balance = Balances::usable_balance(nominator_id);
                do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();

                // staking withdrawal is 5 blocks
                // to unlock funds, confirmed block should be atleast 105
                let confirmed_domain_block = 105;
                LatestConfirmedDomainBlockNumber::<Test>::insert(domain_id, confirmed_domain_block);
                assert_ok!(do_unlock_funds::<Test>(operator_id, nominator_id));

                let expected_balance = if include_ed {
                    previous_usable_balance + withdraw + crate::tests::ExistentialDeposit::get()
                } else {
                    previous_usable_balance + withdraw
                };

                assert_eq!(Balances::usable_balance(nominator_id), expected_balance);

                // ensure there are no withdrawals left
                assert!(Withdrawals::<Test>::get(operator_id, nominator_id).is_none());
            }

            let new_nominator_count = NominatorCount::<Test>::get(operator_id);
            assert_eq!(
                nominator_count - expected_nominator_count_reduced_by,
                new_nominator_count
            );

            // if the nominator count reduced, then there should be no storage for deposits as well
            if new_nominator_count < nominator_count {
                assert!(Deposits::<Test>::get(operator_id, nominator_id).is_none())
            }
        });
    }

    #[test]
    fn withdraw_stake_operator_all() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 0,
            withdraws: vec![(150 * SSC, Err(StakingError::MinimumOperatorStake))],
            maybe_deposit: None,
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
            withdraws: vec![(65 * SSC, Err(StakingError::MinimumOperatorStake))],
            maybe_deposit: None,
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
            withdraws: vec![(51 * SSC, Err(StakingError::MinimumOperatorStake))],
            maybe_deposit: None,
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
            withdraws: vec![(58 * SSC, Ok(()))],
            // given the reward, operator will get 164.28 SSC
            // taking 58 shares will give this following approximate amount.
            maybe_deposit: None,
            expected_withdraw: Some((63523809541959183678, false)),
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
                (58 * SSC, Ok(())),
                (5 * SSC, Err(StakingError::MinimumOperatorStake)),
            ],
            maybe_deposit: None,
            expected_withdraw: Some((63523809541959183678, false)),
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
            withdraws: vec![(53 * SSC, Ok(())), (5 * SSC, Ok(()))],
            maybe_deposit: None,
            expected_withdraw: Some((63523809541959183678, false)),
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
            withdraws: vec![(49 * SSC, Ok(()))],
            maybe_deposit: None,
            expected_withdraw: Some((49 * SSC, false)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_operator_above_minimum_multiple_withdraws_no_rewards() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 0,
            withdraws: vec![(29 * SSC, Ok(())), (20 * SSC, Ok(()))],
            maybe_deposit: None,
            expected_withdraw: Some((49 * SSC, false)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_operator_above_minimum_multiple_withdraws_no_rewards_with_errors() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 0,
            withdraws: vec![
                (29 * SSC, Ok(())),
                (20 * SSC, Ok(())),
                (20 * SSC, Err(StakingError::MinimumOperatorStake)),
            ],
            maybe_deposit: None,
            expected_withdraw: Some((49 * SSC, false)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_nominator_below_minimum_with_rewards() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![(45 * SSC, Ok(()))],
            // given nominator remaining stake goes below minimum
            // we withdraw everything, so for their 50 shares with reward,
            // price would be following
            maybe_deposit: None,
            expected_withdraw: Some((54761904777551020412, true)),
            expected_nominator_count_reduced_by: 1,
        })
    }

    #[test]
    fn withdraw_stake_nominator_below_minimum_with_rewards_multiple_withdraws() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![(25 * SSC, Ok(())), (20 * SSC, Ok(()))],
            // given nominator remaining stake goes below minimum
            // we withdraw everything, so for their 50 shares with reward,
            // price would be following
            maybe_deposit: None,
            expected_withdraw: Some((54761904777551020412, true)),
            expected_nominator_count_reduced_by: 1,
        })
    }

    #[test]
    fn withdraw_stake_nominator_below_minimum_with_rewards_multiple_withdraws_with_errors() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![
                (25 * SSC, Ok(())),
                (20 * SSC, Ok(())),
                (20 * SSC, Err(StakingError::InsufficientShares)),
            ],
            // given nominator remaining stake goes below minimum
            // we withdraw everything, so for their 50 shares with reward,
            // price would be following
            maybe_deposit: None,
            expected_withdraw: Some((54761904777551020412, true)),
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
            withdraws: vec![(45 * SSC, Ok(()))],
            maybe_deposit: None,
            expected_withdraw: Some((50 * SSC, true)),
            expected_nominator_count_reduced_by: 1,
        })
    }

    #[test]
    fn withdraw_stake_nominator_below_minimum_no_reward_multiple_rewards() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 1,
            withdraws: vec![(25 * SSC, Ok(())), (20 * SSC, Ok(()))],
            maybe_deposit: None,
            expected_withdraw: Some((50 * SSC, true)),
            expected_nominator_count_reduced_by: 1,
        })
    }

    #[test]
    fn withdraw_stake_nominator_below_minimum_no_reward_multiple_rewards_with_errors() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 1,
            withdraws: vec![
                (25 * SSC, Ok(())),
                (20 * SSC, Ok(())),
                (20 * SSC, Err(StakingError::InsufficientShares)),
            ],
            maybe_deposit: None,
            expected_withdraw: Some((50 * SSC, true)),
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
            withdraws: vec![(40 * SSC, Ok(()))],
            maybe_deposit: None,
            expected_withdraw: Some((43809523822040816330, false)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_nominator_above_minimum_multiple_withdraws() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![(35 * SSC, Ok(())), (5 * SSC, Ok(()))],
            maybe_deposit: None,
            expected_withdraw: Some((43809523822040816330, false)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_nominator_above_minimum_withdraw_all_multiple_withdraws_error() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![
                (35 * SSC, Ok(())),
                (5 * SSC, Ok(())),
                (15 * SSC, Err(StakingError::InsufficientShares)),
            ],
            maybe_deposit: None,
            expected_withdraw: Some((43809523822040816330, false)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_nominator_above_minimum_no_rewards() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 1,
            withdraws: vec![(39 * SSC, Ok(()))],
            maybe_deposit: None,
            expected_withdraw: Some((39 * SSC, false)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_nominator_above_minimum_no_rewards_multiple_withdraws() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 1,
            withdraws: vec![(35 * SSC, Ok(())), (5 * SSC, Ok(()))],
            maybe_deposit: None,
            expected_withdraw: Some((40 * SSC, false)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_nominator_above_minimum_no_rewards_multiple_withdraws_with_errors() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 1,
            withdraws: vec![
                (35 * SSC, Ok(())),
                (5 * SSC, Ok(())),
                (15 * SSC, Err(StakingError::InsufficientShares)),
            ],
            maybe_deposit: None,
            expected_withdraw: Some((40 * SSC, false)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_nominator_no_rewards_multiple_withdraws_with_error_min_nominator_stake() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: Zero::zero(),
            nominator_id: 1,
            withdraws: vec![
                (35 * SSC, Ok(())),
                (5 * SSC, Ok(())),
                (10 * SSC, Err(StakingError::MinimumNominatorStake)),
            ],
            maybe_deposit: Some(2 * SSC),
            expected_withdraw: Some((40 * SSC, false)),
            expected_nominator_count_reduced_by: 0,
        })
    }

    #[test]
    fn withdraw_stake_nominator_with_rewards_multiple_withdraws_with_error_min_nominator_stake() {
        withdraw_stake(WithdrawParams {
            minimum_nominator_stake: 10 * SSC,
            nominators: vec![(0, 150 * SSC), (1, 50 * SSC), (2, 10 * SSC)],
            operator_reward: 20 * SSC,
            nominator_id: 1,
            withdraws: vec![
                (35 * SSC, Ok(())),
                (5 * SSC, Ok(())),
                (10 * SSC, Err(StakingError::MinimumNominatorStake)),
            ],
            // given nominator remaining stake goes below minimum
            // we withdraw everything, so for their 50 shares with reward,
            // price would be following
            maybe_deposit: Some(2 * SSC),
            expected_withdraw: Some((43809523822040816330, false)),
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
            withdraws: vec![(0, Err(StakingError::ZeroWithdrawShares))],
            maybe_deposit: None,
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

            do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();
            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert_eq!(domain_stake_summary.current_total_stake, 300 * SSC);

            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(operator.current_total_stake, 300 * SSC);

            for unlock in &unlocking {
                do_withdraw_stake::<Test>(operator_id, unlock.0, unlock.1).unwrap();
            }

            do_reward_operators::<Test>(domain_id, vec![operator_id].into_iter(), 20 * SSC)
                .unwrap();
            do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();

            // post epoch transition, domain stake has 21.333 amount reduced due to withdrawal of 20 shares
            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert_eq!(
                domain_stake_summary.current_total_stake,
                298666666666666666667
            );

            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(operator.current_total_stake, 298666666666666666667);

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
            assert!(pending_slashes.contains(&operator_id));

            assert_eq!(
                Balances::total_balance(&crate::tests::TreasuryAccount::get()),
                0
            );

            do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();
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

            assert!(Balances::total_balance(&crate::tests::TreasuryAccount::get()) >= 320 * SSC)
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

            do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();
            let domain_stake_summary = DomainStakingSummary::<Test>::get(domain_id).unwrap();
            assert!(domain_stake_summary.next_operators.contains(&operator_id_1));
            assert!(domain_stake_summary.next_operators.contains(&operator_id_2));
            assert!(domain_stake_summary.next_operators.contains(&operator_id_3));
            assert_eq!(domain_stake_summary.current_total_stake, 600 * SSC);

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

            assert_eq!(
                Balances::total_balance(&crate::tests::TreasuryAccount::get()),
                0
            );

            do_finalize_domain_current_epoch::<Test>(domain_id).unwrap();
            assert_eq!(PendingSlashes::<Test>::get(domain_id), None);
            assert_eq!(Operators::<Test>::get(operator_id_1), None);
            assert_eq!(OperatorIdOwner::<Test>::get(operator_id_1), None);
            assert_eq!(Operators::<Test>::get(operator_id_2), None);
            assert_eq!(OperatorIdOwner::<Test>::get(operator_id_2), None);
            assert_eq!(Operators::<Test>::get(operator_id_3), None);
            assert_eq!(OperatorIdOwner::<Test>::get(operator_id_3), None);

            assert_eq!(
                Balances::total_balance(&crate::tests::TreasuryAccount::get()),
                600 * SSC
            )
        });
    }
}

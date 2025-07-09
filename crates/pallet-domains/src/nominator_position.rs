//! Nominator position calculation logic

use crate::pallet::{
    Config, Deposits, DomainStakingSummary, OperatorEpochSharePrice, Operators, Withdrawals,
};
use crate::{BalanceOf, DomainBlockNumberFor, ReceiptHashFor};
use alloc::vec::Vec;
use sp_domains::{EpochIndex, OperatorId};
use sp_runtime::traits::{Saturating, Zero};

/// Core data needed for nominator position calculation
struct PositionData<T: Config> {
    pub deposit: crate::staking::Deposit<T::Share, BalanceOf<T>>,
    pub operator: crate::staking::Operator<
        BalanceOf<T>,
        T::Share,
        DomainBlockNumberFor<T>,
        ReceiptHashFor<T>,
    >,
    pub current_epoch_index: EpochIndex,
    pub current_share_price: crate::staking::SharePrice,
}

/// Fetches and validates all core data needed for position calculation
fn fetch_position_data<T: Config>(
    operator_id: OperatorId,
    nominator_account: &T::AccountId,
) -> Option<PositionData<T>> {
    use crate::staking::current_share_price;

    // Get deposit information - early return if no position exists
    let deposit = Deposits::<T>::get(operator_id, nominator_account)?;

    // Get operator information
    let operator = Operators::<T>::get(operator_id)?;
    let domain_id = operator.current_domain_id;

    // Get current domain staking summary for epoch info and rewards
    let staking_summary = DomainStakingSummary::<T>::get(domain_id)?;
    let current_epoch_index = staking_summary.current_epoch_index;

    // Calculate current share price including pending rewards
    let current_share_price =
        current_share_price::<T>(operator_id, &operator, &staking_summary).ok()?;

    // Ensure operator has shares (avoid division by zero scenarios)
    if operator.current_total_shares.is_zero() {
        return None;
    }

    Some(PositionData {
        deposit,
        operator,
        current_epoch_index,
        current_share_price,
    })
}

/// Processes deposits to calculate total shares, storage fees, and pending deposits
fn process_deposits<T: Config>(
    position_data: &PositionData<T>,
    operator_id: OperatorId,
) -> (
    T::Share,
    BalanceOf<T>,
    Vec<sp_domains::PendingDeposit<BalanceOf<T>>>,
) {
    let mut total_shares = position_data.deposit.known.shares;
    let mut total_storage_fee_deposit = position_data.deposit.known.storage_fee_deposit;
    let mut pending_deposits = Vec::new();

    // Process pending deposit if it exists
    if let Some(pending_deposit) = &position_data.deposit.pending {
        // Always include storage fee regardless of conversion status
        total_storage_fee_deposit =
            total_storage_fee_deposit.saturating_add(pending_deposit.storage_fee_deposit);

        let (_, effective_epoch) = pending_deposit.effective_domain_epoch.deconstruct();

        // Try to convert pending deposit to shares if epoch has passed
        if effective_epoch < position_data.current_epoch_index {
            if let Some(epoch_share_price) = OperatorEpochSharePrice::<T>::get(
                operator_id,
                pending_deposit.effective_domain_epoch,
            ) {
                // Convert to shares using historical epoch price
                let pending_shares = epoch_share_price.stake_to_shares::<T>(pending_deposit.amount);
                total_shares = total_shares.saturating_add(pending_shares);
            } else {
                // Epoch passed but no share price available yet - keep as pending
                pending_deposits.push(sp_domains::PendingDeposit {
                    amount: pending_deposit.amount,
                    effective_epoch,
                });
            }
        } else {
            // Epoch hasn't passed yet - keep as pending
            pending_deposits.push(sp_domains::PendingDeposit {
                amount: pending_deposit.amount,
                effective_epoch,
            });
        }
    }

    (total_shares, total_storage_fee_deposit, pending_deposits)
}

/// Calculates adjusted storage fee deposit accounting for fund performance
fn calculate_adjusted_storage_fee<T: Config>(
    operator_id: OperatorId,
    operator_total_storage_fee: BalanceOf<T>,
    nominator_storage_fee: BalanceOf<T>,
) -> BalanceOf<T> {
    use crate::bundle_storage_fund;

    let storage_fund_redeem_price = bundle_storage_fund::storage_fund_redeem_price::<T>(
        operator_id,
        operator_total_storage_fee,
    );

    storage_fund_redeem_price.redeem(nominator_storage_fee)
}

/// Processes pending withdrawals for the nominator
fn process_withdrawals<T: Config>(
    operator_id: OperatorId,
    nominator_account: &T::AccountId,
    current_share_price: &crate::staking::SharePrice,
) -> Vec<sp_domains::PendingWithdrawal<BalanceOf<T>, DomainBlockNumberFor<T>>> {
    let Some(withdrawal) = Withdrawals::<T>::get(operator_id, nominator_account) else {
        return Vec::new();
    };

    let mut pending_withdrawals = Vec::with_capacity(
        withdrawal.withdrawals.len()
            + if withdrawal.withdrawal_in_shares.is_some() {
                1
            } else {
                0
            },
    );

    // Process regular withdrawals
    pending_withdrawals.extend(withdrawal.withdrawals.into_iter().map(|w| {
        sp_domains::PendingWithdrawal {
            amount: w.amount_to_unlock,
            unlock_at_block: w.unlock_at_confirmed_domain_block_number,
        }
    }));

    // Process withdrawal in shares
    if let Some(withdrawal_in_shares) = withdrawal.withdrawal_in_shares {
        let withdrawal_amount =
            OperatorEpochSharePrice::<T>::get(operator_id, withdrawal_in_shares.domain_epoch)
                .map(|epoch_share_price| {
                    epoch_share_price.shares_to_stake::<T>(withdrawal_in_shares.shares)
                })
                .unwrap_or_else(|| {
                    current_share_price.shares_to_stake::<T>(withdrawal_in_shares.shares)
                });

        pending_withdrawals.push(sp_domains::PendingWithdrawal {
            amount: withdrawal_amount,
            unlock_at_block: withdrawal_in_shares.unlock_at_confirmed_domain_block_number,
        });
    }

    pending_withdrawals
}

/// Returns the complete nominator position for a given operator and account.
///
/// This calculates the total position including:
/// - Current stake value (converted from shares using instant share price including rewards)
/// - Total storage fee deposits (known + pending)
/// - Pending deposits (not yet converted to shares)
/// - Pending withdrawals (with unlock timing)
///
/// Returns None if no position exists for the given nominator and operator.
pub fn nominator_position<T: Config>(
    operator_id: OperatorId,
    nominator_account: T::AccountId,
) -> Option<sp_domains::NominatorPosition<BalanceOf<T>, DomainBlockNumberFor<T>>> {
    use sp_domains::NominatorPosition;

    // Fetch core data needed for position calculation
    let position_data = fetch_position_data::<T>(operator_id, &nominator_account)?;

    // Calculate current shares and storage fees from deposits
    let (total_shares, total_storage_fee_deposit, pending_deposits) =
        process_deposits::<T>(&position_data, operator_id);

    // Calculate current staked value using instant share price
    let current_staked_value = position_data
        .current_share_price
        .shares_to_stake::<T>(total_shares);

    // Calculate adjusted storage fee deposit (accounts for fund performance)
    let adjusted_storage_fee_deposit = calculate_adjusted_storage_fee::<T>(
        operator_id,
        position_data.operator.total_storage_fee_deposit,
        total_storage_fee_deposit,
    );

    // Process pending withdrawals
    let pending_withdrawals = process_withdrawals::<T>(
        operator_id,
        &nominator_account,
        &position_data.current_share_price,
    );

    Some(NominatorPosition {
        current_staked_value,
        storage_fee_deposit: sp_domains::StorageFeeDeposit {
            total_deposited: total_storage_fee_deposit,
            current_value: adjusted_storage_fee_deposit,
        },
        pending_deposits,
        pending_withdrawals,
    })
}

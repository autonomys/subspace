//! Bundle storage fund

use crate::staking::NewDeposit;
use crate::staking_epoch::mint_into_treasury;
use crate::{BalanceOf, Config, Event, HoldIdentifier, Operators, Pallet};
use frame_support::traits::fungible::{Inspect, Mutate, MutateHold};
use frame_support::traits::tokens::{Fortitude, Precision, Preservation};
use frame_support::traits::Get;
use frame_support::PalletError;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_domains::OperatorId;
use sp_runtime::traits::{AccountIdConversion, CheckedSub, Zero};
use sp_runtime::Perbill;
use sp_std::collections::btree_map::BTreeMap;
use subspace_runtime_primitives::StorageFee;

/// The proportion of staking fund reserved for the bundle storage fee
pub const STORAGE_FEE_RESERVE: Perbill = Perbill::from_percent(20);

/// Bundle storage fund specific errors
#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum Error {
    BundleStorageFeePayment,
    BalanceUnderflow,
    MintBalance,
    FailToDeposit,
    WithdrawAndHold,
    BalanceTransfer,
    FailToWithdraw,
}

/// The type of system account being created.
#[derive(Encode, Decode)]
pub enum AccountType {
    StorageFund,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq, Default)]
pub struct StorageFundRedeemPrice<T: Config>((BalanceOf<T>, BalanceOf<T>));

impl<T: Config> StorageFundRedeemPrice<T> {
    pub(crate) fn new(total_balance: BalanceOf<T>, total_deposit: BalanceOf<T>) -> Self {
        StorageFundRedeemPrice((total_balance, total_deposit))
    }

    /// Return the amount of balance can be redeemed by the given `deposit`, it is calculated
    /// by `storage_fund_total_balance * deposit / total_deposit`.
    ///
    /// If the inflow of the storage fund (i.e. refund of the storage fee) is larger than its
    /// outflow (i.e. payment of the storage fee), the return value will larger than `deposit`
    /// otherwise smaller.
    pub(crate) fn redeem(&self, deposit: BalanceOf<T>) -> BalanceOf<T> {
        let (total_balance, total_deposit) = self.0;
        if total_balance == total_deposit {
            deposit
        } else {
            Perbill::from_rational(deposit, total_deposit).mul_floor(total_balance)
        }
    }
}

/// Return the bundle storage fund account of the given operator.
pub fn storage_fund_account<T: Config>(id: OperatorId) -> T::AccountId {
    T::PalletId::get().into_sub_account_truncating((AccountType::StorageFund, id))
}

/// Charge the bundle storage fee from the operator's bundle storage fund
pub fn charge_bundle_storage_fee<T: Config>(
    operator_id: OperatorId,
    bundle_size: u32,
) -> Result<(), Error> {
    if bundle_size.is_zero() {
        return Ok(());
    }

    let storage_fund_acc = storage_fund_account::<T>(operator_id);
    let storage_fee = T::StorageFee::transaction_byte_fee() * bundle_size.into();

    if let Err(err) = T::Currency::burn_from(
        &storage_fund_acc,
        storage_fee,
        Preservation::Expendable,
        Precision::Exact,
        Fortitude::Polite,
    ) {
        let total_balance = total_balance::<T>(operator_id);
        log::debug!(
            "Operator {operator_id:?} unable to pay for the bundle storage fee {storage_fee:?}, storage fund total balance {total_balance:?}, err {err:?}",
        );
        return Err(Error::BundleStorageFeePayment);
    }

    // Note the storage fee, it will go to the consensus block author
    T::StorageFee::note_storage_fees(storage_fee);

    Ok(())
}

/// Refund the paid bundle storage fee of a particular domain block back to the operator, the amount to
/// refund to a particular operator is determined by the total storage fee collected from the domain user
/// and the percentage of bundle storage that the operator have submitted for the domain block.
pub fn refund_storage_fee<T: Config>(
    total_storage_fee: BalanceOf<T>,
    paid_bundle_storage_fees: BTreeMap<OperatorId, u32>,
) -> Result<(), Error> {
    if total_storage_fee.is_zero() {
        return Ok(());
    }

    let total_paid_storage = paid_bundle_storage_fees.values().sum::<u32>();
    let mut remaining_fee = total_storage_fee;
    for (operator_id, paid_storage) in paid_bundle_storage_fees {
        // If the operator is deregistered and unlocked or slashed and finalized, the refund bundle storage
        // fee will go to the treasury
        if Operators::<T>::get(operator_id).is_none() || paid_storage.is_zero() {
            continue;
        }

        let refund_amount = {
            let paid_storage_percentage = Perbill::from_rational(paid_storage, total_paid_storage);
            paid_storage_percentage.mul_floor(total_storage_fee)
        };
        let storage_fund_acc = storage_fund_account::<T>(operator_id);
        T::Currency::mint_into(&storage_fund_acc, refund_amount).map_err(|_| Error::MintBalance)?;

        remaining_fee = remaining_fee
            .checked_sub(&refund_amount)
            .ok_or(Error::BalanceUnderflow)?;
    }

    // Drop any dust and deregistered/slashed operator's bundle storage fee to the treasury
    mint_into_treasury::<T>(remaining_fee).map_err(|_| Error::MintBalance)?;

    Ok(())
}

/// Split the new deposit into 2 parts: the staking deposit and the storage fee deposit,
/// add the storage fee deposit to the bundle storage fund.
pub fn deposit_reserve_for_storage_fund<T: Config>(
    operator_id: OperatorId,
    source: &T::AccountId,
    deposit_amount: BalanceOf<T>,
) -> Result<NewDeposit<BalanceOf<T>>, Error> {
    let storage_fund_acc = storage_fund_account::<T>(operator_id);

    let storage_fee_reserve = STORAGE_FEE_RESERVE.mul_floor(deposit_amount);

    T::Currency::transfer(
        source,
        &storage_fund_acc,
        storage_fee_reserve,
        Preservation::Preserve,
    )
    .map_err(|_| Error::FailToDeposit)?;

    Pallet::<T>::deposit_event(Event::StorageFeeDeposited {
        operator_id,
        nominator_id: source.clone(),
        amount: storage_fee_reserve,
    });

    let staking = deposit_amount
        .checked_sub(&storage_fee_reserve)
        .ok_or(Error::BalanceUnderflow)?;

    Ok(NewDeposit {
        staking,
        storage_fee_deposit: storage_fee_reserve,
    })
}

/// Transfer the given `withdraw_amount` of balance from the bundle storage fund to the
/// given `dest_account` and hold on the `dest_account`
pub fn withdraw_and_hold<T: Config>(
    operator_id: OperatorId,
    dest_account: &T::AccountId,
    withdraw_amount: BalanceOf<T>,
) -> Result<BalanceOf<T>, Error> {
    if withdraw_amount.is_zero() {
        return Ok(Zero::zero());
    }

    let storage_fund_acc = storage_fund_account::<T>(operator_id);
    let storage_fund_hold_id = T::HoldIdentifier::storage_fund_withdrawal();
    T::Currency::transfer_and_hold(
        &storage_fund_hold_id,
        &storage_fund_acc,
        dest_account,
        withdraw_amount,
        Precision::Exact,
        Preservation::Expendable,
        Fortitude::Force,
    )
    .map_err(|_| Error::WithdrawAndHold)
}

/// Transfer the given `withdraw_amount` of balance from the bundle storage fund to the
/// given `dest_account`
pub fn withdraw_to<T: Config>(
    operator_id: OperatorId,
    dest_account: &T::AccountId,
    withdraw_amount: BalanceOf<T>,
) -> Result<BalanceOf<T>, Error> {
    if withdraw_amount.is_zero() {
        return Ok(Zero::zero());
    }

    let storage_fund_acc = storage_fund_account::<T>(operator_id);
    T::Currency::transfer(
        &storage_fund_acc,
        dest_account,
        withdraw_amount,
        Preservation::Expendable,
    )
    .map_err(|_| Error::FailToWithdraw)
}

/// Return the total balance of the bundle storage fund the given `operator_id`
pub fn total_balance<T: Config>(operator_id: OperatorId) -> BalanceOf<T> {
    let storage_fund_acc = storage_fund_account::<T>(operator_id);
    T::Currency::reducible_balance(
        &storage_fund_acc,
        Preservation::Expendable,
        Fortitude::Polite,
    )
}

/// Return the bundle storage fund redeem price
pub fn storage_fund_redeem_price<T: Config>(
    operator_id: OperatorId,
    operator_total_deposit: BalanceOf<T>,
) -> StorageFundRedeemPrice<T> {
    let total_balance = total_balance::<T>(operator_id);
    StorageFundRedeemPrice::<T>::new(total_balance, operator_total_deposit)
}

/// Transfer all of the balance of the bundle storage fund to the treasury
pub fn transfer_all_to_treasury<T: Config>(operator_id: OperatorId) -> Result<(), Error> {
    let storage_fund_acc = storage_fund_account::<T>(operator_id);
    let total_balance = total_balance::<T>(operator_id);
    T::Currency::transfer(
        &storage_fund_acc,
        &T::TreasuryAccount::get(),
        total_balance,
        Preservation::Expendable,
    )
    .map_err(|_| Error::BalanceTransfer)?;
    Ok(())
}

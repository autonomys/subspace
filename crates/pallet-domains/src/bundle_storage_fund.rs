//! Bundle storage fund

use crate::{BalanceOf, Config, Operators};
use codec::{Decode, Encode};
use frame_support::traits::fungible::Mutate;
use frame_support::traits::tokens::{Fortitude, Precision, Preservation};
use frame_support::traits::Get;
use frame_support::PalletError;
use scale_info::TypeInfo;
use sp_domains::OperatorId;
use sp_runtime::traits::{AccountIdConversion, CheckedSub, Zero};
use sp_runtime::Perbill;
use sp_std::collections::btree_map::BTreeMap;
use subspace_runtime_primitives::StorageFeeInterface;

/// The proportion of staking fund reserved for the bundle storage fee
pub const STORAGE_FEE_RESERVE: Perbill = Perbill::from_percent(20);

/// Bundle storage fund specific errors
#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum Error {
    FailedToDeriveStorageFundAccount,
    BundleStorageFeePayment,
    BalanceUnderflow,
    MintBalance,
    FailToDeposit,
}

/// The type of system account being created.
#[derive(Encode, Decode)]
pub enum AccountType {
    StorageFund,
}

/// Return the bundle storage fund account of the given operator.
pub fn storage_fund_account<T: Config>(id: OperatorId) -> Result<T::AccountId, Error> {
    T::PalletId::get()
        .try_into_sub_account((AccountType::StorageFund, id))
        .ok_or(Error::FailedToDeriveStorageFundAccount)
}

/// Charge the bundle storage fee from the operator's bundle storage fund
pub fn charge_bundle_storage_fee<T: Config>(
    operator_id: OperatorId,
    bundle_size: u32,
) -> Result<(), Error> {
    if bundle_size.is_zero() {
        return Ok(());
    }

    let storage_fund_acc = storage_fund_account::<T>(operator_id)?;
    let storage_fee = T::StorageFeeInterface::transaction_byte_fee() * bundle_size.into();

    T::Currency::burn_from(
        &storage_fund_acc,
        storage_fee,
        Precision::Exact,
        Fortitude::Polite,
    )
    .map_err(|_| Error::BundleStorageFeePayment)?;

    // Note the storage fee, it will go to the consensus block author
    T::StorageFeeInterface::note_storage_fees(storage_fee);

    Ok(())
}

/// Refund the front paid storage fee of a particular domain block back to the operator, the amount to
/// refund to a particular operator is determined by the total storage fee collected from the domain user
/// and the percentage of bundle storage that the operator have submitted for the domain block.
#[allow(dead_code)]
pub fn refund_storage_fee<T: Config>(
    total_storage_fee: BalanceOf<T>,
    front_paid_storage: BTreeMap<OperatorId, u32>,
) -> Result<(), Error> {
    if total_storage_fee.is_zero() {
        return Ok(());
    }

    let total_paid_storage = front_paid_storage.values().sum::<u32>();
    let mut remaining_fee = total_storage_fee;
    for (operator_id, paid_storage) in front_paid_storage {
        // If the operator is deregistered and unlocked or slashed and finalized, the refund bundle storage
        // fee will go to the treasury
        if Operators::<T>::get(operator_id).is_none() || paid_storage.is_zero() {
            continue;
        }

        let refund_amount = {
            let share = Perbill::from_rational(paid_storage, total_paid_storage);
            share.mul_floor(total_storage_fee)
        };
        let storage_fund_acc = storage_fund_account::<T>(operator_id)?;
        T::Currency::mint_into(&storage_fund_acc, refund_amount).map_err(|_| Error::MintBalance)?;

        remaining_fee = remaining_fee
            .checked_sub(&refund_amount)
            .ok_or(Error::BalanceUnderflow)?;
    }

    // Drop any dust and deregistered/slashed operator's bundle storage fee to the treasury
    if !remaining_fee.is_zero() {
        T::Currency::mint_into(&T::TreasuryAccount::get(), remaining_fee)
            .map_err(|_| Error::MintBalance)?;
    }

    Ok(())
}

/// Split a proportion of the deposit to reserve for the bundle storage fund
///
/// Return new deposit amount after deduction of the reserved fund
pub fn deposit_reserve_for_storage_fund<T: Config>(
    operator_id: OperatorId,
    source: &T::AccountId,
    deposit_amount: BalanceOf<T>,
) -> Result<BalanceOf<T>, Error> {
    let storage_fund_acc = storage_fund_account::<T>(operator_id)?;

    let storage_fee_reserve = STORAGE_FEE_RESERVE.mul_floor(deposit_amount);

    T::Currency::transfer(
        source,
        &storage_fund_acc,
        storage_fee_reserve,
        Preservation::Preserve,
    )
    .map_err(|_| Error::FailToDeposit)?;

    deposit_amount
        .checked_sub(&storage_fee_reserve)
        .ok_or(Error::BalanceUnderflow)
}

// TODO: add withdraw function for the bundle storage fund and call it then withdraw happen

//! Fees module for EVM domain

use crate::Config;
use core::marker::PhantomData;
use domain_runtime_primitives::Balance;
use pallet_block_fees::Pallet as BlockFees;
use pallet_evm::FeeCalculator;
use pallet_transaction_payment::Pallet as TransactionPayment;
use sp_core::U256;
use sp_evm_tracker::WEIGHT_PER_GAS;
use sp_runtime::traits::Get;
use sp_runtime::{FixedPointNumber, Perbill};
use sp_weights::Weight;

/// Evm gas price calculator for EVM domains.
/// TransactionWeightFee is the fee for 1 unit of Weight.
/// GasPerByte is the gas for 1 byte
pub struct EvmGasPriceCalculator<T, TransactionWeightFee, GasPerByte, StorageFeePercent>(
    PhantomData<(T, TransactionWeightFee, GasPerByte, StorageFeePercent)>,
);

impl<T, TransactionWeightFee, GasPerByte, StorageFeePercent> FeeCalculator
    for EvmGasPriceCalculator<T, TransactionWeightFee, GasPerByte, StorageFeePercent>
where
    T: Config
        + frame_system::Config
        + pallet_transaction_payment::Config
        + pallet_block_fees::Config<Balance = Balance>,
    TransactionWeightFee: Get<T::Balance>,
    GasPerByte: Get<T::Balance>,
{
    fn min_gas_price() -> (U256, Weight) {
        // spread the storage fee across the gas price based on the Gas Per Byte.
        let storage_fee_per_gas =
            BlockFees::<T>::final_domain_transaction_byte_fee().div_ceil(GasPerByte::get());
        // adjust the fee per weight using the multiplier
        let weight_fee = TransactionWeightFee::get().saturating_mul(WEIGHT_PER_GAS.into());
        let adjusted_weight_fee =
            TransactionPayment::<T>::next_fee_multiplier().saturating_mul_int(weight_fee);

        // finally add the storage_fee_per_gas and adjusted_weight_fee to calculate the final
        // min_gas_price.
        let min_gas_price = adjusted_weight_fee.saturating_add(storage_fee_per_gas);
        (
            min_gas_price.into(),
            <T as frame_system::Config>::DbWeight::get().reads(2),
        )
    }
}

impl<T, TransactionWeightFee, BytePerFee, StorageFeePercent>
    EvmGasPriceCalculator<T, TransactionWeightFee, BytePerFee, StorageFeePercent>
where
    StorageFeePercent: Get<Perbill>,
{
    pub fn split_fee_into_storage_and_execution(fee: Balance) -> (Balance, Balance) {
        let ratio = StorageFeePercent::get();
        let storage_fee = ratio.mul_ceil(fee);
        (storage_fee, fee.saturating_sub(storage_fee))
    }
}

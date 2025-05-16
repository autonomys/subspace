//! Inherents for EVM tracker
#![cfg_attr(not(feature = "std"), no_std)]

use domain_runtime_primitives::{Balance, EthereumAccountId, maximum_domain_block_weight};
use frame_support::parameter_types;
use frame_support::sp_runtime::Perbill;
use frame_support::sp_runtime::app_crypto::sp_core::U256;
use parity_scale_codec::{Decode, Encode};
use sp_domains::PermissionedActionAllowedBy;
#[cfg(feature = "std")]
use sp_inherents::{Error, InherentData};
use sp_inherents::{InherentIdentifier, IsFatalError};
use sp_weights::Weight;
use sp_weights::constants::WEIGHT_REF_TIME_PER_SECOND;

/// Current approximation of the gas/s consumption considering
/// EVM execution over compiled WASM (on 4.4Ghz CPU).
pub const GAS_PER_SECOND: u64 = 40_000_000;

/// Approximate ratio of the amount of Weight per Gas.
/// u64 works for approximations because Weight is a very small unit compared to gas.
pub const WEIGHT_PER_GAS: u64 = WEIGHT_REF_TIME_PER_SECOND.div_ceil(GAS_PER_SECOND);

parameter_types! {
    pub const GasLimitPovSizeRatio: u64 = 4;
    /// Gas per byte
    /// Ethereum’s Yellow Paper states that it costs 20,000 gas to store one 256-bit word.
    /// 1 Byte costs 20_000/32 = 625
    pub const GasPerByte: Balance = 625;
    /// Proportion of final (gas_price * gas_used) given as storage fee.
    pub const StorageFeeRatio: Perbill = Perbill::from_percent(30);
    /// EVM block gas limit is set to maximum to allow all the transaction stored on Consensus chain.
    pub BlockGasLimit: U256 = U256::from(
        maximum_domain_block_weight().ref_time() / WEIGHT_PER_GAS
    );
    pub WeightPerGas: Weight = Weight::from_parts(WEIGHT_PER_GAS, 0);
}

/// Executive inherent identifier.
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"dmnevmtr";

#[derive(Debug, Encode)]
#[cfg_attr(feature = "std", derive(Decode))]
pub enum InherentError {
    MissingRuntimeCall,
    InvalidRuntimeCall,
    IncorrectRuntimeCall,
}

impl IsFatalError for InherentError {
    fn is_fatal_error(&self) -> bool {
        true
    }
}

/// The type of the Subspace inherent data.
#[derive(Debug, Encode, Decode)]
pub struct InherentType {
    /// EVM tracker "set contract creation allowed by" call
    pub maybe_call: Option<PermissionedActionAllowedBy<EthereumAccountId>>,
}

/// Provides the set code inherent data.
#[cfg(feature = "std")]
pub struct InherentDataProvider {
    data: InherentType,
}

#[cfg(feature = "std")]
impl InherentDataProvider {
    /// Create new inherent data provider from the given `data`.
    pub fn new(maybe_call: Option<PermissionedActionAllowedBy<EthereumAccountId>>) -> Self {
        Self {
            data: InherentType { maybe_call },
        }
    }

    /// Returns the `data` of this inherent data provider.
    pub fn data(&self) -> &InherentType {
        &self.data
    }
}

#[cfg(feature = "std")]
#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for InherentDataProvider {
    async fn provide_inherent_data(&self, inherent_data: &mut InherentData) -> Result<(), Error> {
        inherent_data.put_data(INHERENT_IDENTIFIER, &self.data)
    }

    async fn try_handle_error(
        &self,
        identifier: &InherentIdentifier,
        error: &[u8],
    ) -> Option<Result<(), Error>> {
        if *identifier != INHERENT_IDENTIFIER {
            return None;
        }

        let error = InherentError::decode(&mut &*error).ok()?;

        Some(Err(Error::Application(Box::from(format!("{error:?}")))))
    }
}

sp_api::decl_runtime_apis! {
    /// Api to check and verify the evm-tracker extrinsic calls
    pub trait EvmTrackerApi {
        /// Returns an encoded extrinsic for domain "set contract creation allowed by" call.
        fn construct_evm_contract_creation_allowed_by_extrinsic(decoded_argument: PermissionedActionAllowedBy<EthereumAccountId>) -> Block::Extrinsic;
    }
}

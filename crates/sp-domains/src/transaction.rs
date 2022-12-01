#[cfg(not(feature = "std"))]
pub use self::runtime_decl_for_PreValidationObjectApi::PreValidationObjectApi;
use crate::fraud_proof::FraudProof;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::transaction_validity::{InvalidTransaction, TransactionValidity};

/// Custom invalid validity code for the extrinsics in pallet-domains.
#[repr(u8)]
pub enum InvalidTransactionCode {
    BundleEquivicationProof = 101,
    TrasactionProof = 102,
    ExecutionReceipt = 103,
    Bundle = 104,
    FraudProof = 105,
}

impl From<InvalidTransactionCode> for InvalidTransaction {
    fn from(invalid_code: InvalidTransactionCode) -> Self {
        InvalidTransaction::Custom(invalid_code as u8)
    }
}

impl From<InvalidTransactionCode> for TransactionValidity {
    fn from(invalid_code: InvalidTransactionCode) -> Self {
        InvalidTransaction::Custom(invalid_code as u8).into()
    }
}

/// Object for performing the pre-validation in the transaction pool
/// before calling into the regular `validate_transaction` runtime api.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum PreValidationObject {
    Null,
    FraudProof(FraudProof),
    // TODO: extract receipts from submit_bundle extrinsic.
    // Receipts(Vec<ExecutionReceipt>)
}

sp_api::decl_runtime_apis! {
    /// API for extracting the pre-validation objects in the primary chain transaction pool wrapper.
    pub trait PreValidationObjectApi {
        /// Extract the pre-validation object from the given extrinsic.
        fn extract_pre_validation_object(extrinsics: Block::Extrinsic) -> PreValidationObject;
    }
}

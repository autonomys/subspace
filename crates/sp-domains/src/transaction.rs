use crate::fraud_proof::FraudProof;
use crate::SignedOpaqueBundle;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_runtime::traits::{Block as BlockT, NumberFor};
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
pub enum PreValidationObject<Block, DomainHash>
where
    Block: BlockT,
{
    Null,
    FraudProof(FraudProof<NumberFor<Block>, Block::Hash>),
    Bundle(SignedOpaqueBundle<NumberFor<Block>, Block::Hash, DomainHash>),
}

sp_api::decl_runtime_apis! {
    /// API for extracting the pre-validation objects in the primary chain transaction pool wrapper.
    pub trait PreValidationObjectApi<DomainHash: Encode + Decode> {
        /// Extract the pre-validation object from the given extrinsic.
        fn extract_pre_validation_object(extrinsics: Block::Extrinsic) -> PreValidationObject<Block, DomainHash>;
    }
}

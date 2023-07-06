use crate::fraud_proof::FraudProof;
use crate::OpaqueBundle;
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
    #[inline]
    fn from(invalid_code: InvalidTransactionCode) -> Self {
        InvalidTransaction::Custom(invalid_code as u8)
    }
}

impl From<InvalidTransactionCode> for TransactionValidity {
    #[inline]
    fn from(invalid_code: InvalidTransactionCode) -> Self {
        InvalidTransaction::Custom(invalid_code as u8).into()
    }
}

/// Object for performing the pre-validation in the transaction pool
/// before calling into the regular `validate_transaction` runtime api.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub enum PreValidationObject<Block, DomainNumber, DomainHash>
where
    Block: BlockT,
{
    Null,
    FraudProof(FraudProof<NumberFor<Block>, Block::Hash>),
    Bundle(OpaqueBundle<NumberFor<Block>, Block::Hash, DomainNumber, DomainHash>),
}

sp_api::decl_runtime_apis! {
    /// API for extracting the pre-validation objects in the primary chain transaction pool wrapper.
    pub trait PreValidationObjectApi<DomainNumber: Encode + Decode, DomainHash: Encode + Decode> {
        /// Extract the pre-validation object from the given extrinsic.
        fn extract_pre_validation_object(
            extrinsics: Block::Extrinsic,
        ) -> PreValidationObject<Block, DomainNumber, DomainHash>;
    }
}

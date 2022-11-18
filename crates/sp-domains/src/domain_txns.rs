use crate::DomainId;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_std::vec::Vec;

/// Holds an encoded extrinsic that is bound to domain mapped to domain_id.
#[derive(Debug, Decode, Encode, TypeInfo, PartialEq, Eq, Clone)]
pub struct DomainExtrinsic {
    /// Domain Id this transaction is destined to.
    pub domain_id: DomainId,
    /// Encoded transaction.
    pub txn: Vec<u8>,
}

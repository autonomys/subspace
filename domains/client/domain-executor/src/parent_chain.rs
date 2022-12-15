use subspace_core_primitives::BlockNumber;

/// Trait for interacting between the domain and its corresponding parent chain, i.e. retrieving
/// the necessary info from the parent chain or submit extrinsics to the parent chain.
///
/// - System Domain's parent chain => Primary Chain
/// - Core Domain's parent chain => System Domain
pub(crate) trait ParentChainInterface<Hash> {
    fn head_receipt_number(&self, at: Hash) -> Result<BlockNumber, sp_api::ApiError>;
    fn maximum_receipt_drift(&self, at: Hash) -> Result<BlockNumber, sp_api::ApiError>;
}

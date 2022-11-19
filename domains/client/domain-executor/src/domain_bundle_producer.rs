use subspace_core_primitives::BlockNumber;

/// Trait for retrieving the necessary info for collecting the receipts in a new domain bundle.
pub(crate) trait ReceiptInterface<Hash> {
    fn best_execution_chain_number(&self, at: Hash) -> Result<BlockNumber, sp_api::ApiError>;
    fn maximum_receipt_drift(&self, at: Hash) -> Result<BlockNumber, sp_api::ApiError>;
}

use domain_runtime_primitives::opaque::AccountId;
use sp_api::{ApiError, BlockT};
use sp_messenger::messages::ExtractedStateRootsFromProof;
use sp_runtime::traits::NumberFor;

pub type ExtractedStateRoots<Block> = ExtractedStateRootsFromProof<
    NumberFor<Block>,
    <Block as BlockT>::Hash,
    <Block as BlockT>::Hash,
>;

/// Trait to extract XDM state roots from the Extrinsic.
pub trait StateRootExtractor<Block: BlockT> {
    /// Extracts the state roots from the extrinsic.
    fn extract_state_roots(
        &self,
        at: Block::Hash,
        ext: &Block::Extrinsic,
    ) -> Result<ExtractedStateRoots<Block>, ApiError>;
}

/// Trait to construct timestamp extrinsic.
pub trait TimestampExtrinsicConstructor<Block: BlockT> {
    /// Returns encoded timestamp extrinsic for the given time.
    fn construct_timestamp_extrinsic(
        &self,
        at: Block::Hash,
        moment: subspace_runtime_primitives::Moment,
    ) -> Result<Block::Extrinsic, ApiError>;
}

/// Trait to wrap the new domain runtime as an extrinsic of
/// `domain_pallet_executive::Call::sudo_unchecked_weight_unsigned`.
pub trait SetCodeConstructor<Block: BlockT> {
    fn construct_set_code_extrinsic(
        &self,
        at: Block::Hash,
        runtime_code: Vec<u8>,
    ) -> Result<Vec<u8>, ApiError>;
}

/// Trait to wrap the new domain runtime as an extrinsic of
/// `domain_pallet_executive::Call::sudo_unchecked_weight_unsigned`.
pub trait IsInherentExtrinsic<Block: BlockT> {
    fn is_inherent_extrinsic(
        &self,
        at: Block::Hash,
        extrinsic: &<Block as BlockT>::Extrinsic,
    ) -> Result<bool, ApiError>;
}

pub type ExtractSignerResult<Block> = Vec<(Option<AccountId>, <Block as BlockT>::Extrinsic)>;

/// Trait to extract the signer of the extrinsic.
pub trait SignerExtractor<Block: BlockT> {
    fn extract_signer(
        &self,
        at: Block::Hash,
        extrinsics: Vec<<Block as BlockT>::Extrinsic>,
    ) -> Result<ExtractSignerResult<Block>, ApiError>;
}

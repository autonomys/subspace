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

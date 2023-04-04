use sp_api::{ApiError, BlockT};
use sp_domains::SignedOpaqueBundle;
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

/// Trait to extract core domain bundles from the given set of core domain extrinsics.
pub trait CoreBundleConstructor<PBlock: BlockT, Block: BlockT> {
    fn construct_submit_core_bundle_extrinsics(
        &self,
        at: Block::Hash,
        signed_opaque_bundles: Vec<
            SignedOpaqueBundle<NumberFor<PBlock>, PBlock::Hash, Block::Hash>,
        >,
    ) -> Result<Vec<Vec<u8>>, ApiError>;
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

pub type ExtractSignerResult<Block, AccountId> =
    Vec<(Option<AccountId>, <Block as BlockT>::Extrinsic)>;

/// Trait to extract the signer of the extrinsic.
pub trait SignerExtractor<Block: BlockT, AccountId> {
    fn extract_signer(
        &self,
        at: Block::Hash,
        extrinsics: Vec<<Block as BlockT>::Extrinsic>,
    ) -> Result<ExtractSignerResult<Block, AccountId>, ApiError>;
}

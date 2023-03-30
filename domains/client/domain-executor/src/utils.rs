use codec::{Decode, Encode};
use sp_api::{ApiError, RuntimeApiInfo, RuntimeVersion};
use sp_consensus_slots::Slot;
use sp_messenger::messages::ExtractedStateRootsFromProof;
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::convert::TryInto;
use subspace_core_primitives::{Blake2b256Hash, BlockNumber};

pub(crate) type ExtractedStateRoots<Block> = ExtractedStateRootsFromProof<
    NumberFor<Block>,
    <Block as BlockT>::Hash,
    <Block as BlockT>::Hash,
>;

/// Data required to produce bundles on executor node.
#[derive(PartialEq, Clone, Debug)]
pub(super) struct ExecutorSlotInfo {
    /// Slot
    pub(super) slot: Slot,
    /// Global challenge
    pub(super) global_challenge: Blake2b256Hash,
}

/// An event telling the `Overseer` on the particular block
/// that has been imported or finalized.
///
/// This structure exists solely for the purposes of decoupling
/// `Overseer` code from the client code and the necessity to call
/// `HeaderBackend::block_number_from_id()`.
#[derive(Debug, Clone)]
pub struct BlockInfo<Block>
where
    Block: BlockT,
{
    /// hash of the block.
    pub hash: Block::Hash,
    /// hash of the parent block.
    pub parent_hash: Block::Hash,
    /// block's number.
    pub number: NumberFor<Block>,
}

// TODO: unify this with trait bounds set directly on block traits.
// Maybe we dont need these translations.?
/// Converts the block number from the generic type `N1` to `N2`.
pub(crate) fn translate_number_type<N1, N2>(block_number: N1) -> N2
where
    N1: TryInto<BlockNumber>,
    N2: From<BlockNumber>,
{
    N2::from(to_number_primitive(block_number))
}

/// Converts a generic block number to a concrete primitive block number.
pub(crate) fn to_number_primitive<N>(block_number: N) -> BlockNumber
where
    N: TryInto<BlockNumber>,
{
    block_number
        .try_into()
        .unwrap_or_else(|_| panic!("Block number must fit into u32; qed"))
}

/// Converts the block hash from the generic type `B1::Hash` to `B2::Hash`.
pub(crate) fn translate_block_hash_type<B1, B2>(block_hash: B1::Hash) -> B2::Hash
where
    B1: BlockT,
    B2: BlockT,
{
    B2::Hash::decode(&mut block_hash.encode().as_slice()).unwrap()
}

pub(crate) fn extract_xdm_proof_state_roots_with_runtime<MAPI, SBlock>(
    runtime_version: RuntimeVersion,
    messenger_api: &MAPI,
    best_hash: SBlock::Hash,
    ext: &SBlock::Extrinsic,
) -> Result<Option<ExtractedStateRoots<SBlock>>, ApiError>
where
    SBlock: BlockT,
    MAPI: MessengerApi<SBlock, NumberFor<SBlock>>,
{
    let messenger_api_version = runtime_version
        .api_version(&<dyn MessengerApi<SBlock, NumberFor<SBlock>> as RuntimeApiInfo>::ID)
        .ok_or(ApiError::Application(
            format!("Could not find `MessengerApi` api for block `{best_hash:?}`.").into(),
        ))?;

    extract_xdm_proof_state_roots_with_client::<MAPI, SBlock>(
        messenger_api_version,
        messenger_api,
        best_hash,
        ext,
    )
}

pub(crate) fn extract_xdm_proof_state_roots_with_client<MAPI, SBlock>(
    messenger_api_version: u32,
    messenger_api: &MAPI,
    best_hash: SBlock::Hash,
    ext: &SBlock::Extrinsic,
) -> Result<Option<ExtractedStateRoots<SBlock>>, ApiError>
where
    SBlock: BlockT,
    MAPI: MessengerApi<SBlock, NumberFor<SBlock>>,
{
    if messenger_api_version >= 2 {
        // Calling latest version of MessengerApi
        messenger_api.extract_xdm_proof_state_roots(best_hash, ext.encode())
    } else {
        // Calling earlier versions of MessengerApi
        // Since there is only one version at the moment, we can directly call it without checking version, in future if more versions are added
        // we need more else if branches.
        #[allow(deprecated)]
        messenger_api.extract_xdm_proof_state_roots_before_version_2(best_hash, ext)
    }
}

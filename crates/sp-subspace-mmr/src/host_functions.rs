use crate::runtime_interface::LeafData;
use sp_blockchain::HeaderBackend;
use sp_core::H256;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use std::marker::PhantomData;
use std::sync::Arc;

/// Trait to query MMR specific data through host function..
pub trait SubspaceMmrHostFunctions: Send + Sync {
    /// Returns the MMR Leaf data for given consensus block hash
    fn get_mmr_leaf_data(&self, consensus_block_hash: H256) -> Option<LeafData>;
}

sp_externalities::decl_extension! {
    pub struct SubspaceMmrExtension(Arc<dyn SubspaceMmrHostFunctions>);
}

impl SubspaceMmrExtension {
    /// Create a new instance of [`SubspaceMmrExtension`].
    pub fn new(inner: Arc<dyn SubspaceMmrHostFunctions>) -> Self {
        Self(inner)
    }
}

/// Implementation of MMR host function.
pub struct SubspaceMmrHostFunctionsImpl<Block, Client> {
    consensus_client: Arc<Client>,
    _phantom: PhantomData<Block>,
}

impl<Block, Client> SubspaceMmrHostFunctionsImpl<Block, Client> {
    pub fn new(consensus_client: Arc<Client>) -> Self {
        SubspaceMmrHostFunctionsImpl {
            consensus_client,
            _phantom: Default::default(),
        }
    }
}

impl<Block, Client> SubspaceMmrHostFunctions for SubspaceMmrHostFunctionsImpl<Block, Client>
where
    Block: BlockT,
    Block::Hash: From<H256>,
    Client: HeaderBackend<Block>,
{
    fn get_mmr_leaf_data(&self, consensus_block_hash: H256) -> Option<LeafData> {
        let header = self
            .consensus_client
            .header(consensus_block_hash.into())
            .ok()
            .flatten()?;

        Some(LeafData {
            state_root: H256::from_slice(header.state_root().as_ref()),
            extrinsics_root: H256::from_slice(header.extrinsics_root().as_ref()),
        })
    }
}

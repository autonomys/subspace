use crate::runtime_interface::LeafData;
use codec::Decode;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::H256;
pub use sp_mmr_primitives::{EncodableOpaqueLeaf, MmrApi, Proof};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use std::marker::PhantomData;
use std::sync::Arc;

/// Trait to query MMR specific data through host function..
pub trait SubspaceMmrHostFunctions: Send + Sync {
    /// Returns the MMR Leaf data for given consensus block hash
    fn get_mmr_leaf_data(&self, consensus_block_hash: H256) -> Option<LeafData>;

    /// Verifies the mmr proof using consensus chain.
    fn verify_mmr_proof(&self, leaves: Vec<EncodableOpaqueLeaf>, encoded_proof: Vec<u8>) -> bool;
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
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: MmrApi<Block, H256, NumberFor<Block>>,
{
    fn get_mmr_leaf_data(&self, consensus_block_hash: H256) -> Option<LeafData> {
        let header = self
            .consensus_client
            .header(consensus_block_hash.into())
            .expect(
                "Database error is fatal in host function, there is no recovery from this; qed",
            )?;

        Some(LeafData {
            state_root: H256::from_slice(header.state_root().as_ref()),
            extrinsics_root: H256::from_slice(header.extrinsics_root().as_ref()),
        })
    }

    fn verify_mmr_proof(&self, leaves: Vec<EncodableOpaqueLeaf>, encoded_proof: Vec<u8>) -> bool {
        // always use the parent hash in case there is a re-org happening
        let parent_hash = *self
            .consensus_client
            .header(self.consensus_client.info().best_hash)
            .expect("Database error is fatal in host function, there is no recovery from this; qed")
            .expect("Header must be available. There is no recovery if not available; qed.")
            .parent_hash();
        let api = self.consensus_client.runtime_api();
        let proof = match Proof::<H256>::decode(&mut encoded_proof.as_ref()) {
            Ok(proof) => proof,
            Err(_) => return false,
        };
        api.verify_proof(parent_hash, leaves, proof).expect(
            "Runtime Api should not fail in host function, there is no recovery from this; qed.",
        ).is_ok()
    }
}

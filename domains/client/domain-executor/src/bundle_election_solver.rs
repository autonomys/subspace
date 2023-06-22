use sc_client_api::ProofProvider;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_domains::{BundleSolution, DomainId, ExecutorPublicKey};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::Block as BlockT;
use sp_runtime::RuntimeAppPublic;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;

pub(super) struct BundleElectionSolver<Block, SBlock, PBlock, SClient> {
    system_domain_client: Arc<SClient>,
    keystore: KeystorePtr,
    _phantom_data: PhantomData<(Block, SBlock, PBlock)>,
}

impl<Block, SBlock, PBlock, SClient> Clone
    for BundleElectionSolver<Block, SBlock, PBlock, SClient>
{
    fn clone(&self) -> Self {
        Self {
            system_domain_client: self.system_domain_client.clone(),
            keystore: self.keystore.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, SBlock, PBlock, SClient> BundleElectionSolver<Block, SBlock, PBlock, SClient>
where
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock>,
{
    pub(super) fn new(system_domain_client: Arc<SClient>, keystore: KeystorePtr) -> Self {
        Self {
            system_domain_client,
            keystore,
            _phantom_data: PhantomData,
        }
    }

    pub(super) fn solve_bundle_election_challenge(
        &self,
        _best_hash: SBlock::Hash,
        _best_number: NumberFor<SBlock>,
        domain_id: DomainId,
        _global_challenge: Blake2b256Hash,
    ) -> sp_blockchain::Result<Option<BundleSolution<Block::Hash>>> {
        // TODO: Implement Bundle Producer Election v2

        if let Some(authority_id) = self
            .keystore
            .sr25519_public_keys(ExecutorPublicKey::ID)
            .into_iter()
            .next()
        {
            return Ok(Some(BundleSolution::dummy(domain_id, authority_id.into())));
        }

        Ok(None)
    }
}

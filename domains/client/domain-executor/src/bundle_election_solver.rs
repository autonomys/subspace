use sp_domains::{BundleSolution, DomainId, ExecutorPublicKey};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::Block as BlockT;
use sp_runtime::RuntimeAppPublic;
use std::marker::PhantomData;
use subspace_core_primitives::Blake2b256Hash;

pub(super) struct BundleElectionSolver<Block, PBlock> {
    keystore: KeystorePtr,
    _phantom_data: PhantomData<(Block, PBlock)>,
}

impl<Block, PBlock> Clone for BundleElectionSolver<Block, PBlock> {
    fn clone(&self) -> Self {
        Self {
            keystore: self.keystore.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, PBlock> BundleElectionSolver<Block, PBlock>
where
    Block: BlockT,
    PBlock: BlockT,
{
    pub(super) fn new(keystore: KeystorePtr) -> Self {
        Self {
            keystore,
            _phantom_data: PhantomData,
        }
    }

    pub(super) fn solve_bundle_election_challenge(
        &self,
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

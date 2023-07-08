use sp_domains::{BundleSolution, DomainId, OperatorPublicKey};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::Block as BlockT;
use sp_runtime::RuntimeAppPublic;
use std::marker::PhantomData;
use subspace_core_primitives::Blake2b256Hash;

pub(super) struct BundleProducerElectionSolver<Block, CBlock> {
    keystore: KeystorePtr,
    _phantom_data: PhantomData<(Block, CBlock)>,
}

impl<Block, CBlock> Clone for BundleProducerElectionSolver<Block, CBlock> {
    fn clone(&self) -> Self {
        Self {
            keystore: self.keystore.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, CBlock> BundleProducerElectionSolver<Block, CBlock>
where
    Block: BlockT,
    CBlock: BlockT,
{
    pub(super) fn new(keystore: KeystorePtr) -> Self {
        Self {
            keystore,
            _phantom_data: PhantomData,
        }
    }

    pub(super) fn solve_challenge(
        &self,
        domain_id: DomainId,
        _global_challenge: Blake2b256Hash,
    ) -> sp_blockchain::Result<Option<BundleSolution<Block::Hash>>> {
        // TODO: Implement Bundle Producer Election v2

        if let Some(authority_id) = self
            .keystore
            .sr25519_public_keys(OperatorPublicKey::ID)
            .into_iter()
            .next()
        {
            return Ok(Some(BundleSolution::dummy(domain_id, authority_id.into())));
        }

        Ok(None)
    }
}

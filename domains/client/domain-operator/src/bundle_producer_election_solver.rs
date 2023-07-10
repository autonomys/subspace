use sp_consensus_slots::Slot;
use sp_domains::bundle_producer_election::{
    calculate_threshold, is_below_threshold, make_transcript,
};
use sp_domains::{DomainId, OperatorPublicKey, ProofOfElection};
use sp_keystore::{Keystore, KeystorePtr};
use sp_runtime::traits::Block as BlockT;
use sp_runtime::RuntimeAppPublic;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;

pub(super) struct BundleProducerElectionSolver<Block, CBlock, CClient> {
    keystore: KeystorePtr,
    consensus_client: Arc<CClient>,
    _phantom_data: PhantomData<(Block, CBlock)>,
}

impl<Block, CBlock, CClient> Clone for BundleProducerElectionSolver<Block, CBlock, CClient> {
    fn clone(&self) -> Self {
        Self {
            keystore: self.keystore.clone(),
            consensus_client: self.consensus_client.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, CBlock, CClient> BundleProducerElectionSolver<Block, CBlock, CClient>
where
    Block: BlockT,
    CBlock: BlockT,
{
    pub(super) fn new(keystore: KeystorePtr, consensus_client: Arc<CClient>) -> Self {
        Self {
            keystore,
            consensus_client,
            _phantom_data: PhantomData,
        }
    }

    pub(super) fn solve_challenge(
        &self,
        _slot: Slot,
        _consensus_block_hash: CBlock::Hash,
        domain_id: DomainId,
        global_challenge: Blake2b256Hash,
    ) -> sp_blockchain::Result<Option<ProofOfElection<Block::Hash>>> {
        // TODO: Fetch doamin state properly
        let current_operators = vec![0u64];
        let total_domain_stake = 100u128;
        let bundle_slot_probability = (1, 1);

        let vrf_sign_data = make_transcript(domain_id, &global_challenge).into_sign_data();

        for _operator_id in current_operators {
            // TODO: Fetch signing_key for this operator_id
            // let operator_signing_key = self.consensus_client.signing_key(consensus_block_hash, operator_id);

            let maybe_signing_key = self
                .keystore
                .sr25519_public_keys(OperatorPublicKey::ID)
                .into_iter()
                .next();

            if let Some(operator_signing_key) = maybe_signing_key {
                if let Ok(Some(vrf_signature)) = Keystore::sr25519_vrf_sign(
                    &*self.keystore,
                    OperatorPublicKey::ID,
                    &operator_signing_key,
                    &vrf_sign_data,
                ) {
                    // TODO: Fetch operator_stake properly
                    let operator_stake = 100u128;

                    let threshold = calculate_threshold(
                        operator_stake,
                        total_domain_stake,
                        bundle_slot_probability,
                    );

                    if is_below_threshold(&vrf_signature.output, threshold) {
                        // TODO: Proper ProofOfElection
                        return Ok(Some(ProofOfElection::dummy(
                            domain_id,
                            operator_signing_key.into(),
                        )));
                    }
                }
            }
        }

        Ok(None)
    }
}

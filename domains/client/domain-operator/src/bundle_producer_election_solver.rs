use sp_api::ProvideRuntimeApi;
use sp_consensus_slots::Slot;
use sp_domains::bundle_producer_election::{
    calculate_threshold, is_below_threshold, make_transcript, BundleProducerElectionParams,
};
use sp_domains::{BundleProducerElectionApi, DomainId, OperatorPublicKey, ProofOfElection};
use sp_keystore::{Keystore, KeystorePtr};
use sp_runtime::traits::Block as BlockT;
use sp_runtime::RuntimeAppPublic;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;
use subspace_runtime_primitives::Balance;

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
    CClient: ProvideRuntimeApi<CBlock>,
    CClient::Api: BundleProducerElectionApi<CBlock, Balance>,
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
        slot: Slot,
        consensus_block_hash: CBlock::Hash,
        domain_id: DomainId,
        global_challenge: Blake2b256Hash,
    ) -> sp_blockchain::Result<Option<ProofOfElection<Block::Hash>>> {
        let BundleProducerElectionParams {
            current_operators,
            total_domain_stake,
            bundle_slot_probability,
        } = match self
            .consensus_client
            .runtime_api()
            .bundle_producer_election_params(consensus_block_hash, domain_id)?
        {
            Some(params) => params,
            None => return Ok(None),
        };

        let vrf_sign_data = make_transcript(domain_id, &global_challenge).into_sign_data();

        for operator_id in current_operators {
            if let Some((operator_signing_key, operator_stake)) = self
                .consensus_client
                .runtime_api()
                .operator_info(consensus_block_hash, operator_id)?
            {
                if let Ok(Some(vrf_signature)) = Keystore::sr25519_vrf_sign(
                    &*self.keystore,
                    OperatorPublicKey::ID,
                    &operator_signing_key.clone().into(),
                    &vrf_sign_data,
                ) {
                    let threshold = calculate_threshold(
                        operator_stake,
                        total_domain_stake,
                        bundle_slot_probability,
                    );

                    if is_below_threshold(&vrf_signature.output, threshold) {
                        let proof_of_election = ProofOfElection {
                            domain_id,
                            slot_number: slot.into(),
                            global_challenge,
                            vrf_signature,
                            operator_public_key: operator_signing_key,
                            _phandom: Default::default(),
                        };
                        return Ok(Some(proof_of_election));
                    }
                }
            }
        }

        Ok(None)
    }
}

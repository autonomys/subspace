use sp_api::ProvideRuntimeApi;
use sp_consensus_slots::Slot;
use sp_core::ByteArray;
use sp_core::bytes::to_hex;
use sp_domains::bundle_producer_election::{
    BundleProducerElectionParams, calculate_threshold, is_below_threshold, make_transcript,
};
use sp_domains::{
    BundleProducerElectionApi, DomainId, OperatorId, OperatorPublicKey, ProofOfElection,
};
use sp_keystore::{Keystore, KeystorePtr};
use sp_runtime::RuntimeAppPublic;
use sp_runtime::traits::Block as BlockT;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::pot::PotOutput;
use subspace_runtime_primitives::Balance;
use tracing::log;

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
        operator_id: OperatorId,
        proof_of_time: PotOutput,
    ) -> sp_blockchain::Result<Option<(ProofOfElection, OperatorPublicKey)>> {
        let BundleProducerElectionParams {
            total_domain_stake,
            bundle_slot_probability,
            ..
        } = match self
            .consensus_client
            .runtime_api()
            .bundle_producer_election_params(consensus_block_hash, domain_id)?
        {
            Some(params) => params,
            None => return Ok(None),
        };

        let global_challenge = proof_of_time
            .derive_global_randomness()
            .derive_global_challenge(slot.into());
        let vrf_sign_data = make_transcript(domain_id, &global_challenge).into_sign_data();

        // Ideally, we can already cache operator signing key since we do not allow changing such key
        // in the protocol right now. Leaving this as is since we anyway need to need to fetch operator's
        // latest stake and this also returns the signing key with it.
        if let Some((operator_signing_key, operator_stake)) = self
            .consensus_client
            .runtime_api()
            .operator(consensus_block_hash, operator_id)?
        {
            if let Ok(maybe_vrf_signature) = Keystore::sr25519_vrf_sign(
                &*self.keystore,
                OperatorPublicKey::ID,
                &operator_signing_key.clone().into(),
                &vrf_sign_data,
            ) {
                if let Some(vrf_signature) = maybe_vrf_signature {
                    let Some(threshold) = calculate_threshold(
                        operator_stake,
                        total_domain_stake,
                        bundle_slot_probability,
                    ) else {
                        return Ok(None);
                    };

                    if is_below_threshold(&vrf_signature.pre_output, threshold) {
                        let proof_of_election = ProofOfElection {
                            domain_id,
                            slot_number: slot.into(),
                            proof_of_time,
                            vrf_signature,
                            operator_id,
                        };
                        return Ok(Some((proof_of_election, operator_signing_key)));
                    }
                } else {
                    log::warn!(
                        "Operator[{operator_id}]'s Signing key[{}] pair is not available in keystore.",
                        to_hex(operator_signing_key.as_slice(), false)
                    );
                    return Ok(None);
                }
            }
        } else {
            log::warn!("Operator[{operator_id}] is not registered on the Runtime",);
            return Ok(None);
        }

        Ok(None)
    }
}

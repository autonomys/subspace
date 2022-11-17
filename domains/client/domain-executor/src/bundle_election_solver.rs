use sc_client_api::ProofProvider;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_domains::bundle_election::{
    calculate_bundle_election_threshold, derive_bundle_election_solution,
    is_election_solution_within_threshold, make_local_randomness_transcript_data, well_known_keys,
    BundleElectionParams,
};
use sp_domains::{DomainId, ExecutorPublicKey, ProofOfElection, StakeWeight};
use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use sp_runtime::RuntimeAppPublic;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::{Blake2b256Hash, BlockNumber};
use system_runtime_primitives::SystemDomainApi;

pub(super) struct BundleElectionSolver<Block, PBlock, Client> {
    client: Arc<Client>,
    keystore: SyncCryptoStorePtr,
    _phantom_data: PhantomData<(Block, PBlock)>,
}

impl<Block, PBlock, Client> Clone for BundleElectionSolver<Block, PBlock, Client>
where
    Block: BlockT,
    PBlock: BlockT,
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            keystore: self.keystore.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

impl<Block, PBlock, Client> BundleElectionSolver<Block, PBlock, Client>
where
    Block: BlockT,
    PBlock: BlockT,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block> + ProofProvider<Block>,
    Client::Api: SystemDomainApi<Block, NumberFor<PBlock>, PBlock::Hash>,
{
    pub(super) fn new(client: Arc<Client>, keystore: SyncCryptoStorePtr) -> Self {
        Self {
            client,
            keystore,
            _phantom_data: PhantomData::default(),
        }
    }

    pub(super) fn solve_bundle_election_challenge(
        &self,
        best_hash: Block::Hash,
        best_number: NumberFor<Block>,
        domain_id: DomainId,
        global_challenge: Blake2b256Hash,
    ) -> sp_blockchain::Result<Option<ProofOfElection<Block::Hash>>> {
        let best_block_id = BlockId::Hash(best_hash);

        let BundleElectionParams {
            authorities,
            total_stake_weight,
            slot_probability,
        } = self
            .client
            .runtime_api()
            .bundle_elections_params(&best_block_id, domain_id)?;

        assert!(
            total_stake_weight
                == authorities
                    .iter()
                    .map(|(_, weight)| weight)
                    .sum::<StakeWeight>(),
            "Total stake weight mismatches, which must be a bug in the runtime"
        );

        let transcript_data = make_local_randomness_transcript_data(&global_challenge);

        for (authority_id, stake_weight) in authorities {
            if let Ok(Some(vrf_signature)) = SyncCryptoStore::sr25519_vrf_sign(
                &*self.keystore,
                ExecutorPublicKey::ID,
                authority_id.as_ref(),
                transcript_data.clone(),
            ) {
                let election_solution = derive_bundle_election_solution(
                    domain_id,
                    vrf_signature.output.to_bytes(),
                    &authority_id,
                    &global_challenge,
                )
                .map_err(|err| {
                    sp_blockchain::Error::Application(Box::from(format!(
                        "Failed to derive bundle election solution: {err}",
                    )))
                })?;

                let threshold = calculate_bundle_election_threshold(
                    stake_weight,
                    total_stake_weight,
                    slot_probability,
                );

                if is_election_solution_within_threshold(election_solution, threshold) {
                    // TODO: bench how large the storage proof we can afford and try proving a single
                    // electioned executor storage instead of the whole authority set.
                    let storage_proof = if domain_id.is_system() {
                        let storage_keys = well_known_keys::bundle_election_storage_keys(domain_id);
                        self.client
                            .read_proof(best_hash, &mut storage_keys.iter().map(|s| s.as_slice()))?
                    } else if domain_id.is_core() {
                        let storage_keys = self
                            .client
                            .runtime_api()
                            .core_bundle_election_storage_keys(
                                &best_block_id,
                                domain_id,
                                authority_id.clone(),
                            )?
                            .ok_or_else(|| {
                                sp_blockchain::Error::Backend(
                                    "Empty core bundle election storage keys".to_string(),
                                )
                            })?;
                        self.client
                            .read_proof(best_hash, &mut storage_keys.iter().map(|s| s.as_slice()))?
                    } else {
                        return Err(sp_blockchain::Error::Application(Box::from(
                            "Only system and core domain are supported".to_string(),
                        )));
                    };

                    let state_root = *self
                        .client
                        .header(best_block_id)?
                        .expect("Best block header must exist; qed")
                        .state_root();

                    let best_number: BlockNumber = best_number
                        .try_into()
                        .unwrap_or_else(|_| panic!("Secondary number must fit into u32; qed"));

                    let proof_of_election = ProofOfElection {
                        domain_id,
                        vrf_output: vrf_signature.output.to_bytes(),
                        vrf_proof: vrf_signature.proof.to_bytes(),
                        executor_public_key: authority_id,
                        global_challenge,
                        state_root,
                        storage_proof,
                        block_number: best_number,
                        block_hash: best_hash,
                        core_block_hash: None,
                        core_state_root: None,
                    };

                    return Ok(Some(proof_of_election));
                }
            }
        }

        Ok(None)
    }
}

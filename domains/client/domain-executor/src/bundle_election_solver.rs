use crate::utils::{to_number_primitive, translate_block_hash_type};
use sc_client_api::ProofProvider;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_domains::bundle_election::{
    calculate_bundle_election_threshold, derive_bundle_election_solution,
    is_election_solution_within_threshold, make_local_randomness_transcript_data, well_known_keys,
    BundleElectionSolverParams,
};
use sp_domains::merkle_tree::{authorities_merkle_tree, Witness};
use sp_domains::{DomainId, ExecutorPublicKey, ProofOfElection, StakeWeight};
use sp_keystore::{SyncCryptoStore, SyncCryptoStorePtr};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use sp_runtime::RuntimeAppPublic;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::Blake2b256Hash;
use system_runtime_primitives::SystemDomainApi;

pub(super) struct BundleElectionSolver<SBlock, PBlock, SClient> {
    system_domain_client: Arc<SClient>,
    keystore: SyncCryptoStorePtr,
    _phantom_data: PhantomData<(SBlock, PBlock)>,
}

impl<SBlock, PBlock, SClient> Clone for BundleElectionSolver<SBlock, PBlock, SClient> {
    fn clone(&self) -> Self {
        Self {
            system_domain_client: self.system_domain_client.clone(),
            keystore: self.keystore.clone(),
            _phantom_data: self._phantom_data,
        }
    }
}

pub(super) enum PreliminaryBundleSolution<DomainHash> {
    System {
        authority_stake_weight: StakeWeight,
        authority_witness: Witness,
        proof_of_election: ProofOfElection<DomainHash>,
    },
    Core(ProofOfElection<DomainHash>),
}

impl<SBlock, PBlock, SClient> BundleElectionSolver<SBlock, PBlock, SClient>
where
    SBlock: BlockT,
    PBlock: BlockT,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock>,
    SClient::Api: SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
{
    pub(super) fn new(system_domain_client: Arc<SClient>, keystore: SyncCryptoStorePtr) -> Self {
        Self {
            system_domain_client,
            keystore,
            _phantom_data: PhantomData::default(),
        }
    }

    pub(super) fn solve_bundle_election_challenge<Block: BlockT>(
        &self,
        best_hash: SBlock::Hash,
        best_number: NumberFor<SBlock>,
        domain_id: DomainId,
        global_challenge: Blake2b256Hash,
    ) -> sp_blockchain::Result<Option<PreliminaryBundleSolution<Block::Hash>>> {
        let BundleElectionSolverParams {
            authorities,
            total_stake_weight,
            slot_probability,
        } = self
            .system_domain_client
            .runtime_api()
            .bundle_election_solver_params(best_hash, domain_id)?;

        assert!(
            total_stake_weight
                == authorities
                    .iter()
                    .map(|(_, weight)| weight)
                    .sum::<StakeWeight>(),
            "Total stake weight mismatches, which must be a bug in the runtime"
        );

        let transcript_data = make_local_randomness_transcript_data(&global_challenge);

        for (index, (authority_id, stake_weight)) in authorities.iter().enumerate() {
            if let Ok(Some(vrf_signature)) = SyncCryptoStore::sr25519_vrf_sign(
                &*self.keystore,
                ExecutorPublicKey::ID,
                authority_id.as_ref(),
                transcript_data.clone(),
            ) {
                let election_solution = derive_bundle_election_solution(
                    domain_id,
                    vrf_signature.output.to_bytes(),
                    authority_id,
                    &global_challenge,
                )
                .map_err(|err| {
                    sp_blockchain::Error::Application(Box::from(format!(
                        "Failed to derive bundle election solution: {err}",
                    )))
                })?;

                let threshold = calculate_bundle_election_threshold(
                    *stake_weight,
                    total_stake_weight,
                    slot_probability,
                );

                if is_election_solution_within_threshold(election_solution, threshold) {
                    // TODO: bench how large the storage proof we can afford and try proving a single
                    // electioned executor storage instead of the whole authority set.
                    let storage_proof = if domain_id.is_system() {
                        let storage_keys = well_known_keys::system_bundle_election_storage_keys();
                        self.system_domain_client
                            .read_proof(best_hash, &mut storage_keys.iter().map(|s| s.as_slice()))?
                    } else if domain_id.is_core() {
                        let storage_keys = self
                            .system_domain_client
                            .runtime_api()
                            .core_bundle_election_storage_keys(
                                best_hash,
                                domain_id,
                                authority_id.clone(),
                            )?
                            .ok_or_else(|| {
                                sp_blockchain::Error::Backend(
                                    "Empty core bundle election storage keys".to_string(),
                                )
                            })?;
                        self.system_domain_client
                            .read_proof(best_hash, &mut storage_keys.iter().map(|s| s.as_slice()))?
                    } else {
                        return Err(sp_blockchain::Error::Application(Box::from(
                            "Only system and core domain are supported".to_string(),
                        )));
                    };

                    let state_root = *self
                        .system_domain_client
                        .header(best_hash)?
                        .expect("Best block header must exist; qed")
                        .state_root();

                    let block_hash = translate_block_hash_type::<SBlock, Block>(best_hash);
                    let state_root = translate_block_hash_type::<SBlock, Block>(state_root);

                    let proof_of_election = ProofOfElection {
                        domain_id,
                        vrf_output: vrf_signature.output.to_bytes(),
                        vrf_proof: vrf_signature.proof.to_bytes(),
                        executor_public_key: authority_id.clone(),
                        global_challenge,
                        state_root,
                        storage_proof,
                        block_number: to_number_primitive(best_number),
                        block_hash,
                    };

                    let preliminary_bundle_solution = if domain_id.is_system() {
                        let merkle_tree = authorities_merkle_tree(&authorities);
                        let authority_witness = Witness {
                            leaf_index: index.try_into().expect("Leaf index must fit into u32"),
                            number_of_leaves: authorities
                                .len()
                                .try_into()
                                .expect("Authorities size must fit into u32"),
                            proof: merkle_tree.proof(&[index]).to_bytes(),
                        };

                        PreliminaryBundleSolution::System {
                            authority_stake_weight: *stake_weight,
                            authority_witness,
                            proof_of_election,
                        }
                    } else if domain_id.is_core() {
                        PreliminaryBundleSolution::Core(proof_of_election)
                    } else {
                        unreachable!("Open domain has been handled above")
                    };

                    return Ok(Some(preliminary_bundle_solution));
                }
            }
        }

        Ok(None)
    }
}

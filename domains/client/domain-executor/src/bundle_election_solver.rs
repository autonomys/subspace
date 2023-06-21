use crate::utils::{to_number_primitive, translate_block_hash_type};
use sc_client_api::ProofProvider;
use sp_api::{NumberFor, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_domains::bundle_election::{
    calculate_bundle_election_threshold, derive_bundle_election_solution,
    is_election_solution_within_threshold, make_local_randomness_input, well_known_keys,
    BundleElectionSolverParams,
};
use sp_domains::merkle_tree::{authorities_merkle_tree, Witness};
use sp_domains::{BundleSolution, DomainId, ExecutorPublicKey, ProofOfElection, StakeWeight};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
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
        best_hash: SBlock::Hash,
        best_number: NumberFor<SBlock>,
        domain_id: DomainId,
        global_challenge: Blake2b256Hash,
    ) -> sp_blockchain::Result<Option<BundleSolution<Block::Hash>>> {
        // TODO: dummy bundle election

        let BundleElectionSolverParams {
            authorities,
            total_stake_weight,
            slot_probability,
        } = BundleElectionSolverParams::empty();

        assert!(
            total_stake_weight
                == authorities
                    .iter()
                    .map(|(_, weight)| weight)
                    .sum::<StakeWeight>(),
            "Total stake weight mismatches, which must be a bug in the runtime"
        );

        let input = make_local_randomness_input(&global_challenge).into();

        for (index, (authority_id, stake_weight)) in authorities.iter().enumerate() {
            if let Ok(Some(vrf_signature)) =
                self.keystore
                    .sr25519_vrf_sign(ExecutorPublicKey::ID, authority_id.as_ref(), &input)
            {
                let election_solution = derive_bundle_election_solution(
                    domain_id,
                    &vrf_signature.output,
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
                        vrf_output: vrf_signature.output,
                        vrf_proof: vrf_signature.proof,
                        executor_public_key: authority_id.clone(),
                        global_challenge,
                        storage_proof,
                        system_state_root: state_root,
                        system_block_number: to_number_primitive(best_number),
                        system_block_hash: block_hash,
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

                        BundleSolution::System {
                            authority_stake_weight: *stake_weight,
                            authority_witness,
                            proof_of_election,
                        }
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

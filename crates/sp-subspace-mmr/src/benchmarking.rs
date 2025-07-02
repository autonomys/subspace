//! Benchmarking stubs for SubspaceMmrExtension.

use crate::host_functions::{SubspaceMmrExtension, SubspaceMmrHostFunctionsImpl};
use scale_info::prelude::sync::Arc;
use sp_api::{ApiRef, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::H256;
use sp_mmr_primitives::{EncodableOpaqueLeaf, Error, LeafIndex, LeafProof, MmrApi, utils};
use sp_runtime::Digest;
use subspace_core_primitives::BlockNumber;
use subspace_runtime_primitives::opaque::{self, Block};

/// Returns a mock instance of `SubspaceMmrExtension` for benchmarking.
pub(crate) fn mock_subspace_mmr_extension() -> SubspaceMmrExtension {
    SubspaceMmrExtension::new(Arc::new(SubspaceMmrHostFunctionsImpl::<
        // Opaque blocks can cost less than runtime blocks. When we use the SubspaceMmrExtension,
        // we will automatically use runtime blocks:
        // <https://github.com/paritytech/polkadot-sdk/issues/137>
        opaque::Block,
        MockRuntime,
    >::new(
        Arc::new(mock_consensus_client()),
        // Mainnet confirmation_depth_k
        100,
    )))
}

/// Returns a mock instance for benchmarking, which satisfies the `Client` traits.
fn mock_consensus_client() -> MockRuntime {
    MockRuntime { block_number: 1000 }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
struct MockRuntime {
    block_number: BlockNumber,
}

/// Header backend stubs, mostly with random data.
impl HeaderBackend<opaque::Block> for MockRuntime {
    fn header(&self, _block_hash: H256) -> Result<Option<opaque::Header>, sp_blockchain::Error> {
        let header = opaque::Header {
            digest: Digest::default(),
            extrinsics_root: H256::random(),
            number: self.block_number,
            parent_hash: H256::random(),
            state_root: H256::random(),
        };

        Ok(Some(header))
    }

    fn info(&self) -> sp_blockchain::Info<opaque::Block> {
        sp_blockchain::Info {
            best_hash: H256::random(),
            best_number: self.block_number,
            genesis_hash: H256::random(),
            finalized_hash: H256::random(),
            finalized_number: self.block_number,
            block_gap: None,
            finalized_state: None,
            number_leaves: utils::block_num_to_leaf_index::<opaque::Header>(self.block_number, 0)
                .unwrap_or_default() as usize,
        }
    }

    fn status(
        &self,
        _block_hash: H256,
    ) -> Result<sp_blockchain::BlockStatus, sp_blockchain::Error> {
        Ok(sp_blockchain::BlockStatus::InChain)
    }

    fn number(&self, _block_hash: H256) -> Result<Option<BlockNumber>, sp_blockchain::Error> {
        Ok(Some(self.block_number))
    }

    fn hash(&self, _block_number: BlockNumber) -> Result<Option<H256>, sp_blockchain::Error> {
        Ok(Some(H256::random()))
    }
}

impl ProvideRuntimeApi<opaque::Block> for MockRuntime {
    type Api = MockRuntime;

    fn runtime_api(&self) -> ApiRef<'_, Self::Api> {
        (*self).into()
    }
}

sp_api::mock_impl_runtime_apis! {
    /// This code is taken from the runtime and pallet-mmr implementations, but with random data
    /// instead of some pallet calls. These calls are cheaper than disk database lookups, but
    /// lookups require the SubspaceMmrExtension in benchmarks (which isn't supported yet).
    impl MmrApi<opaque::Block, H256, BlockNumber> for MockRuntime {
        fn mmr_root() -> Result<H256, Error> {
            Ok(H256::random())
        }

        fn mmr_leaf_count(&self) -> Result<LeafIndex, Error> {
            Ok(
                utils::block_num_to_leaf_index::<opaque::Header>(self.block_number, 0)
                    .unwrap_or_default()
                    + 1,
            )
        }

        fn generate_proof(
            &self,
            block_numbers: Vec<BlockNumber>,
            best_known_block_number: Option<BlockNumber>,
        ) -> Result<(Vec<EncodableOpaqueLeaf>, LeafProof<H256>), Error> {
            let best_known_block_number = best_known_block_number.unwrap_or(self.block_number);

            let leaf_count =
                utils::block_num_to_leaf_index::<opaque::Header>(best_known_block_number, 0)
                    .unwrap_or_default()
                    + 1;

            // we need to translate the block_numbers into leaf indices.
            let leaf_indices = block_numbers
                .iter()
                .map(|block_num| -> Result<LeafIndex, Error> {
                    utils::block_num_to_leaf_index::<opaque::Header>(*block_num, 0)
                })
                .collect::<Result<Vec<LeafIndex>, _>>()?;

            // Mmr::generate_proof depends on the pallet and runtime, so does
            // generate_mock_ancestry_proof.

            let leaves = leaf_indices
                .iter()
                .map(|_index| EncodableOpaqueLeaf::from_leaf(&H256::random()))
                .collect();

            let proof = LeafProof {
                leaf_indices,
                leaf_count,
                items: vec![H256::random(); leaf_count as usize],
            };

            Ok((leaves, proof))
        }

        fn verify_proof(
            &self,
            leaves: Vec<EncodableOpaqueLeaf>,
            proof: LeafProof<H256>,
        ) -> Result<(), Error> {
            self.verify_proof_stateless(H256::random(), H256::random(), leaves, proof)
                .map_err(|_| Error::Verify)
                .flatten()
        }

        fn verify_proof_stateless(
            root: H256,
            leaves: Vec<EncodableOpaqueLeaf>,
            proof: LeafProof<H256>,
        ) -> Result<(), Error> {
            let leaves = leaves
                .into_iter()
                .map(|l| l.into_opaque_leaf().into())
                .collect::<Vec<_>>();
            let result = pallet_mmr::verify_leaves_proof::<sp_runtime::traits::BlakeTwo256, _>(
                root, leaves, proof,
            );
            // always true, because it only returns `Error::Verify`, but the compiler doesn't know
            // that, so it can't optimize it out
            if result.is_ok() || (result.is_err() && result.unwrap_err() == Error::Verify) {
                Ok(())
            } else {
                Err(Error::Verify)
            }
        }
    }
}

use rand::{seq::SliceRandom, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sc_client_api::BlockBackend;
use sc_consensus::{
	BlockImport, BlockImportParams, ForkChoiceStrategy, StateAction, StorageChanges,
};
use sp_api::ProvideRuntimeApi;
use sp_consensus::BlockOrigin;
use sp_inherents::{CreateInherentDataProviders, InherentData, InherentDataProvider};
use sp_runtime::{
	generic::BlockId,
	traits::{BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT},
};
use std::{
	collections::{BTreeMap, VecDeque},
	fmt::Debug,
};

use cirrus_block_builder::{BlockBuilder, BuiltBlock, RecordProof};
use cirrus_node_primitives::ProcessorResult;
use cirrus_primitives::{AccountId, SecondaryApi};
use sp_executor::{ExecutionReceipt, OpaqueBundle};
use subspace_core_primitives::Randomness;
use subspace_runtime_primitives::Hash as PHash;

use super::{Executor, LOG_TARGET};
use codec::{Decode, Encode};

/// Shuffles the extrinsics in a deterministic way.
///
/// The extrinsics are grouped by the signer. The extrinsics without a signer, i.e., unsigned
/// extrinsics, are considered as a special group. The items in different groups are cross shuffled,
/// while the order of items inside the same group is still maintained.
fn shuffle_extrinsics<Extrinsic: Debug>(
	extrinsics: Vec<(Option<AccountId>, Extrinsic)>,
	shuffling_seed: Randomness,
) -> Vec<Extrinsic> {
	let mut rng = ChaCha8Rng::from_seed(shuffling_seed);

	let mut positions = extrinsics
		.iter()
		.map(|(maybe_signer, _)| maybe_signer)
		.cloned()
		.collect::<Vec<_>>();

	// Shuffles the positions using Fisher–Yates algorithm.
	positions.shuffle(&mut rng);

	let mut grouped_extrinsics: BTreeMap<Option<AccountId>, VecDeque<_>> =
		extrinsics.into_iter().fold(BTreeMap::new(), |mut groups, (maybe_signer, tx)| {
			groups.entry(maybe_signer).or_insert_with(VecDeque::new).push_back(tx);
			groups
		});

	// The relative ordering for the items in the same group does not change.
	let shuffled_extrinsics = positions
		.into_iter()
		.map(|maybe_signer| {
			grouped_extrinsics
				.get_mut(&maybe_signer)
				.expect("Extrinsics are grouped correctly; qed")
				.pop_front()
				.expect("Extrinsic definitely exists as it's correctly grouped above; qed")
		})
		.collect::<Vec<_>>();

	tracing::trace!(target: LOG_TARGET, ?shuffled_extrinsics, "Shuffled extrinsics");

	shuffled_extrinsics
}

impl<Block, BS, Client, TransactionPool, Backend, CIDP>
	Executor<Block, BS, Client, TransactionPool, Backend, CIDP>
where
	Block: BlockT,
	Client: sp_blockchain::HeaderBackend<Block> + ProvideRuntimeApi<Block>,
	Client::Api: SecondaryApi<Block, AccountId>
		+ sp_block_builder::BlockBuilder<Block>
		+ sp_api::ApiExt<
			Block,
			StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
		>,
	for<'b> &'b Client: sc_consensus::BlockImport<
		Block,
		Transaction = sp_api::TransactionFor<Client, Block>,
		Error = sp_consensus::Error,
	>,
	BS: BlockBackend<Block>,
	Backend: sc_client_api::Backend<Block>,
	TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
	CIDP: CreateInherentDataProviders<Block, cirrus_primitives::Hash>,
{
	/// Actually implements `process_bundles`.
	pub(super) async fn process_bundles_impl(
		&self,
		primary_hash: PHash,
		bundles: Vec<OpaqueBundle>,
		shuffling_seed: Randomness,
	) -> Result<Option<ProcessorResult>, sp_blockchain::Error> {
		let mut extrinsics = bundles
			.into_iter()
			.flat_map(|bundle| {
				bundle.opaque_extrinsics.into_iter().filter_map(|opaque_extrinsic| {
					match <<Block as BlockT>::Extrinsic>::decode(
						&mut opaque_extrinsic.encode().as_slice(),
					) {
						Ok(uxt) => Some(uxt),
						Err(e) => {
							tracing::error!(
								target: LOG_TARGET,
								error = ?e,
								"Failed to decode the opaque extrisic in bundle, this should not happen"
							);
							None
						},
					}
				})
			})
			.collect::<Vec<_>>();

		// TODO: or just Vec::new()?
		// Ideally there should be only a few duplicated transactions.
		let mut seen = Vec::with_capacity(extrinsics.len());
		extrinsics.retain(|uxt| match seen.contains(uxt) {
			true => {
				tracing::trace!(target: LOG_TARGET, extrinsic = ?uxt, "Duplicated extrinsic");
				false
			},
			false => {
				seen.push(uxt.clone());
				true
			},
		});
		drop(seen);

		tracing::trace!(target: LOG_TARGET, ?extrinsics, "Origin deduplicated extrinsics");

		let parent_hash = self.client.info().best_hash;
		let parent_number = self.client.info().best_number;

		let extrinsics: Vec<_> = match self
			.client
			.runtime_api()
			.extract_signer(&BlockId::Hash(parent_hash), extrinsics)
		{
			Ok(res) => res,
			Err(e) => {
				tracing::error!(
					target: LOG_TARGET,
					error = ?e,
					"Error at calling runtime api: extract_signer"
				);
				return Err(e.into())
			},
		};

		let extrinsics =
			shuffle_extrinsics::<<Block as BlockT>::Extrinsic>(extrinsics, shuffling_seed);

		let mut block_builder = BlockBuilder::new(
			&*self.client,
			parent_hash,
			parent_number,
			RecordProof::No,
			Default::default(),
			&*self.backend,
		)?;

		let inherent_data = self.inherent_data(parent_hash, primary_hash).await?;

		let mut final_extrinsics = block_builder.create_inherents(inherent_data)?;
		final_extrinsics.extend(extrinsics);

		block_builder.set_extrinsics(final_extrinsics);

		let BuiltBlock { block, storage_changes, proof: _ } = block_builder.build()?;

		let (header, body) = block.deconstruct();
		let state_root = *header.state_root();
		let header_hash = header.hash();

		let block_import_params = {
			let mut import_block = BlockImportParams::new(BlockOrigin::Own, header);
			import_block.body = Some(body);
			import_block.state_action =
				StateAction::ApplyChanges(StorageChanges::Changes(storage_changes));
			// TODO: double check the fork choice is correct, see also ParachainBlockImport.
			import_block.fork_choice = Some(ForkChoiceStrategy::LongestChain);
			import_block
		};
		(&*self.client).import_block(block_import_params, Default::default()).await?;

		let mut roots =
			self.client.runtime_api().intermediate_roots(&BlockId::Hash(parent_hash))?;
		roots.push(state_root.encode());

		let trace_root =
			BlakeTwo256::ordered_trie_root(roots.clone(), sp_core::storage::StateVersion::V1);

		let trace = roots
			.into_iter()
			.map(|r| {
				Block::Hash::decode(&mut r.as_slice())
					.expect("Storage root uses the same Block hash type; qed")
			})
			.collect();

		tracing::debug!(
			target: LOG_TARGET,
			?trace,
			?trace_root,
			"Trace root calculated for #{}",
			header_hash
		);

		let execution_receipt =
			ExecutionReceipt { primary_hash, secondary_hash: header_hash, trace, trace_root };

		// The applied txs can be fully removed from the transaction pool

		// TODO: win the executor election to broadcast ER, authority node only.
		let is_elected = self.is_authority;

		if is_elected {
			if let Err(e) = self.execution_receipt_sender.unbounded_send(execution_receipt.clone())
			{
				tracing::error!(target: LOG_TARGET, error = ?e, "Failed to send execution receipt");
			}

			// Return `Some(_)` to broadcast ER to all farmers via unsigned extrinsic.
			Ok(Some(ProcessorResult { opaque_execution_receipt: execution_receipt.into() }))
		} else {
			Ok(None)
		}
	}

	/// Get the inherent data.
	async fn inherent_data(
		&self,
		parent: Block::Hash,
		relay_parent: PHash,
	) -> Result<InherentData, sp_blockchain::Error> {
		let inherent_data_providers = self
			.create_inherent_data_providers
			.create_inherent_data_providers(parent, relay_parent)
			.await?;

		inherent_data_providers.create_inherent_data().map_err(|e| {
			tracing::error!(
				target: LOG_TARGET,
				error = ?e,
				"Failed to create inherent data.",
			);
			sp_blockchain::Error::Consensus(sp_consensus::Error::InherentData(e.into()))
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_keyring::sr25519::Keyring;
	use sp_runtime::traits::{BlakeTwo256, Hash as HashT};

	#[test]
	fn shuffle_extrinsics_should_work() {
		let alice = Keyring::Alice.to_account_id();
		let bob = Keyring::Bob.to_account_id();
		let charlie = Keyring::Charlie.to_account_id();

		let extrinsics = vec![
			(Some(alice.clone()), 10),
			(None, 100),
			(Some(bob.clone()), 1),
			(Some(bob), 2),
			(Some(charlie.clone()), 30),
			(Some(alice.clone()), 11),
			(Some(charlie), 31),
			(None, 101),
			(None, 102),
			(Some(alice), 12),
		];

		let dummy_seed = BlakeTwo256::hash_of(&[1u8; 64]).into();
		let shuffled_extrinsics = shuffle_extrinsics(extrinsics, dummy_seed);

		assert_eq!(shuffled_extrinsics, vec![100, 30, 10, 1, 11, 101, 31, 12, 102, 2]);
	}
}

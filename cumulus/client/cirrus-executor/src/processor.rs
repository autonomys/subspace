use rand::{seq::SliceRandom, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sc_client_api::BlockBackend;
use sc_consensus::{
	BlockImport, BlockImportParams, ForkChoiceStrategy, StateAction, StorageChanges,
};
use sp_api::ProvideRuntimeApi;
use sp_consensus::BlockOrigin;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};
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

impl<Block, BS, RA, Client, TransactionPool, Backend, CIDP>
	Executor<Block, BS, RA, Client, TransactionPool, Backend, CIDP>
where
	Block: BlockT,
	Client: sp_blockchain::HeaderBackend<Block>,
	for<'b> &'b Client: sc_consensus::BlockImport<
		Block,
		Transaction = sp_api::TransactionFor<RA, Block>,
		Error = sp_consensus::Error,
	>,
	BS: BlockBackend<Block>,
	Backend: sc_client_api::Backend<Block>,
	RA: ProvideRuntimeApi<Block>,
	RA::Api: SecondaryApi<Block, AccountId>
		+ sp_block_builder::BlockBuilder<Block>
		+ sp_api::ApiExt<
			Block,
			StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
		>,
	TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
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

		let block_number = self.client.info().best_number;
		let extrinsics: Vec<_> = match self
			.runtime_api
			.runtime_api()
			.extract_signer(&BlockId::Number(block_number), extrinsics)
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

		let block_builder = BlockBuilder::new(
			&*self.runtime_api,
			self.client.info().best_hash,
			self.client.info().best_number,
			RecordProof::No,
			Default::default(),
			&*self.backend,
			extrinsics,
		)?;
		let BuiltBlock { block, storage_changes, proof: _ } = block_builder.build()?;
		let (header, body) = block.deconstruct();
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

		// TODO: now we have the final transaction list:
		// - apply each tx one by one.
		// - compute the incremental state root and add to the execution trace
		// - produce ExecutionReceipt
		let execution_receipt = ExecutionReceipt {
			primary_hash,
			secondary_hash: Block::Hash::default(),
			state_root: Block::Hash::default(),
			state_transition_root: Block::Hash::default(),
		};

		// The applied txs can be fully removed from the transaction pool

		// TODO: win the executor election to broadcast ER.
		let is_elected = true;

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

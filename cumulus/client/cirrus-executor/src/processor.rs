use sc_client_api::BlockBackend;
use sp_api::ProvideRuntimeApi;
use sp_runtime::{generic::BlockId, traits::Block as BlockT};

use cirrus_node_primitives::ProcessorResult;
use cirrus_primitives::{AccountId, SecondaryApi};
use sp_executor::{ExecutionReceipt, OpaqueBundle};
use subspace_runtime_primitives::Hash as PHash;

use super::{Executor, LOG_TARGET};
use codec::{Decode, Encode};

impl<Block, BS, RA, Client, TransactionPool> Executor<Block, BS, RA, Client, TransactionPool>
where
	Block: BlockT,
	Client: sp_blockchain::HeaderBackend<Block>,
	BS: BlockBackend<Block>,
	RA: ProvideRuntimeApi<Block>,
	RA::Api: SecondaryApi<Block, AccountId>,
	TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
	/// Actually implements `process_bundles`.
	pub(super) async fn process_bundles_impl(
		self,
		primary_hash: PHash,
		bundles: Vec<OpaqueBundle>,
	) -> Option<ProcessorResult> {
		// TODO:
		// 1. [x] convert the bundles to a full tx list
		// 2. [x] duplicate the full tx list
		// 3. shuffle the full tx list by sender account
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
				return None
			},
		};

		let _final_extrinsics = Self::shuffle_extrinsics(extrinsics);

		// TODO: now we have the final transaction list:
		// - apply each tx one by one.
		// - compute the incremental state root and add to the execution trace
		// - produce ExecutionReceipt

		// The applied txs can be fully removed from the transaction pool

		// TODO: win the executor election to broadcast ER.
		let is_elected = true;

		if is_elected {
			// TODO: broadcast ER to all executors.

			// Return `Some(_)` to broadcast ER to all farmers via unsigned extrinsic.
			Some(ProcessorResult {
				execution_receipt: ExecutionReceipt {
					primary_hash,
					secondary_hash: Default::default(),
					state_root: Default::default(),
					state_transition_root: Default::default(),
				},
			})
		} else {
			None
		}
	}

	// TODO:
	// 1. determine the randomness generator
	// 2. Fisher-Yates
	fn shuffle_extrinsics(
		extrinsics: Vec<(Option<AccountId>, <Block as BlockT>::Extrinsic)>,
	) -> Vec<<Block as BlockT>::Extrinsic> {
		extrinsics.into_iter().map(|(_, uxt)| uxt).collect()
	}
}

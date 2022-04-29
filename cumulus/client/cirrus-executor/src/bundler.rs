use codec::{Decode, Encode};
use futures::{select, FutureExt};
use sc_client_api::BlockBackend;
use sc_transaction_pool_api::InPoolTransaction;
use sp_api::ProvideRuntimeApi;
use sp_core::ByteArray;
use sp_keystore::SyncCryptoStore;
use sp_runtime::{
	generic::BlockId,
	traits::{BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT},
	RuntimeAppPublic,
};
use std::time;

use crate::overseer::ExecutorSlotInfo;
use cirrus_primitives::{AccountId, SecondaryApi};
use sp_executor::{
	Bundle, BundleHeader, ExecutorApi, ExecutorId, ExecutorSignature, OpaqueBundle, SignedBundle,
};

use subspace_runtime_primitives::Hash as PHash;

use super::{Executor, LOG_TARGET};

impl<Block, PBlock, Client, PClient, TransactionPool, Backend, E>
	Executor<Block, PBlock, Client, PClient, TransactionPool, Backend, E>
where
	Block: BlockT,
	PBlock: BlockT,
	Client: sp_blockchain::HeaderBackend<Block> + BlockBackend<Block> + ProvideRuntimeApi<Block>,
	Client::Api: SecondaryApi<Block, AccountId>
		+ sp_block_builder::BlockBuilder<Block>
		+ sp_api::ApiExt<
			Block,
			StateBackend = sc_client_api::backend::StateBackendFor<Backend, Block>,
		>,
	PClient: ProvideRuntimeApi<PBlock>,
	PClient::Api: ExecutorApi<PBlock, Block::Hash>,
	Backend: sc_client_api::Backend<Block>,
	TransactionPool: sc_transaction_pool_api::TransactionPool<Block = Block>,
{
	pub(super) async fn produce_bundle_impl(
		self,
		primary_hash: PHash,
		slot_info: ExecutorSlotInfo,
	) -> Result<Option<OpaqueBundle>, sp_blockchain::Error> {
		let parent_number = self.client.info().best_number;

		let mut t1 = self.transaction_pool.ready_at(parent_number).fuse();
		// TODO: proper timeout
		let mut t2 = futures_timer::Delay::new(time::Duration::from_micros(100)).fuse();

		let pending_iterator = select! {
			res = t1 => res,
			_ = t2 => {
				tracing::warn!(
					target: LOG_TARGET,
					"Timeout fired waiting for transaction pool at #{}, proceeding with production.",
					parent_number,
				);
				self.transaction_pool.ready()
			}
		};

		// TODO: proper deadline
		let pushing_duration = time::Duration::from_micros(500);

		let start = time::Instant::now();

		// TODO: Select transactions properly from the transaction pool
		//
		// Selection policy:
		// - minimize the transaction equivocation.
		// - maximize the executor computation power.
		let mut extrinsics = Vec::new();

		for pending_tx in pending_iterator {
			if start.elapsed() >= pushing_duration {
				break
			}
			let pending_tx_data = pending_tx.data().clone();
			extrinsics.push(pending_tx_data);
		}

		let extrinsics_root = BlakeTwo256::ordered_trie_root(
			extrinsics.iter().map(|xt| xt.encode()).collect(),
			sp_core::storage::StateVersion::V1,
		);

		let _state_root = self.client.expect_header(BlockId::Number(parent_number))?.state_root();

		let bundle = Bundle {
			header: BundleHeader { slot_number: slot_info.slot.into(), extrinsics_root },
			extrinsics,
		};

		let executor_id = self.primary_chain_client.runtime_api().executor_id(&BlockId::Hash(
			PBlock::Hash::decode(&mut primary_hash.encode().as_slice())
				.expect("Primary block hash must be the correct type; qed"),
		))?;

		if self.is_authority &&
			SyncCryptoStore::has_keys(
				&*self.keystore,
				&[(ByteArray::to_raw_vec(&executor_id), ExecutorId::ID)],
			) {
			let to_sign = bundle.hash();
			match SyncCryptoStore::sign_with(
				&*self.keystore,
				ExecutorId::ID,
				&executor_id.clone().into(),
				to_sign.as_ref(),
			) {
				Ok(Some(signature)) => {
					let signed_bundle = SignedBundle {
						bundle: bundle.clone(),
						signature: ExecutorSignature::decode(&mut signature.as_slice()).map_err(
							|err| {
								sp_blockchain::Error::Application(Box::from(format!(
									"Failed to decode the signature of bundle: {err}"
								)))
							},
						)?,
						signer: executor_id,
					};

					if let Err(e) = self.bundle_sender.unbounded_send(signed_bundle) {
						tracing::error!(target: LOG_TARGET, error = ?e, "Failed to send transaction bundle");
					}

					// TODO: SignedOpaqueBundle for farmers.
					Ok(Some(bundle.into()))
				},
				Ok(None) => Err(sp_blockchain::Error::Application(Box::from(
					"This should not happen as the existence of key was just checked",
				))),
				Err(error) => Err(sp_blockchain::Error::Application(Box::from(format!(
					"Error occurred when signing the bundle: {error}"
				)))),
			}
		} else {
			Ok(None)
		}
	}
}

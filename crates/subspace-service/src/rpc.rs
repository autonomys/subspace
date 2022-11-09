// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! A collection of node-specific RPC methods.
//! Substrate provides the `sc-rpc` crate, which defines the core RPC layer
//! used by Substrate nodes. This file extends those RPC definitions with
//! capabilities that are specific to this project's runtime configuration.

#![warn(missing_docs)]

use jsonrpsee::RpcModule;
use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
use sc_client_api::BlockBackend;
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::{
    ArchivedSegmentNotification, NewSlotNotification, RewardSigningNotification,
};
use sc_consensus_subspace_rpc::{SubspaceRpc, SubspaceRpcApiServer};
use sc_piece_cache::PieceCache;
use sc_rpc::SubscriptionTaskExecutor;
use sc_rpc_api::DenyUnsafe;
use sc_rpc_spec_v2::chain_spec::{ChainSpec, ChainSpecApiServer};
use sc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_consensus_subspace::FarmerPublicKey;
use std::sync::Arc;
use subspace_runtime_primitives::opaque::Block;
use subspace_runtime_primitives::{AccountId, Balance, Index};
use substrate_frame_rpc_system::{System, SystemApiServer};

/// Full client dependencies.
pub struct FullDeps<C, P, PC> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
    /// A copy of the chain spec.
    pub chain_spec: Box<dyn sc_chain_spec::ChainSpec>,
    /// Whether to deny unsafe calls.
    pub deny_unsafe: DenyUnsafe,
    /// Executor to drive the subscription manager in the Grandpa RPC handler.
    pub subscription_executor: SubscriptionTaskExecutor,
    /// A stream with notifications about new slot arrival with ability to send solution back.
    pub new_slot_notification_stream: SubspaceNotificationStream<NewSlotNotification>,
    /// A stream with notifications about headers that need to be signed with ability to send
    /// signature back.
    pub reward_signing_notification_stream: SubspaceNotificationStream<RewardSigningNotification>,
    /// A stream with notifications about archived segment creation.
    pub archived_segment_notification_stream:
        SubspaceNotificationStream<ArchivedSegmentNotification>,
    /// Caching layer for pieces produced during archiving to make them available for some time
    /// after they were produced.
    pub piece_cache: PC,
}

/// Instantiate all full RPC extensions.
pub fn create_full<C, P, PC>(
    deps: FullDeps<C, P, PC>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    C: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = BlockChainError>
        + Send
        + Sync
        + 'static,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Index>
        + pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
        + BlockBuilder<Block>
        + sp_consensus_subspace::SubspaceApi<Block, FarmerPublicKey>,
    P: TransactionPool + 'static,
    PC: PieceCache + Send + Sync + 'static,
{
    let mut module = RpcModule::new(());
    let FullDeps {
        client,
        pool,
        chain_spec,
        deny_unsafe,
        subscription_executor,
        new_slot_notification_stream,
        reward_signing_notification_stream,
        archived_segment_notification_stream,
        piece_cache,
    } = deps;

    let chain_name = chain_spec.name().to_string();
    let genesis_hash = client
        .block_hash(0)
        .ok()
        .flatten()
        .expect("Genesis block exists; qed");
    let properties = chain_spec.properties();
    module.merge(ChainSpec::new(chain_name, genesis_hash, properties).into_rpc())?;

    module.merge(System::new(client.clone(), pool, deny_unsafe).into_rpc())?;
    module.merge(TransactionPayment::new(client.clone()).into_rpc())?;

    module.merge(
        SubspaceRpc::new(
            client,
            subscription_executor,
            new_slot_notification_stream,
            reward_signing_notification_stream,
            archived_segment_notification_stream,
            piece_cache,
        )
        .into_rpc(),
    )?;

    Ok(module)
}

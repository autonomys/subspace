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
//!
//! Substrate provides the `sc-rpc` crate, which defines the core RPC layer
//! used by Substrate nodes. This file extends those RPC definitions with
//! capabilities that are specific to this project's runtime configuration.

#![warn(missing_docs)]

use jsonrpsee::RpcModule;
use mmr_rpc::{Mmr, MmrApiServer};
use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
use sc_client_api::{AuxStore, BlockBackend};
use sc_consensus_subspace::archiver::{ArchivedSegmentNotification, SegmentHeadersStore};
use sc_consensus_subspace::notification::SubspaceNotificationStream;
use sc_consensus_subspace::slot_worker::{
    NewSlotNotification, RewardSigningNotification, SubspaceSyncOracle,
};
use sc_consensus_subspace_rpc::{SubspaceRpc, SubspaceRpcApiServer, SubspaceRpcConfig};
use sc_rpc::SubscriptionTaskExecutor;
use sc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};
use sp_consensus::SyncOracle;
use sp_consensus_subspace::SubspaceApi;
use sp_objects::ObjectsApi;
use std::sync::Arc;
use subspace_core_primitives::{BlockNumber, PublicKey};
use subspace_erasure_coding::ErasureCoding;
use subspace_kzg::Kzg;
use subspace_networking::libp2p::Multiaddr;
use subspace_runtime_primitives::opaque::Block;
use subspace_runtime_primitives::{AccountId, Balance, Nonce};
use substrate_frame_rpc_system::{System, SystemApiServer};

/// Full client dependencies.
pub struct FullDeps<C, P, SO, AS, B>
where
    SO: SyncOracle + Send + Sync + Clone,
{
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
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
    /// Bootstrap nodes for DSN.
    pub dsn_bootstrap_nodes: Vec<Multiaddr>,
    /// Segment header provider.
    pub segment_headers_store: SegmentHeadersStore<AS>,
    /// Subspace sync oracle.
    pub sync_oracle: SubspaceSyncOracle<SO>,
    /// Kzg instance.
    pub kzg: Kzg,
    /// Erasure coding instance.
    pub erasure_coding: ErasureCoding,
    /// Backend used by the node.
    pub backend: Arc<B>,
}

/// Instantiate all full RPC extensions.
pub fn create_full<C, P, SO, AS, B>(
    deps: FullDeps<C, P, SO, AS, B>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    C: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = BlockChainError>
        + Send
        + Sync
        + 'static,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>
        + pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
        + BlockBuilder<Block>
        + SubspaceApi<Block, PublicKey>
        + mmr_rpc::MmrRuntimeApi<Block, <Block as sp_runtime::traits::Block>::Hash, BlockNumber>
        + ObjectsApi<Block>,
    P: TransactionPool + 'static,
    SO: SyncOracle + Send + Sync + Clone + 'static,
    AS: AuxStore + Send + Sync + 'static,
    B: sc_client_api::Backend<Block> + Send + Sync + 'static,
    B::State: sc_client_api::StateBackend<sp_runtime::traits::HashingFor<Block>>,
{
    let mut module = RpcModule::new(());
    let FullDeps {
        client,
        pool,
        subscription_executor,
        new_slot_notification_stream,
        reward_signing_notification_stream,
        archived_segment_notification_stream,
        dsn_bootstrap_nodes,
        segment_headers_store,
        sync_oracle,
        kzg,
        erasure_coding,
        backend,
    } = deps;

    module.merge(System::new(client.clone(), pool).into_rpc())?;
    module.merge(TransactionPayment::new(client.clone()).into_rpc())?;

    module.merge(
        SubspaceRpc::new(SubspaceRpcConfig {
            client: client.clone(),
            subscription_executor,
            new_slot_notification_stream,
            reward_signing_notification_stream,
            archived_segment_notification_stream,
            dsn_bootstrap_nodes,
            segment_headers_store,
            sync_oracle,
            kzg,
            erasure_coding,
        })?
        .into_rpc(),
    )?;
    module.merge(
        Mmr::new(
            client,
            backend
                .offchain_storage()
                .ok_or("Backend doesn't provide the required offchain storage")?,
        )
        .into_rpc(),
    )?;

    Ok(module)
}

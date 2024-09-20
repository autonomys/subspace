// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

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

use sc_client_api::{
    BlockBackend, BlockchainEvents, ExecutorProvider, ProofProvider, StorageProvider, UsageProvider,
};
use sc_rpc_api::DenyUnsafe;
use sc_service::{
    gen_rpc_module, init_telemetry, propagate_transaction_notifications, start_rpc_servers, Error,
    MetricsService, RpcHandlers, SpawnTasksParams,
};
use sc_transaction_pool_api::MaintainedTransactionPool;
use sp_api::{CallApiAt, ProvideRuntimeApi};
use sp_blockchain::{HeaderBackend, HeaderMetadata};
use sp_consensus::block_validation::Chain;
use sp_runtime::traits::{Block as BlockT, BlockIdTo};
use std::sync::Arc;
use tracing::info;

/// Spawn the tasks that are required to run a node.
pub(super) fn spawn_tasks<TBl, TBackend, TExPool, TRpc, TCl>(
    params: SpawnTasksParams<TBl, TCl, TExPool, TRpc, TBackend>,
) -> Result<RpcHandlers, Error>
where
    TCl: ProvideRuntimeApi<TBl>
        + HeaderMetadata<TBl, Error = sp_blockchain::Error>
        + Chain<TBl>
        + BlockBackend<TBl>
        + BlockIdTo<TBl, Error = sp_blockchain::Error>
        + ProofProvider<TBl>
        + HeaderBackend<TBl>
        + BlockchainEvents<TBl>
        + ExecutorProvider<TBl>
        + UsageProvider<TBl>
        + StorageProvider<TBl, TBackend>
        + CallApiAt<TBl>
        + Send
        + 'static,
    TCl::Api: sp_api::Metadata<TBl>
        + sp_transaction_pool::runtime_api::TaggedTransactionQueue<TBl>
        + sp_session::SessionKeys<TBl>
        + sp_api::ApiExt<TBl>,
    TBl: BlockT,
    TBl::Hash: Unpin,
    TBl::Header: Unpin,
    TBackend: 'static + sc_client_api::backend::Backend<TBl> + Send,
    TExPool: MaintainedTransactionPool<Block = TBl, Hash = TBl::Hash> + 'static,
{
    let SpawnTasksParams {
        // TODO: Stop using `Configuration` once
        //  https://github.com/paritytech/polkadot-sdk/pull/5364 is in our fork
        mut config,
        task_manager,
        client,
        backend,
        keystore,
        transaction_pool,
        rpc_builder,
        network,
        system_rpc_tx,
        tx_handler_controller,
        sync_service,
        telemetry,
    } = params;

    let chain_info = client.usage_info().chain;

    let sysinfo = sc_sysinfo::gather_sysinfo();
    sc_sysinfo::print_sysinfo(&sysinfo);

    let telemetry = telemetry
        .map(|telemetry| {
            init_telemetry(
                &mut config,
                network.clone(),
                client.clone(),
                telemetry,
                Some(sysinfo),
            )
        })
        .transpose()?;

    info!("📦 Highest known block at #{}", chain_info.best_number);

    let spawn_handle = task_manager.spawn_handle();

    // Inform the tx pool about imported and finalized blocks.
    spawn_handle.spawn(
        "txpool-notifications",
        Some("transaction-pool"),
        sc_transaction_pool::notification_future(client.clone(), transaction_pool.clone()),
    );

    spawn_handle.spawn(
        "on-transaction-imported",
        Some("transaction-pool"),
        propagate_transaction_notifications(
            transaction_pool.clone(),
            tx_handler_controller,
            telemetry.clone(),
        ),
    );

    // Periodically updated metrics and telemetry updates.
    spawn_handle.spawn(
        "telemetry-periodic-send",
        None,
        MetricsService::new(telemetry).run(
            client.clone(),
            transaction_pool.clone(),
            network.clone(),
            sync_service.clone(),
        ),
    );

    let rpc_id_provider = config.rpc_id_provider.take();

    // jsonrpsee RPC
    let gen_rpc_module = |deny_unsafe: DenyUnsafe| {
        gen_rpc_module(
            deny_unsafe,
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool.clone(),
            keystore.clone(),
            system_rpc_tx.clone(),
            &config,
            backend.clone(),
            &*rpc_builder,
        )
    };

    let rpc = config
        .rpc_addr
        .map(|_| start_rpc_servers(&config, gen_rpc_module, rpc_id_provider))
        .transpose()?;
    let rpc_handlers = RpcHandlers::new(Arc::new(gen_rpc_module(DenyUnsafe::No)?));

    // Spawn informant task
    spawn_handle.spawn(
        "informant",
        None,
        sc_informant::build(
            client.clone(),
            network,
            sync_service.clone(),
            config.informant_output_format,
        ),
    );

    task_manager.keep_alive((config.base_path, rpc));

    Ok(rpc_handlers)
}

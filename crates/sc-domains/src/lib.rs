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

//! Domain specific Host functions and Extension factory

use sc_client_api::execution_extensions::ExtensionsFactory as ExtensionsFactoryT;
use sc_executor::RuntimeVersionOf;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::DomainsApi;
use sp_externalities::Extensions;
use sp_messenger_host_functions::{MessengerApi, MessengerExtension, MessengerHostFunctionsImpl};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_subspace_mmr::host_functions::{MmrApi, SubspaceMmrExtension, SubspaceMmrHostFunctionsImpl};
use std::marker::PhantomData;
use std::sync::Arc;

/// Host functions required for Subspace domain
#[cfg(not(feature = "runtime-benchmarks"))]
pub type HostFunctions = (
    sp_auto_id::auto_id_runtime_interface::HostFunctions,
    sp_io::SubstrateHostFunctions,
    sp_messenger_host_functions::HostFunctions,
    sp_subspace_mmr::DomainHostFunctions,
);

/// Host functions required for Subspace domain
#[cfg(feature = "runtime-benchmarks")]
pub type HostFunctions = (
    sp_auto_id::auto_id_runtime_interface::HostFunctions,
    sp_io::SubstrateHostFunctions,
    sp_messenger_host_functions::HostFunctions,
    sp_subspace_mmr::DomainHostFunctions,
    frame_benchmarking::benchmarking::HostFunctions,
);

/// Runtime executor for Domains
pub type RuntimeExecutor = sc_executor::WasmExecutor<HostFunctions>;

/// Extensions factory for subspace domains.
pub struct ExtensionsFactory<CClient, CBlock, Block, Executor> {
    consensus_client: Arc<CClient>,
    executor: Arc<Executor>,
    _marker: PhantomData<(CBlock, Block)>,
}

impl<CClient, CBlock, Block, Executor> ExtensionsFactory<CClient, CBlock, Block, Executor> {
    pub fn new(consensus_client: Arc<CClient>, executor: Arc<Executor>) -> Self {
        Self {
            consensus_client,
            executor,
            _marker: Default::default(),
        }
    }
}

impl<CClient, CBlock, Block, Executor> ExtensionsFactoryT<Block>
    for ExtensionsFactory<CClient, CBlock, Block, Executor>
where
    Block: BlockT,
    CBlock: BlockT,
    CBlock::Hash: From<H256>,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + 'static,
    CClient::Api: MmrApi<CBlock, H256, NumberFor<CBlock>>
        + MessengerApi<CBlock>
        + DomainsApi<CBlock, Block::Header>,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn extensions_for(
        &self,
        _block_hash: Block::Hash,
        _block_number: NumberFor<Block>,
    ) -> Extensions {
        let mut exts = Extensions::new();
        exts.register(SubspaceMmrExtension::new(Arc::new(
            SubspaceMmrHostFunctionsImpl::<CBlock, _>::new(self.consensus_client.clone()),
        )));

        exts.register(MessengerExtension::new(Arc::new(
            MessengerHostFunctionsImpl::<CBlock, _, Block, _>::new(
                self.consensus_client.clone(),
                self.executor.clone(),
            ),
        )));

        exts.register(sp_auto_id::host_functions::HostFunctionExtension::new(
            Arc::new(sp_auto_id::host_functions::HostFunctionsImpl),
        ));

        exts
    }
}

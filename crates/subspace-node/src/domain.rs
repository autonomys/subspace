// Copyright (C) 2023 Subspace Labs, Inc.
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

pub(crate) mod cli;
pub(crate) mod evm_chain_spec;

pub use self::cli::{DomainCli, Subcommand as DomainSubcommand};
use evm_domain_runtime::AccountId as AccountId20;
use sc_client_api::Backend;
use sc_executor::{NativeExecutionDispatch, RuntimeVersionOf};
use sc_service::{BuildGenesisBlock, GenesisBlockBuilder};
use sp_core::crypto::AccountId32;
use sp_core::{ByteArray, H160, H256};
use sp_domains::RuntimeType;
use sp_runtime::traits::{Block as BlockT, Convert, Header as HeaderT};
use std::marker::PhantomData;
use std::sync::Arc;

pub struct AccountId32ToAccountId20Converter;

impl Convert<AccountId32, AccountId20> for AccountId32ToAccountId20Converter {
    fn convert(acc: AccountId32) -> AccountId20 {
        // Using the full hex key, truncating to the first 20 bytes (the first 40 hex chars)
        H160::from_slice(&acc.as_slice()[0..20]).into()
    }
}

/// EVM domain executor instance.
pub struct EVMDomainExecutorDispatch;

impl NativeExecutionDispatch for EVMDomainExecutorDispatch {
    #[cfg(feature = "runtime-benchmarks")]
    type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
    #[cfg(not(feature = "runtime-benchmarks"))]
    type ExtendHostFunctions = ();

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        evm_domain_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        evm_domain_runtime::native_version()
    }
}

/// [`DomainGenesisBlockBuilder`] is used on the consensus node for building the
/// domain genesis block from a specific serialized domain runtime genesis config.
pub struct DomainGenesisBlockBuilder<Block, B, E> {
    backend: Arc<B>,
    executor: E,
    _phantom: PhantomData<Block>,
}

impl<Block, B, E> DomainGenesisBlockBuilder<Block, B, E>
where
    Block: BlockT,
    B: Backend<Block>,
    E: RuntimeVersionOf + Clone,
{
    /// Constructs a new instance of [`DomainGenesisBlockBuilder`].
    pub fn new(backend: Arc<B>, executor: E) -> Self {
        Self {
            backend,
            executor,
            _phantom: Default::default(),
        }
    }

    /// Constructs the genesis domain block from a serialized runtime genesis config.
    pub fn generate_genesis_block(
        &self,
        runtime_type: RuntimeType,
        runtime_code: Vec<u8>,
    ) -> sp_blockchain::Result<Block> {
        let domain_genesis_block_builder = match runtime_type {
            RuntimeType::Evm => {
                let mut runtime_cfg = evm_domain_runtime::RuntimeGenesisConfig::default();
                runtime_cfg.system.code = runtime_code;
                GenesisBlockBuilder::new(
                    &runtime_cfg,
                    false,
                    self.backend.clone(),
                    self.executor.clone(),
                )?
            }
        };
        domain_genesis_block_builder
            .build_genesis_block()
            .map(|(genesis_block, _)| genesis_block)
    }
}

impl<Block, B, E> sp_domains::GenerateGenesisStateRoot for DomainGenesisBlockBuilder<Block, B, E>
where
    Block: BlockT,
    Block::Hash: Into<H256>,
    B: Backend<Block>,
    E: RuntimeVersionOf + Clone + Send + Sync,
{
    fn generate_genesis_state_root(
        &self,
        runtime_type: RuntimeType,
        runtime_code: Vec<u8>,
    ) -> Option<H256> {
        self.generate_genesis_block(runtime_type, runtime_code)
            .map(|genesis_block| *genesis_block.header().state_root())
            .ok()
            .map(Into::into)
    }
}

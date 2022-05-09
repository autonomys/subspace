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

use crate::ExecutionChainSpec;
use clap::Parser;
use sc_cli::{
    ChainSpec, CliConfiguration, DefaultConfigurationValues, ImportParams, KeystoreParams,
    NetworkParams, Result, RunCmd, RuntimeVersion, SharedParams, SubstrateCli,
};
use sc_service::{config::PrometheusConfig, BasePath};
use std::{net::SocketAddr, path::PathBuf};

/// Sub-commands supported by the executor.
#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
    /// Build a chain specification.
    BuildSpec(sc_cli::BuildSpecCmd),

    /// Validate blocks.
    CheckBlock(sc_cli::CheckBlockCmd),

    /// Export blocks.
    ExportBlocks(sc_cli::ExportBlocksCmd),

    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Import blocks.
    ImportBlocks(sc_cli::ImportBlocksCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Sub-commands concerned with benchmarking.
    #[clap(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),
}

pub struct SecondaryChainCli {
    /// Run a node.
    pub run: RunCmd,

    /// The base path that should be used by the secondary chain.
    pub base_path: Option<PathBuf>,

    /// Specification of the secondary chain derived from primary chain spec.
    pub chain_spec: ExecutionChainSpec,
}

impl SecondaryChainCli {
    /// Constructs a new instance of [`SecondaryChainCli`].
    ///
    /// If no explicit base path for the secondary chain, the default value will be `primary_base_path/executor`.
    pub fn new<'a>(
        base_path: Option<PathBuf>,
        chain_spec: ExecutionChainSpec,
        secondary_chain_args: impl Iterator<Item = &'a String>,
    ) -> Self {
        Self {
            base_path,
            chain_spec,
            run: RunCmd::parse_from(secondary_chain_args),
        }
    }
}

impl SubstrateCli for SecondaryChainCli {
    fn impl_name() -> String {
        "Subspace Executor".into()
    }

    fn impl_version() -> String {
        env!("SUBSTRATE_CLI_IMPL_VERSION").into()
    }

    fn executable_name() -> String {
        // Customize to make sure directory used for data by default is the same regardless of the
        // name of the executable file.
        "subspace-node".to_string()
    }

    fn description() -> String {
        "Subspace Executor".into()
    }

    fn author() -> String {
        env!("CARGO_PKG_AUTHORS").into()
    }

    fn support_url() -> String {
        "https://github.com/subspace/subspace/issues/new".into()
    }

    fn copyright_start_year() -> i32 {
        2022
    }

    fn load_spec(&self, _id: &str) -> std::result::Result<Box<dyn ChainSpec>, String> {
        let mut chain_spec = self.chain_spec.clone();

        // In case there are bootstrap nodes specified explicitly, ignore those that are in the
        // chain spec
        if !self.run.network_params.bootnodes.is_empty() {
            let mut chain_spec_value =
                serde_json::to_value(&chain_spec).map_err(|error| error.to_string())?;
            if let Some(boot_nodes) = chain_spec_value.get_mut("bootNodes") {
                if let Some(boot_nodes) = boot_nodes.as_array_mut() {
                    boot_nodes.clear();
                }
            }
            chain_spec =
                serde_json::from_value(chain_spec_value).map_err(|error| error.to_string())?;
        }

        Ok(Box::new(chain_spec))
    }

    fn native_runtime_version(_chain_spec: &Box<dyn ChainSpec>) -> &'static RuntimeVersion {
        &cirrus_runtime::VERSION
    }
}

impl DefaultConfigurationValues for SecondaryChainCli {
    fn p2p_listen_port() -> u16 {
        30334
    }

    fn rpc_ws_listen_port() -> u16 {
        9945
    }

    fn rpc_http_listen_port() -> u16 {
        9934
    }

    fn prometheus_listen_port() -> u16 {
        9616
    }
}

impl CliConfiguration<Self> for SecondaryChainCli {
    fn shared_params(&self) -> &SharedParams {
        self.run.shared_params()
    }

    fn import_params(&self) -> Option<&ImportParams> {
        self.run.import_params()
    }

    fn network_params(&self) -> Option<&NetworkParams> {
        self.run.network_params()
    }

    fn keystore_params(&self) -> Option<&KeystoreParams> {
        self.run.keystore_params()
    }

    fn base_path(&self) -> Result<Option<BasePath>> {
        Ok(self
            .shared_params()
            .base_path()
            .or_else(|| self.base_path.clone().map(Into::into)))
    }

    fn rpc_http(&self, default_listen_port: u16) -> Result<Option<SocketAddr>> {
        self.run.rpc_http(default_listen_port)
    }

    fn rpc_ipc(&self) -> Result<Option<String>> {
        self.run.rpc_ipc()
    }

    fn rpc_ws(&self, default_listen_port: u16) -> Result<Option<SocketAddr>> {
        self.run.rpc_ws(default_listen_port)
    }

    fn prometheus_config(
        &self,
        default_listen_port: u16,
        chain_spec: &Box<dyn ChainSpec>,
    ) -> Result<Option<PrometheusConfig>> {
        self.run.prometheus_config(default_listen_port, chain_spec)
    }

    fn chain_id(&self, is_dev: bool) -> Result<String> {
        self.run.chain_id(is_dev)
    }

    fn role(&self, is_dev: bool) -> Result<sc_service::Role> {
        self.run.role(is_dev)
    }

    fn transaction_pool(&self) -> Result<sc_service::config::TransactionPoolOptions> {
        self.run.transaction_pool()
    }

    fn state_cache_child_ratio(&self) -> Result<Option<usize>> {
        self.run.state_cache_child_ratio()
    }

    fn rpc_methods(&self) -> Result<sc_service::config::RpcMethods> {
        self.run.rpc_methods()
    }

    fn rpc_ws_max_connections(&self) -> Result<Option<usize>> {
        self.run.rpc_ws_max_connections()
    }

    fn rpc_cors(&self, is_dev: bool) -> Result<Option<Vec<String>>> {
        self.run.rpc_cors(is_dev)
    }

    fn default_heap_pages(&self) -> Result<Option<u64>> {
        self.run.default_heap_pages()
    }

    fn force_authoring(&self) -> Result<bool> {
        self.run.force_authoring()
    }

    fn disable_grandpa(&self) -> Result<bool> {
        self.run.disable_grandpa()
    }

    fn max_runtime_instances(&self) -> Result<Option<usize>> {
        self.run.max_runtime_instances()
    }

    fn announce_block(&self) -> Result<bool> {
        self.run.announce_block()
    }

    fn dev_key_seed(&self, is_dev: bool) -> Result<Option<String>> {
        self.run.dev_key_seed(is_dev)
    }

    fn telemetry_endpoints(
        &self,
        chain_spec: &Box<dyn ChainSpec>,
    ) -> Result<Option<sc_telemetry::TelemetryEndpoints>> {
        self.run.telemetry_endpoints(chain_spec)
    }
}

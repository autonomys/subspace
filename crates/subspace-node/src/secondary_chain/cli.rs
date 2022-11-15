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

use clap::Parser;
use sc_cli::{
    ChainSpec, CliConfiguration, DefaultConfigurationValues, ImportParams, KeystoreParams,
    NetworkParams, Result, RunCmd as SubstrateRunCmd, RuntimeVersion, SharedParams, SubstrateCli,
};
use sc_service::config::PrometheusConfig;
use sc_service::BasePath;
use sc_subspace_chain_specs::ExecutionChainSpec;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::PathBuf;
use system_domain_runtime::GenesisConfig as SystemDomainGenesisConfig;

/// Sub-commands supported by the executor.
#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Sub-commands concerned with benchmarking.
    #[clap(subcommand)]
    Benchmark(Box<frame_benchmarking_cli::BenchmarkCmd>),
}

#[derive(Debug, Clone, Parser)]
pub struct RunCmd {
    /// Substrate run commands.
    #[clap(flatten)]
    pub sub_run: SubstrateRunCmd,

    /// Optional relayer address to relay messages on behalf.
    #[arg(long)]
    pub relayer_id: Option<String>,
}

pub struct SecondaryChainCli {
    /// Run a node.
    pub run: RunCmd,

    /// The base path that should be used by the secondary chain.
    pub base_path: Option<PathBuf>,

    /// Specification of the secondary chain derived from primary chain spec.
    pub chain_spec: ExecutionChainSpec<SystemDomainGenesisConfig>,
}

impl SecondaryChainCli {
    /// Constructs a new instance of [`SecondaryChainCli`].
    ///
    /// If no explicit base path for the secondary chain, the default value will be `primary_base_path/executor`.
    pub fn new<'a>(
        base_path: Option<PathBuf>,
        chain_spec: ExecutionChainSpec<SystemDomainGenesisConfig>,
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
        if !self.run.sub_run.network_params.bootnodes.is_empty() {
            let mut chain_spec_value: Value = serde_json::from_str(&chain_spec.as_json(true)?)
                .map_err(|error| error.to_string())?;
            if let Some(boot_nodes) = chain_spec_value.get_mut("bootNodes") {
                if let Some(boot_nodes) = boot_nodes.as_array_mut() {
                    boot_nodes.clear();
                }
            }
            // Such mess because native serialization of the chain spec serializes it twice, see
            // docs on `sc_subspace_chain_specs::utils::SerializableChainSpec`.
            chain_spec = serde_json::to_string(&chain_spec_value.to_string())
                .and_then(|chain_spec_string| serde_json::from_str(&chain_spec_string))
                .map_err(|error| error.to_string())?;
        }

        Ok(Box::new(chain_spec))
    }

    fn native_runtime_version(_chain_spec: &Box<dyn ChainSpec>) -> &'static RuntimeVersion {
        &system_domain_runtime::VERSION
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
        self.run.sub_run.shared_params()
    }

    fn import_params(&self) -> Option<&ImportParams> {
        self.run.sub_run.import_params()
    }

    fn network_params(&self) -> Option<&NetworkParams> {
        self.run.sub_run.network_params()
    }

    fn keystore_params(&self) -> Option<&KeystoreParams> {
        self.run.sub_run.keystore_params()
    }

    fn base_path(&self) -> Result<Option<BasePath>> {
        Ok(self
            .shared_params()
            .base_path()?
            .or_else(|| self.base_path.clone().map(Into::into)))
    }

    fn rpc_http(&self, default_listen_port: u16) -> Result<Option<SocketAddr>> {
        self.run.sub_run.rpc_http(default_listen_port)
    }

    fn rpc_ipc(&self) -> Result<Option<String>> {
        self.run.sub_run.rpc_ipc()
    }

    fn rpc_ws(&self, default_listen_port: u16) -> Result<Option<SocketAddr>> {
        self.run.sub_run.rpc_ws(default_listen_port)
    }

    fn prometheus_config(
        &self,
        default_listen_port: u16,
        chain_spec: &Box<dyn ChainSpec>,
    ) -> Result<Option<PrometheusConfig>> {
        self.run
            .sub_run
            .prometheus_config(default_listen_port, chain_spec)
    }

    fn chain_id(&self, is_dev: bool) -> Result<String> {
        self.run.sub_run.chain_id(is_dev)
    }

    fn role(&self, is_dev: bool) -> Result<sc_service::Role> {
        self.run.sub_run.role(is_dev)
    }

    fn transaction_pool(&self, is_dev: bool) -> Result<sc_service::config::TransactionPoolOptions> {
        self.run.sub_run.transaction_pool(is_dev)
    }

    fn trie_cache_maximum_size(&self) -> Result<Option<usize>> {
        self.run.sub_run.trie_cache_maximum_size()
    }

    fn rpc_methods(&self) -> Result<sc_service::config::RpcMethods> {
        self.run.sub_run.rpc_methods()
    }

    fn rpc_ws_max_connections(&self) -> Result<Option<usize>> {
        self.run.sub_run.rpc_ws_max_connections()
    }

    fn rpc_cors(&self, is_dev: bool) -> Result<Option<Vec<String>>> {
        self.run.sub_run.rpc_cors(is_dev)
    }

    fn default_heap_pages(&self) -> Result<Option<u64>> {
        self.run.sub_run.default_heap_pages()
    }

    fn force_authoring(&self) -> Result<bool> {
        self.run.sub_run.force_authoring()
    }

    fn disable_grandpa(&self) -> Result<bool> {
        self.run.sub_run.disable_grandpa()
    }

    fn max_runtime_instances(&self) -> Result<Option<usize>> {
        self.run.sub_run.max_runtime_instances()
    }

    fn announce_block(&self) -> Result<bool> {
        self.run.sub_run.announce_block()
    }

    fn dev_key_seed(&self, is_dev: bool) -> Result<Option<String>> {
        self.run.sub_run.dev_key_seed(is_dev)
    }

    fn telemetry_endpoints(
        &self,
        chain_spec: &Box<dyn ChainSpec>,
    ) -> Result<Option<sc_telemetry::TelemetryEndpoints>> {
        self.run.sub_run.telemetry_endpoints(chain_spec)
    }
}

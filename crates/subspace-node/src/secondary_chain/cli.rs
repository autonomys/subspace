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

use crate::core_domain::cli::CoreDomainCli;
use crate::parser::parse_relayer_id;
use clap::Parser;
use domain_runtime_primitives::RelayerId;
use domain_service::DomainConfiguration;
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

#[derive(Debug, Parser)]
pub struct DomainCli {
    /// Run a node.
    #[clap(flatten)]
    pub run_system: SubstrateRunCmd,

    /// Optional relayer address to relay messages on behalf.
    #[clap(long, value_parser = parse_relayer_id)]
    pub relayer_id: Option<RelayerId>,

    #[clap(raw = true)]
    pub core_domain_args: Vec<String>,
}

pub struct SecondaryChainCli {
    /// Run a node.
    pub run: DomainCli,

    /// The base path that should be used by the secondary chain.
    pub base_path: Option<PathBuf>,

    /// Specification of the secondary chain derived from primary chain spec.
    pub chain_spec: ExecutionChainSpec<SystemDomainGenesisConfig>,
}

impl SecondaryChainCli {
    /// Constructs a new instance of [`SecondaryChainCli`].
    ///
    /// If no explicit base path for the secondary chain, the default value will be `primary_base_path/executor`.
    pub fn new(
        mut base_path: Option<PathBuf>,
        chain_spec: ExecutionChainSpec<SystemDomainGenesisConfig>,
        secondary_chain_args: impl Iterator<Item = String>,
    ) -> (Self, Option<CoreDomainCli>) {
        let domain_cli = DomainCli::parse_from(
            [Self::executable_name()]
                .into_iter()
                .chain(secondary_chain_args),
        );

        let maybe_core_domain_cli = if !domain_cli.core_domain_args.is_empty() {
            let core_domain_cli = CoreDomainCli::new(
                base_path.clone(),
                domain_cli.core_domain_args.clone().into_iter(),
            );
            Some(core_domain_cli)
        } else {
            None
        };

        (
            Self {
                base_path: base_path.as_mut().map(|path| path.join("system")),
                chain_spec,
                run: domain_cli,
            },
            maybe_core_domain_cli,
        )
    }

    /// Creates domain configuration from Secondary chain cli.
    pub fn create_domain_configuration(
        &self,
        tokio_handle: tokio::runtime::Handle,
    ) -> sc_cli::Result<DomainConfiguration> {
        // if is dev, use the known key ring to start relayer
        let maybe_relayer_id = if self.shared_params().is_dev() {
            self.run
                .run_system
                .get_keyring()
                .map(|kr| kr.to_account_id())
        } else {
            self.run.relayer_id.clone()
        };

        let service_config = SubstrateCli::create_configuration(self, self, tokio_handle)?;
        Ok(DomainConfiguration {
            service_config,
            maybe_relayer_id,
        })
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
        if !self.run.run_system.network_params.bootnodes.is_empty() {
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
        self.run.run_system.shared_params()
    }

    fn import_params(&self) -> Option<&ImportParams> {
        self.run.run_system.import_params()
    }

    fn network_params(&self) -> Option<&NetworkParams> {
        self.run.run_system.network_params()
    }

    fn keystore_params(&self) -> Option<&KeystoreParams> {
        self.run.run_system.keystore_params()
    }

    fn base_path(&self) -> Result<Option<BasePath>> {
        Ok(self
            .shared_params()
            .base_path()?
            .as_mut()
            .map(|base_path| {
                let path: PathBuf = base_path.path().to_path_buf();
                BasePath::new(path.join("system"))
            })
            .or_else(|| self.base_path.clone().map(Into::into)))
    }

    fn rpc_http(&self, default_listen_port: u16) -> Result<Option<SocketAddr>> {
        self.run.run_system.rpc_http(default_listen_port)
    }

    fn rpc_ipc(&self) -> Result<Option<String>> {
        self.run.run_system.rpc_ipc()
    }

    fn rpc_ws(&self, default_listen_port: u16) -> Result<Option<SocketAddr>> {
        self.run.run_system.rpc_ws(default_listen_port)
    }

    fn prometheus_config(
        &self,
        default_listen_port: u16,
        chain_spec: &Box<dyn ChainSpec>,
    ) -> Result<Option<PrometheusConfig>> {
        self.run
            .run_system
            .prometheus_config(default_listen_port, chain_spec)
    }

    fn chain_id(&self, is_dev: bool) -> Result<String> {
        self.run.run_system.chain_id(is_dev)
    }

    fn role(&self, is_dev: bool) -> Result<sc_service::Role> {
        self.run.run_system.role(is_dev)
    }

    fn transaction_pool(&self, is_dev: bool) -> Result<sc_service::config::TransactionPoolOptions> {
        self.run.run_system.transaction_pool(is_dev)
    }

    fn trie_cache_maximum_size(&self) -> Result<Option<usize>> {
        self.run.run_system.trie_cache_maximum_size()
    }

    fn rpc_methods(&self) -> Result<sc_service::config::RpcMethods> {
        self.run.run_system.rpc_methods()
    }

    fn rpc_ws_max_connections(&self) -> Result<Option<usize>> {
        self.run.run_system.rpc_ws_max_connections()
    }

    fn rpc_cors(&self, is_dev: bool) -> Result<Option<Vec<String>>> {
        self.run.run_system.rpc_cors(is_dev)
    }

    fn default_heap_pages(&self) -> Result<Option<u64>> {
        self.run.run_system.default_heap_pages()
    }

    fn force_authoring(&self) -> Result<bool> {
        self.run.run_system.force_authoring()
    }

    fn disable_grandpa(&self) -> Result<bool> {
        self.run.run_system.disable_grandpa()
    }

    fn max_runtime_instances(&self) -> Result<Option<usize>> {
        self.run.run_system.max_runtime_instances()
    }

    fn announce_block(&self) -> Result<bool> {
        self.run.run_system.announce_block()
    }

    fn dev_key_seed(&self, is_dev: bool) -> Result<Option<String>> {
        self.run.run_system.dev_key_seed(is_dev)
    }

    fn telemetry_endpoints(
        &self,
        chain_spec: &Box<dyn ChainSpec>,
    ) -> Result<Option<sc_telemetry::TelemetryEndpoints>> {
        self.run.run_system.telemetry_endpoints(chain_spec)
    }
}

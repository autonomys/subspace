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

use crate::domain::evm_chain_spec::{self, SpecId};
use clap::Parser;
use domain_service::DomainConfiguration;
use sc_cli::{
    ChainSpec, CliConfiguration, DefaultConfigurationValues, ImportParams, KeystoreParams,
    NetworkParams, Result, Role, RunCmd as SubstrateRunCmd, RuntimeVersion, SharedParams,
    SubstrateCli,
};
use sc_service::config::PrometheusConfig;
use sc_service::BasePath;
use sp_core::crypto::AccountId32;
use sp_domains::DomainId;
use sp_runtime::traits::Convert;
use std::io::Write;
use std::net::SocketAddr;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str::FromStr;

/// Sub-commands supported by the executor.
#[derive(Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Subcommand {
    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Sub-commands concerned with benchmarking.
    #[clap(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),

    /// Build the genesis config of the evm domain chain in json format
    BuildGenesisConfig(BuildGenesisConfigCmd),
}

fn parse_domain_id(s: &str) -> std::result::Result<DomainId, ParseIntError> {
    s.parse::<u32>().map(Into::into)
}

#[derive(Debug, Parser)]
pub struct DomainCli {
    /// Run a domain node.
    #[clap(flatten)]
    pub run: SubstrateRunCmd,

    #[clap(long, value_parser = parse_domain_id)]
    pub domain_id: DomainId,

    /// Optional relayer address to relay messages on behalf.
    #[clap(long)]
    pub relayer_id: Option<String>,

    /// Run the node as an Operator
    #[arg(long, conflicts_with = "validator")]
    pub operator: bool,

    /// Additional args for domain.
    #[clap(raw = true)]
    additional_args: Vec<String>,
}

impl DomainCli {
    /// Constructs a new instance of [`DomainCli`].
    pub fn new(
        consensus_base_path: Option<PathBuf>,
        domain_args: impl Iterator<Item = String>,
    ) -> Self {
        let mut cli =
            DomainCli::parse_from([Self::executable_name()].into_iter().chain(domain_args));

        // Use `consensus_base_path/domain-{domain_id}` as the domain base path if it's not
        // specified explicitly but there is an explicit consensus base path.
        match consensus_base_path {
            Some(c_path) if cli.run.shared_params.base_path.is_none() => {
                cli.run
                    .shared_params
                    .base_path
                    .replace(c_path.join(format!("domain-{}", u32::from(cli.domain_id))));
            }
            _ => {}
        }

        cli
    }

    pub fn additional_args(&self) -> impl Iterator<Item = String> {
        [Self::executable_name()]
            .into_iter()
            .chain(self.additional_args.clone())
    }

    pub fn maybe_relayer_id<AccountId, CA>(&self) -> sc_cli::Result<Option<AccountId>>
    where
        CA: Convert<AccountId32, AccountId>,
        AccountId: FromStr,
    {
        // if is dev, use the known key ring to start relayer
        let res = if self.shared_params().is_dev() && self.relayer_id.is_none() {
            self.run
                .get_keyring()
                .map(|kr| CA::convert(kr.to_account_id()))
        } else if let Some(relayer_id) = self.relayer_id.clone() {
            Some(AccountId::from_str(&relayer_id).map_err(|_err| {
                sc_cli::Error::Input(format!("Invalid Relayer Id: {relayer_id}"))
            })?)
        } else {
            None
        };
        Ok(res)
    }

    /// Creates domain configuration from domain cli.
    pub fn create_domain_configuration<AccountId, CA>(
        &self,
        tokio_handle: tokio::runtime::Handle,
    ) -> sc_cli::Result<DomainConfiguration<AccountId>>
    where
        CA: Convert<AccountId32, AccountId>,
        AccountId: FromStr,
    {
        // if is dev, use the known key ring to start relayer
        let maybe_relayer_id = if self.shared_params().is_dev() && self.relayer_id.is_none() {
            self.run
                .get_keyring()
                .map(|kr| CA::convert(kr.to_account_id()))
        } else if let Some(relayer_id) = self.relayer_id.clone() {
            Some(AccountId::from_str(&relayer_id).map_err(|_err| {
                sc_cli::Error::Input(format!("Invalid Relayer Id: {relayer_id}"))
            })?)
        } else {
            None
        };

        let service_config = SubstrateCli::create_configuration(self, self, tokio_handle)?;
        Ok(DomainConfiguration {
            service_config,
            maybe_relayer_id,
        })
    }
}

impl SubstrateCli for DomainCli {
    fn impl_name() -> String {
        "Subspace Domain".into()
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
        "Subspace Domain".into()
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

    fn load_spec(&self, id: &str) -> std::result::Result<Box<dyn ChainSpec>, String> {
        // TODO: Fetch the runtime name of `self.domain_id` properly.
        let runtime_name = "evm";
        match runtime_name {
            "evm" => evm_chain_spec::load_chain_spec(id),
            unknown_name => Err(format!("Unknown runtime: {unknown_name}")),
        }
    }

    fn native_runtime_version(_chain_spec: &Box<dyn ChainSpec>) -> &'static RuntimeVersion {
        // TODO: Fetch the runtime name of `self.domain_id` properly.
        let runtime_name = "evm";
        match runtime_name {
            "evm" => &evm_domain_runtime::VERSION,
            unknown_name => unreachable!("Unknown runtime: {unknown_name}"),
        }
    }
}

impl DefaultConfigurationValues for DomainCli {
    fn p2p_listen_port() -> u16 {
        30334
    }

    fn rpc_listen_port() -> u16 {
        9945
    }

    fn prometheus_listen_port() -> u16 {
        9616
    }
}

impl CliConfiguration<Self> for DomainCli {
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
        self.shared_params().base_path()
    }

    fn rpc_addr(&self, default_listen_port: u16) -> Result<Option<SocketAddr>> {
        self.run.rpc_addr(default_listen_port)
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
        // is authority when operator is enabled or in dev mode
        let is_authority = self.operator || self.run.validator || is_dev;

        Ok(if is_authority {
            Role::Authority
        } else {
            Role::Full
        })
    }

    fn transaction_pool(&self, is_dev: bool) -> Result<sc_service::config::TransactionPoolOptions> {
        self.run.transaction_pool(is_dev)
    }

    fn trie_cache_maximum_size(&self) -> Result<Option<usize>> {
        self.run.trie_cache_maximum_size()
    }

    fn rpc_methods(&self) -> Result<sc_service::config::RpcMethods> {
        self.run.rpc_methods()
    }

    fn rpc_max_connections(&self) -> Result<u32> {
        self.run.rpc_max_connections()
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

// TODO: make the command generic over different runtime type instead of just the evm domain runtime
/// The `build-genesis-config` command used to build the genesis config of the evm domain chain.
#[derive(Debug, Clone, Parser)]
pub struct BuildGenesisConfigCmd {
    /// Whether output the WASM runtime code
    #[arg(long, default_value_t = false)]
    pub with_wasm_code: bool,

    /// The base struct of the build-genesis-config command.
    #[clap(flatten)]
    pub shared_params: SharedParams,
}

impl BuildGenesisConfigCmd {
    /// Run the build-genesis-config command
    pub fn run(&self) -> sc_cli::Result<()> {
        let is_dev = self.shared_params.is_dev();
        let chain_id = self.shared_params.chain_id(is_dev);
        let mut domain_genesis_config = match chain_id.as_str() {
            "gemini-3f" => evm_chain_spec::get_testnet_genesis_by_spec_id(SpecId::Gemini).0,
            "devnet" => evm_chain_spec::get_testnet_genesis_by_spec_id(SpecId::DevNet).0,
            "dev" => evm_chain_spec::get_testnet_genesis_by_spec_id(SpecId::Dev).0,
            "" | "local" => evm_chain_spec::get_testnet_genesis_by_spec_id(SpecId::Local).0,
            unknown_id => {
                eprintln!(
                    "unknown chain {unknown_id:?}, expected gemini-3f, devnet, dev, or local",
                );
                return Ok(());
            }
        };

        if !self.with_wasm_code {
            // Clear the WASM code of the genesis config
            domain_genesis_config.system.code = Default::default();
        }
        let raw_domain_genesis_config = serde_json::to_vec(&domain_genesis_config)
            .expect("Genesis config serialization never fails; qed");

        if std::io::stdout()
            .write_all(raw_domain_genesis_config.as_ref())
            .is_err()
        {
            let _ = std::io::stderr().write_all(b"Error writing to stdout\n");
        }
        Ok(())
    }
}

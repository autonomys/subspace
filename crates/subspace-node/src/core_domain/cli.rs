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

use crate::core_domain::{core_evm_chain_spec, core_payments_chain_spec};
use clap::Parser;
use core_evm_runtime::AccountId as AccountId20;
use domain_service::DomainConfiguration;
use once_cell::sync::OnceCell;
use sc_cli::{
    ChainSpec, CliConfiguration, DefaultConfigurationValues, ImportParams, KeystoreParams,
    NetworkParams, Result, RunCmd, RuntimeVersion, SharedParams, SubstrateCli,
};
use sc_service::config::PrometheusConfig;
use sc_service::BasePath;
use sp_core::crypto::AccountId32;
use sp_core::{ByteArray, H160};
use sp_domains::DomainId;
use sp_runtime::traits::Convert;
use std::net::SocketAddr;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str::FromStr;

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

fn parse_domain_id(s: &str) -> std::result::Result<DomainId, ParseIntError> {
    s.parse::<u32>().map(Into::into)
}

#[derive(Debug, Parser)]
pub struct CoreDomainCli {
    /// Run a node.
    #[clap(flatten)]
    pub run: RunCmd,

    #[clap(long, value_parser = parse_domain_id)]
    pub domain_id: DomainId,

    /// Optional relayer address to relay messages on behalf.
    #[clap(long)]
    pub relayer_id: Option<String>,

    /// The base path that should be used by the core domain.
    #[clap(skip)]
    pub base_path: Option<PathBuf>,

    /// Additional args for core domain.
    #[clap(raw = true)]
    additional_args: Vec<String>,
}

pub struct AccountId32ToAccountId20Converter;

impl Convert<AccountId32, AccountId20> for AccountId32ToAccountId20Converter {
    fn convert(acc: AccountId32) -> AccountId20 {
        // Using the full hex key, truncating to the first 20 bytes (the first 40 hex chars)
        H160::from_slice(&acc.as_slice()[0..20]).into()
    }
}

static CORE_DOMAIN_ID: OnceCell<DomainId> = OnceCell::new();

impl CoreDomainCli {
    /// Constructs a new instance of [`CoreDomainCli`].
    ///
    /// If no explicit base path for the core domain, the default value will be
    /// `base_path/core-domain-{domain_id}`.
    pub fn new(base_path: Option<PathBuf>, core_domain_args: impl Iterator<Item = String>) -> Self {
        let mut cli = Self {
            base_path,
            ..Self::parse_from(
                [Self::executable_name()]
                    .into_iter()
                    .chain(core_domain_args),
            )
        };

        cli.base_path
            .as_mut()
            .map(|path| path.join(format!("core-domain-{}", u32::from(cli.domain_id))));

        CORE_DOMAIN_ID
            .set(cli.domain_id)
            .expect("Initialization must succeed as the cell has never been set; qed");

        cli
    }

    pub fn additional_args(&self) -> impl Iterator<Item = String> {
        [Self::executable_name()]
            .into_iter()
            .chain(self.additional_args.clone())
    }

    /// Creates domain configuration from Core domain cli.
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

impl SubstrateCli for CoreDomainCli {
    fn impl_name() -> String {
        "Subspace".into()
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
        "Subspace Core Domain Operator".into()
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
        // TODO: add core domain chain spec an extension of system domain chain spec.
        match self.domain_id {
            DomainId::CORE_PAYMENTS => core_payments_chain_spec::load_chain_spec(id),
            DomainId::CORE_EVM => core_evm_chain_spec::load_chain_spec(id),
            domain_id => unreachable!("Unsupported core domain: {domain_id:?}"),
        }
    }

    fn native_runtime_version(_chain_spec: &Box<dyn ChainSpec>) -> &'static RuntimeVersion {
        match CORE_DOMAIN_ID
            .get()
            .expect("Initialized when constructing this struct")
        {
            &DomainId::CORE_PAYMENTS => &core_payments_domain_runtime::VERSION,
            &DomainId::CORE_EVM => &core_evm_runtime::VERSION,
            domain_id => unreachable!("Unsupported core domain: {domain_id:?}"),
        }
    }
}

impl DefaultConfigurationValues for CoreDomainCli {
    fn p2p_listen_port() -> u16 {
        30335
    }

    fn rpc_listen_port() -> u16 {
        9946
    }

    fn prometheus_listen_port() -> u16 {
        9617
    }
}

impl CliConfiguration<Self> for CoreDomainCli {
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
            .base_path()?
            .as_mut()
            .map(|base_path| {
                let path = base_path.path().to_path_buf();
                BasePath::new(path.join(format!("core-domain-{}", u32::from(self.domain_id))))
            })
            .or_else(|| self.base_path.clone().map(Into::into)))
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
        self.run.role(is_dev)
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

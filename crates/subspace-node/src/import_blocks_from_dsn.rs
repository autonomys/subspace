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
use sc_cli::{CliConfiguration, ImportParams, SharedParams};
use sc_client_api::{BlockBackend, HeaderBackend};
use sp_core::traits::SpawnEssentialNamed;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use subspace_networking::libp2p::Multiaddr;
use subspace_service::dsn::import_blocks::import_blocks;

/// The `import-blocks-from-network` command used to import blocks from Subspace Network DSN.
#[derive(Debug, Parser)]
pub struct ImportBlocksFromDsnCmd {
    /// Multiaddrs of bootstrap nodes to connect to on startup, multiple are supported
    #[arg(long)]
    pub bootstrap_node: Vec<Multiaddr>,

    /// The default number of 64KB pages to ever allocate for Wasm execution.
    ///
    /// Don't alter this unless you know what you're doing.
    #[arg(long, value_name = "COUNT")]
    pub default_heap_pages: Option<u32>,

    #[allow(missing_docs)]
    #[clap(flatten)]
    pub shared_params: SharedParams,

    #[allow(missing_docs)]
    #[clap(flatten)]
    pub import_params: ImportParams,
}

impl ImportBlocksFromDsnCmd {
    /// Run the import-blocks command
    pub async fn run<B, C, IQ>(
        &self,
        client: Arc<C>,
        import_queue: IQ,
        spawner: impl SpawnEssentialNamed,
    ) -> sc_cli::Result<()>
    where
        C: HeaderBackend<B> + BlockBackend<B> + Send + Sync + 'static,
        B: BlockT + for<'de> serde::Deserialize<'de>,
        IQ: sc_service::ImportQueue<B> + 'static,
    {
        import_blocks(
            self.bootstrap_node.clone(),
            client,
            import_queue,
            &spawner,
            false,
        )
        .await
        .map_err(Into::into)
    }
}

impl CliConfiguration for ImportBlocksFromDsnCmd {
    fn shared_params(&self) -> &SharedParams {
        &self.shared_params
    }

    fn import_params(&self) -> Option<&ImportParams> {
        Some(&self.import_params)
    }
}

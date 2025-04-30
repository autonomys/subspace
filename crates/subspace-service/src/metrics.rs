//! Node metrics

use futures::StreamExt;
use parity_scale_codec::Encode;
use sc_client_api::{BlockBackend, BlockImportNotification, ImportNotifications};
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use substrate_prometheus_endpoint::{register, Counter, PrometheusError, Registry, U64};

pub struct NodeMetrics<Block: BlockT, Client> {
    client: Arc<Client>,
    block_import: ImportNotifications<Block>,
    blocks: Counter<U64>,
    extrinsics: Counter<U64>,
    extrinsics_size: Counter<U64>,
    _p: std::marker::PhantomData<Block>,
}

impl<Block, Client> NodeMetrics<Block, Client>
where
    Block: BlockT,
    Client: BlockBackend<Block> + 'static,
{
    pub fn new(
        client: Arc<Client>,
        block_import: ImportNotifications<Block>,
        registry: &Registry,
    ) -> Result<Self, PrometheusError> {
        Ok(Self {
            client,
            block_import,
            blocks: register(
                Counter::new("subspace_node_blocks", "Total number of imported blocks")?,
                registry,
            )?,
            extrinsics: register(
                Counter::new(
                    "subspace_node_extrinsics",
                    "Total number of extrinsics in the imported blocks",
                )?,
                registry,
            )?,
            extrinsics_size: register(
                Counter::new(
                    "subspace_node_extrinsics_size",
                    "Total extrinsic bytes in the imported blocks",
                )?,
                registry,
            )?,
            _p: Default::default(),
        })
    }

    pub async fn run(mut self) {
        while let Some(incoming_block) = self.block_import.next().await {
            self.update_block_metrics(incoming_block);
        }
    }

    fn update_block_metrics(&self, incoming_block: BlockImportNotification<Block>) {
        let extrinsics = self
            .client
            .block_body(incoming_block.hash)
            .ok()
            .flatten()
            .unwrap_or_default();
        self.blocks.inc();
        self.extrinsics.inc_by(extrinsics.len() as u64);
        let total_size: usize = extrinsics
            .iter()
            .map(|extrinsic| extrinsic.encoded_size())
            .sum();
        self.extrinsics_size.inc_by(total_size as u64);
    }
}

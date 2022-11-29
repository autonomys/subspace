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
use parity_scale_codec::Encode;
use sc_cli::{CliConfiguration, ImportParams, SharedParams};
use sc_client_api::{BlockBackend, HeaderBackend};
use sc_consensus::{BlockImportError, BlockImportStatus, IncomingBlock, Link};
use sc_service::ImportQueue;
use sc_tracing::tracing::{debug, info, trace};
use sp_consensus::BlockOrigin;
use sp_core::traits::SpawnEssentialNamed;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use std::sync::Arc;
use std::task::Poll;
use subspace_archiving::reconstructor::Reconstructor;
use subspace_core_primitives::{Piece, RECORDED_HISTORY_SEGMENT_SIZE, RECORD_SIZE};
use subspace_networking::libp2p::Multiaddr;
use subspace_networking::utils::multihash;
use subspace_networking::{BootstrappedNetworkingParameters, Config};

type PieceIndex = u64;

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

struct WaitLinkError<B: BlockT> {
    error: BlockImportError,
    hash: B::Hash,
}

struct WaitLink<B: BlockT> {
    imported_blocks: u64,
    error: Option<WaitLinkError<B>>,
}

impl<B: BlockT> WaitLink<B> {
    fn new() -> Self {
        Self {
            imported_blocks: 0,
            error: None,
        }
    }
}

impl<B: BlockT> Link<B> for WaitLink<B> {
    fn blocks_processed(
        &mut self,
        imported: usize,
        _num_expected_blocks: usize,
        results: Vec<(
            Result<BlockImportStatus<NumberFor<B>>, BlockImportError>,
            B::Hash,
        )>,
    ) {
        debug!("Imported {imported} blocks");
        self.imported_blocks += imported as u64;

        for result in results {
            if let (Err(error), hash) = result {
                self.error.replace(WaitLinkError { error, hash });
                break;
            }
        }
    }
}

/// Starts the process of importing blocks.
async fn import_blocks<B, IQ, C>(
    bootstrap_nodes: Vec<Multiaddr>,
    client: Arc<C>,
    mut import_queue: IQ,
    spawner: &impl SpawnEssentialNamed,
    force: bool,
) -> Result<(), sc_service::Error>
where
    C: HeaderBackend<B> + BlockBackend<B> + Send + Sync + 'static,
    B: BlockT + for<'de> serde::Deserialize<'de>,
    IQ: ImportQueue<B> + 'static,
{
    let (node, mut node_runner) = subspace_networking::create(Config {
        networking_parameters_registry: BootstrappedNetworkingParameters::new(bootstrap_nodes)
            .boxed(),
        allow_non_global_addresses_in_dht: true,
        ..Config::with_generated_keypair()
    })
    .await
    .map_err(|error| sc_service::Error::Other(error.to_string()))?;

    spawner.spawn_essential(
        "node-runner",
        Some("subspace-networking"),
        Box::pin(async move {
            node_runner.run().await;
        }),
    );

    debug!("Waiting for connected peers...");
    let _ = node.wait_for_connected_peers().await;
    debug!("Connected to peers.");

    let best_block_number = client.info().best_number;
    let mut link = WaitLink::new();
    let mut imported_blocks = 0;
    let mut reconstructor = Reconstructor::new(RECORD_SIZE, RECORDED_HISTORY_SEGMENT_SIZE)
        .map_err(|error| sc_service::Error::Other(error.to_string()))?;

    let pieces_in_segment = u64::from(RECORDED_HISTORY_SEGMENT_SIZE / RECORD_SIZE * 2);

    // TODO: Check latest known root block on chain and skip downloading of corresponding segments
    // Collection is intentional to make sure downloading starts right away and not lazily
    for segment_index in 0.. {
        let pieces_indexes = (0..pieces_in_segment / 2).map(|piece_position| {
            let piece_index: PieceIndex = segment_index * pieces_in_segment + piece_position;

            piece_index
        });

        let mut pieces = vec![None::<Piece>; pieces_in_segment as usize];
        let mut found_one_piece = false;

        for (piece_index, piece) in pieces_indexes.zip(pieces.iter_mut()) {
            let maybe_piece = node
                .get_value(multihash::create_multihash_by_piece_index(piece_index))
                .await
                .map_err(|error| sc_service::Error::Other(error.to_string()))?;

            trace!(
                ?piece_index,
                success = maybe_piece.is_some(),
                "Piece request completed.",
            );

            if let Some(piece_vec) = maybe_piece {
                found_one_piece = true;

                piece.replace(piece_vec.as_slice().try_into()?);
            }
        }

        if !found_one_piece {
            info!("Found no pieces for segment index {}", segment_index);
            break;
        }

        let reconstructed_contents = reconstructor
            .add_segment(pieces.as_ref())
            .map_err(|error| sc_service::Error::Other(error.to_string()))?;

        for (block_number, block_bytes) in reconstructed_contents.blocks {
            {
                let block_number = block_number.into();
                if block_number <= best_block_number {
                    if block_number == 0u32.into() {
                        let block = client
                            .block(&BlockId::Number(block_number))?
                            .expect("Block before best block number must always be found; qed");

                        if block.encode() != block_bytes {
                            return Err(sc_service::Error::Other(
                                "Wrong genesis block, block import failed".to_string(),
                            ));
                        }
                    }

                    continue;
                }
            }

            let block = B::decode(&mut block_bytes.as_slice())
                .map_err(|error| sc_service::Error::Other(error.to_string()))?;

            let (header, extrinsics) = block.deconstruct();
            let hash = header.hash();

            // import queue handles verification and importing it into the client.
            import_queue.import_blocks(
                BlockOrigin::NetworkInitialSync,
                vec![IncomingBlock::<B> {
                    hash,
                    header: Some(header),
                    body: Some(extrinsics),
                    indexed_body: None,
                    justifications: None,
                    origin: None,
                    allow_missing_state: false,
                    import_existing: force,
                    state: None,
                    skip_execution: false,
                }],
            );

            imported_blocks += 1;

            if imported_blocks % 1000 == 0 {
                info!("Imported block {}", block_number);
            }
        }

        futures::future::poll_fn(|ctx| {
            import_queue.poll_actions(ctx, &mut link);

            Poll::Ready(())
        })
        .await;

        if let Some(WaitLinkError { error, hash }) = &link.error {
            return Err(sc_service::Error::Other(format!(
                "Stopping block import after #{} blocks on {} because of an error: {}",
                link.imported_blocks, hash, error
            )));
        }
    }

    while link.imported_blocks < imported_blocks {
        futures::future::poll_fn(|ctx| {
            import_queue.poll_actions(ctx, &mut link);

            Poll::Ready(())
        })
        .await;

        if let Some(WaitLinkError { error, hash }) = &link.error {
            return Err(sc_service::Error::Other(format!(
                "Stopping block import after #{} blocks on {} because of an error: {}",
                link.imported_blocks, hash, error
            )));
        }
    }

    info!(
        "🎉 Imported {} blocks, best #{}/#{}, check against reliable sources to make sure it is a \
        block on canonical chain",
        imported_blocks,
        client.info().best_number,
        client.info().best_hash
    );

    Ok(())
}

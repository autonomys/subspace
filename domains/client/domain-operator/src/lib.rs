// Copyright 2019-2021 Parity Technologies (UK) Ltd.
// This file is part of Cumulus.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Cumulus.  If not, see <http://www.gnu.org/licenses/>.

//! # Domain Operator
//!
//! ## Domains
//!
//! Domains, the enshrined rollups solution of Subspace, is a configurable execution
//! framework allowing for the simple, secure and low-cost deployment of application
//! specific blockchain called domain.
//!
//! ## Operators
//!
//! In Subspace, the farmers offering the storage resources are responsible for maintaining
//! the consensus layer, operators are a separate class of contributors in the system focusing
//! on the execution layer, they provide the necessary computational resources to maintain the
//! blockchain state by running domains. Some deposits as the stake are required to be an operator.
//!
//! Specifically, operators have the responsibility of producing a [`Bundle`] which contains a
//! number of [`ExecutionReceipt`]s on each slot notified from the consensus chain. The operators
//! are primarily driven by two events from the consensus chain.
//!
//! - On each new slot, operators will attempt to solve a domain-specific bundle election
//!   challenge derived from a global randomness provided by the consensus chain. Upon finding
//!   a solution to the challenge, they will start producing a bundle: they will collect a set
//!   of extrinsics from the transaction pool which are verified to be able to cover the transaction
//!   fee. With these collected extrinsics, the bundle election solution and proper receipts, a
//!   [`Bundle`] can be constructed and then be submitted to the consensus chain. The transactions
//!   included in each bundle are uninterpretable blob from the consensus chain's perspective.
//!
//! - On each imported consensus block, operators will extract all the needed bundles from it
//!   and convert the bundles to a list of extrinsics, construct a custom [`BlockBuilder`] to
//!   build a domain block. The execution trace of all the extrinsics and hooks like
//!   `initialize_block`/`finalize_block` will be recorded during the domain block execution.
//!   Once the domain block is imported successfully, the [`ExecutionReceipt`] of this block
//!   will be generated and stored locally.
//!
//! The receipt of each domain block contains all the intermediate state roots during the block
//! execution, which will be gossiped in the domain subnet (in future). All operators whether
//! running as an authority or a full node will compute each block and generate an execution receipt
//! independently, once the execution receipt received from the network does not match the one
//! produced locally, a [`FraudProof`] will be generated and reported to the consensus chain
//! accordingly.
//!
//! [`BlockBuilder`]: ../domain_block_builder/struct.BlockBuilder.html
//! [`FraudProof`]: ../sp_domains/struct.FraudProof.html

#![feature(array_windows)]
#![feature(const_option)]
#![feature(extract_if)]

mod aux_schema;
mod bundle_processor;
mod bundle_producer_election_solver;
mod domain_block_processor;
pub mod domain_bundle_producer;
pub mod domain_bundle_proposer;
mod domain_worker;
mod fetch_domain_bootstrap_info;
mod fraud_proof;
mod operator;
#[cfg(test)]
mod tests;
mod utils;

pub use self::aux_schema::load_execution_receipt;
pub use self::fetch_domain_bootstrap_info::{fetch_domain_bootstrap_info, BootstrapResult};
pub use self::operator::Operator;
pub use self::utils::{DomainBlockImportNotification, DomainImportNotifications, OperatorSlotInfo};
pub use domain_worker::OpaqueBundleFor;
use futures::channel::mpsc;
use futures::Stream;
use sc_client_api::{AuxStore, BlockImportNotification};
use sc_consensus::BoxBlockImport;
use sc_transaction_pool_api::OffchainTransactionPoolFactory;
use sc_utils::mpsc::TracingUnboundedSender;
use sp_blockchain::HeaderBackend;
use sp_consensus::SyncOracle;
use sp_consensus_slots::Slot;
use sp_domain_digests::AsPredigest;
use sp_domains::{Bundle, DomainId, ExecutionReceipt, OperatorId};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use sp_runtime::DigestItem;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_core_primitives::PotOutput;
use subspace_runtime_primitives::Balance;

pub type ExecutionReceiptFor<Block, CBlock> = ExecutionReceipt<
    NumberFor<CBlock>,
    <CBlock as BlockT>::Hash,
    NumberFor<Block>,
    <Block as BlockT>::Hash,
    Balance,
>;

type BundleSender<Block, CBlock> = TracingUnboundedSender<
    Bundle<
        <Block as BlockT>::Extrinsic,
        NumberFor<CBlock>,
        <CBlock as BlockT>::Hash,
        <Block as BlockT>::Header,
        Balance,
    >,
>;

/// Notification streams from the consensus chain driving the executor.
pub struct OperatorStreams<CBlock, IBNS, CIBNS, NSNS, ASS> {
    /// Pause the consensus block import when the consensus chain client
    /// runs much faster than the domain client.
    pub consensus_block_import_throttling_buffer_size: u32,
    /// Notification about to be imported.
    ///
    /// Fired before the completion of entire block import pipeline.
    pub block_importing_notification_stream: IBNS,
    /// Consensus block import notification from the client.
    ///
    /// Fired after the completion of entire block import pipeline.
    pub imported_block_notification_stream: CIBNS,
    /// New slot arrives.
    pub new_slot_notification_stream: NSNS,
    /// The acknowledgement sender only used in test to ensure all of
    /// the operator's previous tasks are finished
    pub acknowledgement_sender_stream: ASS,
    pub _phantom: PhantomData<CBlock>,
}

type NewSlotNotification = (Slot, PotOutput);

pub struct OperatorParams<
    Block,
    CBlock,
    Client,
    CClient,
    TransactionPool,
    Backend,
    E,
    IBNS,
    CIBNS,
    NSNS,
    ASS,
> where
    Block: BlockT,
    CBlock: BlockT,
    IBNS: Stream<Item = (NumberFor<CBlock>, mpsc::Sender<()>)> + Send + 'static,
    CIBNS: Stream<Item = BlockImportNotification<CBlock>> + Send + 'static,
    NSNS: Stream<Item = NewSlotNotification> + Send + 'static,
    ASS: Stream<Item = mpsc::Sender<()>> + Send + 'static,
{
    pub domain_id: DomainId,
    pub domain_created_at: NumberFor<CBlock>,
    pub consensus_client: Arc<CClient>,
    pub consensus_offchain_tx_pool_factory: OffchainTransactionPoolFactory<CBlock>,
    pub consensus_network_sync_oracle: Arc<dyn SyncOracle + Send + Sync>,
    pub client: Arc<Client>,
    pub transaction_pool: Arc<TransactionPool>,
    pub backend: Arc<Backend>,
    pub code_executor: Arc<E>,
    pub maybe_operator_id: Option<OperatorId>,
    pub keystore: KeystorePtr,
    pub bundle_sender: Arc<BundleSender<Block, CBlock>>,
    pub operator_streams: OperatorStreams<CBlock, IBNS, CIBNS, NSNS, ASS>,
    pub domain_confirmation_depth: NumberFor<Block>,
    pub block_import: Arc<BoxBlockImport<Block>>,
    pub skip_empty_bundle_production: bool,
    pub skip_out_of_order_slot: bool,
}

pub(crate) fn load_execution_receipt_by_domain_hash<Block, CBlock, Client>(
    domain_client: &Client,
    domain_hash: Block::Hash,
    domain_number: NumberFor<Block>,
) -> Result<ExecutionReceiptFor<Block, CBlock>, sp_blockchain::Error>
where
    Block: BlockT,
    CBlock: BlockT,
    Client: AuxStore + HeaderBackend<Block>,
{
    let domain_header = domain_client.header(domain_hash)?.ok_or_else(|| {
        sp_blockchain::Error::Backend(format!(
            "Header for domain block {domain_hash}#{domain_number} not found"
        ))
    })?;

    let consensus_block_hash = domain_header
        .digest()
        .convert_first(DigestItem::as_consensus_block_info)
        .ok_or_else(|| {
            sp_blockchain::Error::Application(format!(
                "Domain block header {domain_hash}#{domain_number} must have consensus block info predigest"
            ).into())
        })?;

    // Get receipt by consensus block hash
    crate::aux_schema::load_execution_receipt::<_, Block, CBlock>(
        domain_client,
        consensus_block_hash,
    )?
    .ok_or_else(|| {
        sp_blockchain::Error::Backend(format!(
            "Receipt for consensus block {consensus_block_hash} and domain block \
                {domain_hash}#{domain_number} not found"
        ))
    })
}

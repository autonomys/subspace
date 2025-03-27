use crate::aux_schema::{
    cleanup_chain_channel_storages, get_channel_state, get_xdm_processed_block_number,
    set_channel_state, set_xdm_message_processed_at, BlockId,
};
use crate::gossip_worker::{ChannelUpdate, MessageData};
use crate::{ChainMsg, ChannelDetail};
use domain_block_preprocessor::stateless_runtime::StatelessRuntime;
use fp_account::AccountId20;
use futures::{Stream, StreamExt};
use sc_client_api::AuxStore;
use sc_executor::RuntimeVersionOf;
use sc_network::NetworkPeers;
use sc_transaction_pool_api::error::{Error as PoolError, IntoPoolError};
use sc_transaction_pool_api::{TransactionPool, TransactionSource};
use sp_api::{ApiError, ApiExt, ProvideRuntimeApi, StorageProof};
use sp_blockchain::HeaderBackend;
use sp_consensus::SyncOracle;
use sp_core::crypto::AccountId32;
use sp_core::storage::StorageKey;
use sp_core::traits::CodeExecutor;
use sp_core::{Hasher, H256};
use sp_domains::proof_provider_and_verifier::{StorageProofVerifier, VerificationError};
use sp_domains::{DomainId, DomainsApi, RuntimeType};
use sp_messenger::messages::{ChainId, Channel, ChannelId};
use sp_messenger::{ChannelNonce, MessengerApi, RelayerApi, XdmId};
use sp_runtime::codec::Decode;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, HashingFor, Header, NumberFor};
use sp_runtime::{SaturatedConversion, Saturating};
use std::collections::BTreeMap;
use std::sync::Arc;
use subspace_runtime_primitives::{Balance, BlockNumber};
use thiserror::Error;

pub(crate) const LOG_TARGET: &str = "domain_message_listener";
const TX_POOL_PREFIX: &[u8] = b"xdm_tx_pool_listener";
pub const RELAYER_PREFIX: &[u8] = b"xdm_relayer";

/// Number of blocks an already submitted XDM is not accepted since last submission.
const XDM_ACCEPT_BLOCK_LIMIT: u32 = 15;

type BlockOf<T> = <T as TransactionPool>::Block;
type HeaderOf<T> = <<T as TransactionPool>::Block as BlockT>::Header;
type ExtrinsicOf<T> = <<T as TransactionPool>::Block as BlockT>::Extrinsic;

#[derive(Debug, Error)]
pub enum Error {
    /// Blockchain related error.
    #[error("Blockchain error: {0}")]
    Blockchain(Box<sp_blockchain::Error>),
    /// Api related error.
    #[error("Api error: {0}")]
    Api(sp_api::ApiError),
    /// Missing block hash
    #[error("Missing block hash")]
    MissingBlockHash,
    /// Missing block header
    #[error("Missing block header")]
    MissingBlockHeader,
    /// Missing domain runtime code
    #[error("Missing domain runtime code")]
    MissingDomainRuntimeCode,
    /// Missing domain receipt hash
    #[error("Missing domain receipt hash")]
    MissingDomainReceiptHash,
    /// Bad domain receipt hash
    #[error("Bad domain receipt hash")]
    BadDomainReceiptHash,
    /// Missing domain receipt
    #[error("Missing domain receipt")]
    MissingDomainReceipt,
    /// Proof verification error
    #[error("Proof error: {0}")]
    Proof(VerificationError),
}

impl From<sp_api::ApiError> for Error {
    fn from(value: ApiError) -> Self {
        Error::Api(value)
    }
}

impl From<sp_blockchain::Error> for Error {
    fn from(value: sp_blockchain::Error) -> Self {
        Error::Blockchain(Box::new(value))
    }
}

impl From<VerificationError> for Error {
    fn from(value: VerificationError) -> Self {
        Error::Proof(value)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_cross_chain_message_listener<
    Client,
    TxPool,
    TxnListener,
    CClient,
    CBlock,
    Executor,
    SO,
>(
    chain_id: ChainId,
    consensus_client: Arc<CClient>,
    client: Arc<Client>,
    tx_pool: Arc<TxPool>,
    network: Arc<dyn NetworkPeers + Send + Sync>,
    mut listener: TxnListener,
    domain_executor: Arc<Executor>,
    sync_oracle: SO,
) where
    TxPool: TransactionPool + 'static,
    Client: ProvideRuntimeApi<BlockOf<TxPool>> + HeaderBackend<BlockOf<TxPool>> + AuxStore,
    CBlock: BlockT,
    Client::Api: MessengerApi<BlockOf<TxPool>, NumberFor<CBlock>, CBlock::Hash>,
    CClient: ProvideRuntimeApi<CBlock> + HeaderBackend<CBlock> + AuxStore,
    CClient::Api: DomainsApi<CBlock, HeaderOf<TxPool>>
        + RelayerApi<CBlock, NumberFor<CBlock>, NumberFor<CBlock>, CBlock::Hash>,
    TxnListener: Stream<Item = ChainMsg> + Unpin,
    Executor: CodeExecutor + RuntimeVersionOf,
    SO: SyncOracle + Send,
{
    tracing::info!(
        target: LOG_TARGET,
        "Starting transaction listener for Chain: {:?}",
        chain_id
    );

    let mut domain_storage_key_cache = BTreeMap::<(H256, ChainId, ChannelId), StorageKey>::new();

    while let Some(msg) = listener.next().await {
        // If the client is in major sync, wait until sync is complete
        if sync_oracle.is_major_syncing() {
            continue;
        }

        tracing::debug!(
            target: LOG_TARGET,
            "Message received for Chain: {:?}",
            chain_id,
        );

        match msg.data {
            MessageData::Xdm(encoded_data) => {
                let ext = match ExtrinsicOf::<TxPool>::decode(&mut encoded_data.as_ref()) {
                    Ok(ext) => ext,
                    Err(err) => {
                        tracing::error!(
                            target: LOG_TARGET,
                            "Failed to decode message: {:?} with error: {:?}",
                            encoded_data,
                            err
                        );
                        if let Some(peer_id) = msg.maybe_peer {
                            network.report_peer(
                                peer_id,
                                crate::gossip_worker::rep::GOSSIP_NOT_DECODABLE,
                            );
                        }
                        continue;
                    }
                };

                if let Ok(valid) =
                    handle_xdm_message::<_, _, CBlock>(&client, &tx_pool, chain_id, ext).await
                    && !valid
                {
                    if let Some(peer_id) = msg.maybe_peer {
                        network.report_peer(peer_id, crate::gossip_worker::rep::NOT_XDM);
                    }
                    continue;
                }
            }
            MessageData::ChannelUpdate(channel_update) => {
                handle_channel_update::<_, _, _, BlockOf<TxPool>>(
                    chain_id,
                    channel_update,
                    &consensus_client,
                    domain_executor.clone(),
                    &mut domain_storage_key_cache,
                )
            }
        }
    }
}

fn handle_channel_update<CClient, CBlock, Executor, Block>(
    chain_id: ChainId,
    channel_update: ChannelUpdate,
    consensus_client: &Arc<CClient>,
    executor: Arc<Executor>,
    domain_storage_key_cache: &mut BTreeMap<(H256, ChainId, ChannelId), StorageKey>,
) where
    CBlock: BlockT,
    Block: BlockT,
    CClient: ProvideRuntimeApi<CBlock> + HeaderBackend<CBlock> + AuxStore,
    CClient::Api: DomainsApi<CBlock, Block::Header>
        + RelayerApi<CBlock, NumberFor<CBlock>, NumberFor<CBlock>, CBlock::Hash>,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    let ChannelUpdate {
        src_chain_id,
        channel_id,
        block_number,
        storage_proof,
    } = channel_update;

    match src_chain_id {
        ChainId::Consensus => {
            if let Err(err) = handle_consensus_channel_update(
                chain_id,
                channel_id,
                consensus_client,
                block_number,
                storage_proof,
            ) {
                tracing::debug!(
                    target: LOG_TARGET,
                    "Failed to update channel update from {:?} to {:?}: {:?}",
                    ChainId::Consensus,
                    chain_id,
                    err
                );
            } else {
                tracing::debug!(
                    target: LOG_TARGET,
                    "Updated channel state from {:?} to {:?}: {:?}",
                    ChainId::Consensus,
                    chain_id,
                    channel_id
                );
            }
        }
        ChainId::Domain(domain_id) => {
            if let Err(err) = handle_domain_channel_update::<_, _, _, Block>(
                domain_id,
                chain_id,
                channel_id,
                consensus_client,
                block_number,
                storage_proof,
                executor,
                domain_storage_key_cache,
            ) {
                tracing::debug!(
                    target: LOG_TARGET,
                    "Failed to update channel update from {:?} to {:?}: {:?}",
                    ChainId::Domain(domain_id),
                    chain_id,
                    err
                );
            } else {
                tracing::debug!(
                    target: LOG_TARGET,
                    "Updated channel state from {:?} to {:?}: {:?}",
                    ChainId::Domain(domain_id),
                    chain_id,
                    channel_id
                );
            }
        }
    };
}

fn handle_consensus_channel_update<CClient, CBlock>(
    self_chain_id: ChainId,
    channel_id: ChannelId,
    consensus_client: &Arc<CClient>,
    consensus_block_number: BlockNumber,
    proof: StorageProof,
) -> Result<(), Error>
where
    CBlock: BlockT,
    CClient: ProvideRuntimeApi<CBlock> + HeaderBackend<CBlock> + AuxStore,
    CClient::Api: RelayerApi<CBlock, NumberFor<CBlock>, NumberFor<CBlock>, CBlock::Hash>,
{
    // check if the consensus block number is canonical
    let consensus_block_hash = consensus_client
        .hash(consensus_block_number.into())?
        .ok_or(Error::MissingBlockHash)?;

    let maybe_existing_channel_detail = get_channel_state(
        &**consensus_client,
        ChainId::Consensus,
        self_chain_id,
        channel_id,
    )?;

    let api = consensus_client.runtime_api();
    let best_hash = consensus_client.info().best_hash;
    let header = consensus_client.expect_header(consensus_block_hash)?;

    // if there is an existing channel detail,
    // return if the channel update is from canonical chain and block number is latest
    // else store the update.
    if let Some(existing_channel_update) = maybe_existing_channel_detail {
        let maybe_block_hash =
            consensus_client.hash(existing_channel_update.block_number.into())?;
        if let Some(block_hash) = maybe_block_hash {
            if block_hash.as_ref() == existing_channel_update.block_hash.as_ref()
                && header.state_root().as_ref() == existing_channel_update.state_root.as_ref()
                && existing_channel_update.block_number >= consensus_block_number
            {
                return Ok(());
            }
        }
    }

    let storage_key = StorageKey(api.channel_storage_key(best_hash, self_chain_id, channel_id)?);
    let channel = StorageProofVerifier::<HashingFor<CBlock>>::get_decoded_value::<
        Channel<Balance, AccountId32>,
    >(header.state_root(), proof, storage_key)?;

    let channel_detail = ChannelDetail {
        block_number: consensus_block_number,
        block_hash: H256::from_slice(consensus_block_hash.as_ref()),
        state_root: H256::from_slice(header.state_root().as_ref()),
        channel_id,
        state: channel.state,
        next_inbox_nonce: channel.next_inbox_nonce,
        next_outbox_nonce: channel.next_outbox_nonce,
        latest_response_received_message_nonce: channel.latest_response_received_message_nonce,
    };

    set_channel_state(
        &**consensus_client,
        ChainId::Consensus,
        self_chain_id,
        channel_detail,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_domain_channel_update<CClient, CBlock, Executor, Block>(
    src_domain_id: DomainId,
    self_chain_id: ChainId,
    channel_id: ChannelId,
    consensus_client: &Arc<CClient>,
    domain_block_number: BlockNumber,
    proof: StorageProof,
    executor: Arc<Executor>,
    storage_key_cache: &mut BTreeMap<(H256, ChainId, ChannelId), StorageKey>,
) -> Result<(), Error>
where
    CBlock: BlockT,
    Block: BlockT,
    CClient: ProvideRuntimeApi<CBlock> + HeaderBackend<CBlock> + AuxStore,
    CClient::Api: DomainsApi<CBlock, Block::Header>,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    let runtime_api = consensus_client.runtime_api();
    let consensus_best_hash = consensus_client.info().best_hash;
    let consensus_block_header = consensus_client
        .header(consensus_best_hash)?
        .ok_or(Error::MissingBlockHeader)?;

    let domain_runtime_type = runtime_api
        .domain_instance_data(*consensus_block_header.parent_hash(), src_domain_id)?
        .ok_or(Error::MissingDomainRuntimeCode)?
        .0
        .runtime_type;

    let is_valid_domain_block_number =
        |block_number: BlockNumber| -> Result<(Block::Hash, Block::Hash), Error> {
            let runtime_api = consensus_client.runtime_api();
            let receipt_hash = runtime_api
                .receipt_hash(consensus_best_hash, src_domain_id, block_number.into())?
                .ok_or(Error::MissingDomainReceiptHash)?;

            // check if the receipt is challenged by fraud proof
            if runtime_api.is_bad_er_pending_to_prune(
                consensus_best_hash,
                src_domain_id,
                receipt_hash,
            )? {
                return Err(Error::BadDomainReceiptHash);
            }

            let receipt = runtime_api
                .execution_receipt(consensus_best_hash, receipt_hash)?
                .ok_or(Error::MissingDomainReceipt)?;

            Ok((receipt.domain_block_hash, receipt.final_state_root))
        };

    // check if the domain block number is valid
    let (domain_block_hash, domain_state_root) = is_valid_domain_block_number(domain_block_number)?;

    // if there is an existing channel detail,
    // return if the channel update is from canonical domain and block number is latest
    // else store the update.
    let maybe_existing_channel_detail = get_channel_state(
        &**consensus_client,
        ChainId::Domain(src_domain_id),
        self_chain_id,
        channel_id,
    )?;

    if let Some(existing_channel_update) = maybe_existing_channel_detail {
        // if the existing update domain block number
        // is valid, and
        // more the new block number, then don't update
        if let Ok((existing_block_hash, _)) =
            is_valid_domain_block_number(existing_channel_update.block_number)
        {
            if existing_block_hash.as_ref() == existing_channel_update.block_hash.as_ref()
                && domain_state_root.as_ref() == existing_channel_update.state_root.as_ref()
                && existing_channel_update.block_number >= domain_block_number
            {
                return Ok(());
            }
        }
    }

    let domain_runtime = runtime_api
        .domain_runtime_code(*consensus_block_header.parent_hash(), src_domain_id)?
        .ok_or(Error::MissingDomainRuntimeCode)?;

    let runtime_hash = BlakeTwo256::hash(&domain_runtime);
    let storage_key = match storage_key_cache.get(&(runtime_hash, self_chain_id, channel_id)) {
        None => {
            let domain_stateless_runtime =
                StatelessRuntime::<CBlock, Block, _>::new(executor.clone(), domain_runtime.into());
            let storage_key = StorageKey(
                domain_stateless_runtime.channel_storage_key(self_chain_id, channel_id)?,
            );
            storage_key_cache.insert(
                (runtime_hash, self_chain_id, channel_id),
                storage_key.clone(),
            );
            storage_key
        }
        Some(key) => key.clone(),
    };

    let channel_detail = match domain_runtime_type {
        RuntimeType::Evm => {
            let channel = StorageProofVerifier::<HashingFor<Block>>::get_decoded_value::<
                Channel<Balance, AccountId20>,
            >(&domain_state_root, proof, storage_key)?;
            ChannelDetail {
                block_number: domain_block_number,
                block_hash: H256::from_slice(domain_block_hash.as_ref()),
                state_root: H256::from_slice(domain_state_root.as_ref()),
                channel_id,
                state: channel.state,
                next_inbox_nonce: channel.next_inbox_nonce,
                next_outbox_nonce: channel.next_outbox_nonce,
                latest_response_received_message_nonce: channel
                    .latest_response_received_message_nonce,
            }
        }
        RuntimeType::AutoId => {
            let channel = StorageProofVerifier::<HashingFor<Block>>::get_decoded_value::<
                Channel<Balance, AccountId32>,
            >(&domain_state_root, proof, storage_key)?;
            ChannelDetail {
                block_number: domain_block_number,
                block_hash: H256::from_slice(domain_block_hash.as_ref()),
                state_root: H256::from_slice(domain_state_root.as_ref()),
                channel_id,
                state: channel.state,
                next_inbox_nonce: channel.next_inbox_nonce,
                next_outbox_nonce: channel.next_outbox_nonce,
                latest_response_received_message_nonce: channel
                    .latest_response_received_message_nonce,
            }
        }
    };

    set_channel_state(
        &**consensus_client,
        ChainId::Domain(src_domain_id),
        self_chain_id,
        channel_detail,
    )?;
    Ok(())
}

pub fn can_allow_xdm_submission<Client, Block>(
    client: &Arc<Client>,
    xdm_id: XdmId,
    maybe_submitted_block_id: Option<BlockId<Block>>,
    current_block_id: BlockId<Block>,
    maybe_channel_nonce: Option<ChannelNonce>,
) -> bool
where
    Client: HeaderBackend<Block>,
    Block: BlockT,
{
    if let Some(channel_nonce) = maybe_channel_nonce {
        let maybe_nonces = match (
            xdm_id,
            channel_nonce.relay_msg_nonce,
            channel_nonce.relay_response_msg_nonce,
        ) {
            (XdmId::RelayMessage((_, _, nonce)), Some(channel_nonce), _) => {
                Some((nonce, channel_nonce))
            }
            (XdmId::RelayResponseMessage((_, _, nonce)), _, Some(channel_nonce)) => {
                Some((nonce, channel_nonce))
            }
            _ => None,
        };

        if let Some((xdm_nonce, channel_nonce)) = maybe_nonces
            && (xdm_nonce <= channel_nonce)
        {
            tracing::debug!(
                target: LOG_TARGET,
                "Stale XDM submitted: XDM Nonce: {:?}, Channel Nonce: {:?}",
                xdm_nonce,
                channel_nonce
            );
            return false;
        }
    }

    match maybe_submitted_block_id {
        None => true,
        Some(submitted_block_id) => {
            match client.hash(submitted_block_id.number).ok().flatten() {
                // there is no block at this number, allow xdm submission
                None => return true,
                Some(hash) => {
                    if hash != submitted_block_id.hash {
                        // client re-org'ed, allow xdm submission
                        return true;
                    }
                }
            }

            let latest_block_number = current_block_id.number;
            let block_limit: NumberFor<Block> = XDM_ACCEPT_BLOCK_LIMIT.saturated_into();
            submitted_block_id.number < latest_block_number.saturating_sub(block_limit)
        }
    }
}

async fn handle_xdm_message<TxPool, Client, CBlock>(
    client: &Arc<Client>,
    tx_pool: &Arc<TxPool>,
    chain_id: ChainId,
    ext: ExtrinsicOf<TxPool>,
) -> Result<bool, Error>
where
    TxPool: TransactionPool + 'static,
    CBlock: BlockT,
    Client: ProvideRuntimeApi<BlockOf<TxPool>> + HeaderBackend<BlockOf<TxPool>> + AuxStore,
    Client::Api: MessengerApi<BlockOf<TxPool>, NumberFor<CBlock>, CBlock::Hash>,
{
    let block_id: BlockId<BlockOf<TxPool>> = client.info().into();
    let runtime_api = client.runtime_api();
    let api_version = runtime_api
        .api_version::<dyn MessengerApi<BlockOf<TxPool>, NumberFor<CBlock>, CBlock::Hash>>(
            block_id.hash,
        )?
        .unwrap_or(1);

    let api_available = api_version >= 2;
    if api_available {
        let xdm_id = match runtime_api.xdm_id(block_id.hash, &ext)? {
            // not a valid xdm, so return as invalid
            None => return Ok(false),
            Some(xdm_id) => xdm_id,
        };

        let (src_chain_id, channel_id) = xdm_id.get_chain_id_and_channel_id();
        let maybe_channel_nonce =
            runtime_api.channel_nonce(block_id.hash, src_chain_id, channel_id)?;

        let maybe_submitted_xdm_block = get_xdm_processed_block_number::<_, BlockOf<TxPool>>(
            &**client,
            TX_POOL_PREFIX,
            xdm_id,
        )?;
        if !can_allow_xdm_submission(
            client,
            xdm_id,
            maybe_submitted_xdm_block,
            block_id.clone(),
            maybe_channel_nonce,
        ) {
            tracing::debug!(
                target: LOG_TARGET,
                "Skipping XDM[{:?}] submission. At: {:?}",
                xdm_id,
                block_id
            );
            return Ok(true);
        }

        tracing::debug!(
            target: LOG_TARGET,
            "Submitting XDM[{:?}] to tx pool for chain {:?} at block: {:?}",
            xdm_id,
            chain_id,
            block_id
        );

        let tx_pool_res = tx_pool
            .submit_one(block_id.hash, TransactionSource::External, ext)
            .await;

        let block_id: BlockId<BlockOf<TxPool>> = client.info().into();
        if let Err(err) = tx_pool_res {
            match err.into_pool_error() {
                Ok(err) => match err {
                    PoolError::TooLowPriority { .. }
                    | PoolError::AlreadyImported(..)
                    | PoolError::TemporarilyBanned => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            "XDM[{:?}] to tx pool for Chain {:?} at block: {:?}: Already included",
                            xdm_id,
                            chain_id,
                            block_id
                        );
                        set_xdm_message_processed_at(&**client, TX_POOL_PREFIX, xdm_id, block_id)?;
                    }
                    _ => {
                        tracing::error!(
                            target: LOG_TARGET,
                            "Failed to submit XDM[{:?}] to tx pool for Chain {:?} with error: {:?} at block: {:?}",
                            xdm_id,
                            chain_id,
                            err,
                            block_id
                        );
                    }
                },
                Err(err) => {
                    tracing::error!(
                        target: LOG_TARGET,
                        "Failed to submit XDM[{:?}] to tx pool for Chain {:?} with error: {:?} at block: {:?}",
                        xdm_id,
                        chain_id,
                        err,
                        block_id
                    );
                }
            }
        } else {
            tracing::debug!(
                target: LOG_TARGET,
                "Submitted XDM[{:?}] to tx pool for chain {:?} at {:?}",
                xdm_id,
                chain_id,
                block_id
            );

            set_xdm_message_processed_at(&**client, TX_POOL_PREFIX, xdm_id, block_id)?;
        }

        if let Some(channel_nonce) = maybe_channel_nonce {
            cleanup_chain_channel_storages(
                &**client,
                TX_POOL_PREFIX,
                src_chain_id,
                channel_id,
                channel_nonce,
            )?;
        }

        Ok(true)
    } else {
        let tx_pool_res = tx_pool
            .submit_one(block_id.hash, TransactionSource::External, ext)
            .await;

        let block_id: BlockId<BlockOf<TxPool>> = client.info().into();
        if let Err(err) = tx_pool_res {
            tracing::error!(
                target: LOG_TARGET,
                "Failed to submit XDM to tx pool for Chain {:?} with error: {:?} at block: {:?}",
                chain_id,
                err,
                block_id
            );
        } else {
            tracing::debug!(
                target: LOG_TARGET,
                "Submitted XDM to tx pool for chain {:?} at {:?}",
                chain_id,
                block_id
            );
        }

        Ok(true)
    }
}

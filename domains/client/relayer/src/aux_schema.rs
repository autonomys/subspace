//! Schema for processed channel data

use crate::CHANNEL_PROCESSED_STATE_CACHE_LIMIT;
use parity_scale_codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, HeaderBackend, Result as ClientResult};
use sp_messenger::messages::{ChainId, ChannelId, Nonce};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_runtime::{SaturatedConversion, Saturating};
use std::sync::Arc;

const CHANNEL_PROCESSED_STATE: &[u8] = b"channel_processed_state";
const OUTBOX_MESSAGES_PREFIX: &[u8] = b"outbox_messages";
const INBOX_RESPONSE_MESSAGES_PREFIX: &[u8] = b"inbox_responses_messages";

fn channel_processed_state_key(
    prefix: &[u8],
    src_chain_id: ChainId,
    dst_chain_id: ChainId,
    channel_id: ChannelId,
) -> Vec<u8> {
    (
        CHANNEL_PROCESSED_STATE,
        prefix,
        src_chain_id,
        dst_chain_id,
        channel_id,
    )
        .encode()
}

fn load_decode<Backend: AuxStore, T: Decode>(
    backend: &Backend,
    key: &[u8],
) -> ClientResult<Option<T>> {
    match backend.get_aux(key)? {
        None => Ok(None),
        Some(t) => T::decode(&mut &t[..])
            .map_err(|e| {
                ClientError::Backend(format!("Relayer DB is corrupted. Decode error: {e}"))
            })
            .map(Some),
    }
}

/// Channel processed state for given dst_chain and channel ID.
#[derive(Debug, Encode, Decode, Clone)]
pub struct ChannelProcessedState<Block: BlockT> {
    // Block number of chain at which the channel state is updated
    pub block_number: NumberFor<Block>,
    /// Block hash of the chain at which the channel state is updated.
    pub block_hash: Block::Hash,
    /// Channel identifier.
    pub channel_id: ChannelId,
    /// Last processed channel nonce.
    pub nonce: Option<Nonce>,
}

/// Load the channel outbox processed state
fn get_channel_outbox_processed_state<Backend, Block: BlockT>(
    backend: &Backend,
    src_chain_id: ChainId,
    dst_chain_id: ChainId,
    channel_id: ChannelId,
) -> ClientResult<Option<ChannelProcessedState<Block>>>
where
    Backend: AuxStore,
{
    load_decode::<_, ChannelProcessedState<Block>>(
        backend,
        channel_processed_state_key(
            OUTBOX_MESSAGES_PREFIX,
            src_chain_id,
            dst_chain_id,
            channel_id,
        )
        .as_slice(),
    )
}

/// Load the channel inbox response processed state
fn get_channel_inbox_message_response_processed_state<Backend, Block: BlockT>(
    backend: &Backend,
    src_chain_id: ChainId,
    dst_chain_id: ChainId,
    channel_id: ChannelId,
) -> ClientResult<Option<ChannelProcessedState<Block>>>
where
    Backend: AuxStore,
{
    load_decode::<_, ChannelProcessedState<Block>>(
        backend,
        channel_processed_state_key(
            INBOX_RESPONSE_MESSAGES_PREFIX,
            src_chain_id,
            dst_chain_id,
            channel_id,
        )
        .as_slice(),
    )
}

/// Set the channel outbox processed state
pub(crate) fn set_channel_outbox_processed_state<Backend, Block: BlockT>(
    backend: &Backend,
    src_chain_id: ChainId,
    dst_chain_id: ChainId,
    channel_state: ChannelProcessedState<Block>,
) -> ClientResult<()>
where
    Backend: AuxStore,
{
    backend.insert_aux(
        &[(
            channel_processed_state_key(
                OUTBOX_MESSAGES_PREFIX,
                src_chain_id,
                dst_chain_id,
                channel_state.channel_id,
            )
            .as_slice(),
            channel_state.encode().as_slice(),
        )],
        vec![],
    )
}

/// Set the channel inbox processed state
pub(crate) fn set_channel_inbox_response_processed_state<Backend, Block: BlockT>(
    backend: &Backend,
    src_chain_id: ChainId,
    dst_chain_id: ChainId,
    channel_state: ChannelProcessedState<Block>,
) -> ClientResult<()>
where
    Backend: AuxStore,
{
    backend.insert_aux(
        &[(
            channel_processed_state_key(
                INBOX_RESPONSE_MESSAGES_PREFIX,
                src_chain_id,
                dst_chain_id,
                channel_state.channel_id,
            )
            .as_slice(),
            channel_state.encode().as_slice(),
        )],
        vec![],
    )
}

/// Last processed nonce data.
#[derive(Debug, Clone)]
pub(crate) struct LastProcessedNonces {
    pub outbox_nonce: Option<Nonce>,
    pub inbox_response_nonce: Option<Nonce>,
}

/// Returns non expired last processed nonces.
pub(crate) fn get_last_processed_nonces<Backend, Client, Block>(
    backend: &Backend,
    client: &Arc<Client>,
    latest_hash: Block::Hash,
    src_chain_id: ChainId,
    dst_chain_id: ChainId,
    channel_id: ChannelId,
) -> ClientResult<LastProcessedNonces>
where
    Backend: AuxStore,
    Block: BlockT,
    Client: HeaderBackend<Block>,
{
    let last_processed_outbox_nonce = get_channel_outbox_processed_state::<_, Block>(
        backend,
        src_chain_id,
        dst_chain_id,
        channel_id,
    )?
    .and_then(|state| {
        is_last_processed_nonce_valid(
            client,
            latest_hash,
            state.block_number,
            state.block_hash,
            state.nonce,
        )
        .ok()
        .flatten()
    });

    let last_processed_inbox_response_nonce = get_channel_inbox_message_response_processed_state::<
        _,
        Block,
    >(
        backend, src_chain_id, dst_chain_id, channel_id
    )?
    .and_then(|state| {
        is_last_processed_nonce_valid(
            client,
            latest_hash,
            state.block_number,
            state.block_hash,
            state.nonce,
        )
        .ok()
        .flatten()
    });

    Ok(LastProcessedNonces {
        outbox_nonce: last_processed_outbox_nonce,
        inbox_response_nonce: last_processed_inbox_response_nonce,
    })
}

fn is_last_processed_nonce_valid<Client, Block>(
    client: &Arc<Client>,
    latest_hash: Block::Hash,
    processed_block_number: NumberFor<Block>,
    processed_block_hash: Block::Hash,
    last_process_nonce: Option<Nonce>,
) -> ClientResult<Option<Nonce>>
where
    Block: BlockT,
    Client: HeaderBackend<Block>,
{
    // short circuit if there is no last processed nonce
    if last_process_nonce.is_none() {
        return Ok(None);
    }

    // there is no block at this number, could be due to re-org
    let Some(block_hash) = client.hash(processed_block_number)? else {
        return Ok(None);
    };

    // hash mismatch could be due to re-org
    if block_hash != processed_block_hash {
        return Ok(None);
    }

    let Some(latest_number) = client.number(latest_hash)? else {
        return Ok(None);
    };

    // if the cache limit is reached, return none
    if latest_number.saturating_sub(processed_block_number)
        > CHANNEL_PROCESSED_STATE_CACHE_LIMIT.saturated_into()
    {
        Ok(None)
    } else {
        Ok(last_process_nonce)
    }
}

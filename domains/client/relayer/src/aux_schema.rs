//! Schema for processed channel data

use parity_scale_codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, Result as ClientResult};
use sp_core::H256;
use sp_messenger::messages::{ChainId, ChannelId, Nonce};
use subspace_runtime_primitives::BlockNumber;

const CHANNEL_PROCESSED_STATE: &[u8] = b"channel_processed_state";

fn channel_processed_state_key(dst_chain_id: ChainId, channel_id: ChannelId) -> Vec<u8> {
    (CHANNEL_PROCESSED_STATE, dst_chain_id, channel_id).encode()
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
pub struct ChannelProcessedState {
    // Block number of chain at which the channel state is updated
    pub block_number: BlockNumber,
    /// Block hash of the chain at which the channel state is updated.
    pub block_hash: H256,
    /// Channel identifier.
    pub channel_id: ChannelId,
    /// Last processed channel outbox nonce.
    pub last_outbox_nonce: Nonce,
    /// Last processed channel inbox message response nonce.
    pub last_inbox_message_response_nonce: Nonce,
}

/// Load the channel processed state
pub fn get_channel_processed_state<Backend>(
    backend: &Backend,
    dst_chain_id: ChainId,
    channel_id: ChannelId,
) -> ClientResult<Option<ChannelProcessedState>>
where
    Backend: AuxStore,
{
    load_decode::<_, ChannelProcessedState>(
        backend,
        channel_processed_state_key(dst_chain_id, channel_id).as_slice(),
    )
}

/// Set the channel processed state
pub fn set_channel_state<Backend>(
    backend: &Backend,
    dst_chain_id: ChainId,
    channel_state: ChannelProcessedState,
) -> ClientResult<()>
where
    Backend: AuxStore,
{
    backend.insert_aux(
        &[(
            channel_processed_state_key(dst_chain_id, channel_state.channel_id).as_slice(),
            channel_state.encode().as_slice(),
        )],
        vec![],
    )
}

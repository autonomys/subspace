//! Schema for channel update storage.

use parity_scale_codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, Info, Result as ClientResult};
use sp_core::bytes::to_hex;
use sp_core::H256;
use sp_messenger::messages::{ChainId, ChannelId, ChannelState, Nonce};
use sp_messenger::{ChannelNonce, XdmId};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use subspace_runtime_primitives::BlockNumber;

const CHANNEL_DETAIL: &[u8] = b"channel_detail";

fn channel_detail_key(
    src_chain_id: ChainId,
    self_chain_id: ChainId,
    channel_id: ChannelId,
) -> Vec<u8> {
    (CHANNEL_DETAIL, src_chain_id, self_chain_id, channel_id).encode()
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

/// Channel detail between src and dst chain.
#[derive(Debug, Encode, Decode, Clone)]
pub struct ChannelDetail {
    // Block number of chain at which the channel state is verified.
    pub block_number: BlockNumber,
    /// Block hash of the chain at which the channel state is verified.
    pub block_hash: H256,
    /// State root of the chain at the above block height.
    pub state_root: H256,
    /// Channel identifier.
    pub channel_id: ChannelId,
    /// State of the channel.
    pub state: ChannelState,
    /// Next inbox nonce.
    pub next_inbox_nonce: Nonce,
    /// Next outbox nonce.
    pub next_outbox_nonce: Nonce,
    /// Latest outbox message nonce for which response was received from dst_chain.
    pub latest_response_received_message_nonce: Option<Nonce>,
}

/// Load the channel state of self_chain_id on src_chain_id.
pub fn get_channel_state<Backend>(
    backend: &Backend,
    src_chain_id: ChainId,
    self_chain_id: ChainId,
    channel_id: ChannelId,
) -> ClientResult<Option<ChannelDetail>>
where
    Backend: AuxStore,
{
    load_decode(
        backend,
        channel_detail_key(src_chain_id, self_chain_id, channel_id).as_slice(),
    )
}

/// Set the channel state of self_chain_id on src_chain_id.
pub fn set_channel_state<Backend>(
    backend: &Backend,
    src_chain_id: ChainId,
    self_chain_id: ChainId,
    channel_detail: ChannelDetail,
) -> ClientResult<()>
where
    Backend: AuxStore,
{
    backend.insert_aux(
        &[(
            channel_detail_key(src_chain_id, self_chain_id, channel_detail.channel_id).as_slice(),
            channel_detail.encode().as_slice(),
        )],
        vec![],
    )
}

mod xdm_keys {
    use parity_scale_codec::Encode;
    use sp_domains::{ChainId, ChannelId};
    use sp_messenger::messages::MessageKey;
    use sp_messenger::XdmId;

    const XDM: &[u8] = b"xdm";
    const XDM_RELAY: &[u8] = b"relay_msg";
    const XDM_RELAY_RESPONSE: &[u8] = b"relay_msg_response";
    const XDM_LAST_CLEANUP_NONCE: &[u8] = b"xdm_last_cleanup_nonce";

    pub(super) fn get_key_for_xdm_id(prefix: &[u8], xdm_id: XdmId) -> Vec<u8> {
        match xdm_id {
            XdmId::RelayMessage(id) => get_key_for_xdm_relay(prefix, id),
            XdmId::RelayResponseMessage(id) => get_key_for_xdm_relay_response(prefix, id),
        }
    }

    pub(super) fn get_key_for_last_cleanup_relay_nonce(
        prefix: &[u8],
        chain_id: ChainId,
        channel_id: ChannelId,
    ) -> Vec<u8> {
        (
            prefix,
            XDM,
            XDM_RELAY,
            XDM_LAST_CLEANUP_NONCE,
            chain_id,
            channel_id,
        )
            .encode()
    }

    pub(super) fn get_key_for_last_cleanup_relay_response_nonce(
        prefix: &[u8],
        chain_id: ChainId,
        channel_id: ChannelId,
    ) -> Vec<u8> {
        (
            prefix,
            XDM,
            XDM_RELAY_RESPONSE,
            XDM_LAST_CLEANUP_NONCE,
            chain_id,
            channel_id,
        )
            .encode()
    }

    pub(super) fn get_key_for_xdm_relay(prefix: &[u8], id: MessageKey) -> Vec<u8> {
        (prefix, XDM, XDM_RELAY, id).encode()
    }

    pub(super) fn get_key_for_xdm_relay_response(prefix: &[u8], id: MessageKey) -> Vec<u8> {
        (prefix, XDM, XDM_RELAY_RESPONSE, id).encode()
    }
}

#[derive(Debug, Encode, Decode, Clone)]
pub struct BlockId<Block: BlockT> {
    pub number: NumberFor<Block>,
    pub hash: Block::Hash,
}

impl<Block: BlockT> From<Info<Block>> for BlockId<Block> {
    fn from(value: Info<Block>) -> Self {
        BlockId {
            number: value.best_number,
            hash: value.best_hash,
        }
    }
}

/// Store the given XDM ID as processed at given block.
pub fn set_xdm_message_processed_at<Backend, Block>(
    backend: &Backend,
    prefix: &[u8],
    xdm_id: XdmId,
    block_id: BlockId<Block>,
) -> ClientResult<()>
where
    Backend: AuxStore,
    Block: BlockT,
{
    let key = xdm_keys::get_key_for_xdm_id(prefix, xdm_id);
    backend.insert_aux(&[(key.as_slice(), block_id.encode().as_slice())], vec![])
}

/// Returns the maybe last processed block number for given xdm.
pub fn get_xdm_processed_block_number<Backend, Block>(
    backend: &Backend,
    prefix: &[u8],
    xdm_id: XdmId,
) -> ClientResult<Option<BlockId<Block>>>
where
    Backend: AuxStore,
    Block: BlockT,
{
    load_decode(
        backend,
        xdm_keys::get_key_for_xdm_id(prefix, xdm_id).as_slice(),
    )
}

/// Cleans up all the xdm storages until the latest nonces.
pub fn cleanup_chain_channel_storages<Backend>(
    backend: &Backend,
    prefix: &[u8],
    chain_id: ChainId,
    channel_id: ChannelId,
    channel_nonce: ChannelNonce,
) -> ClientResult<()>
where
    Backend: AuxStore,
{
    let mut to_insert = vec![];
    let mut to_delete = vec![];
    if let Some(latest_relay_nonce) = channel_nonce.relay_msg_nonce {
        let last_cleanup_relay_nonce_key =
            xdm_keys::get_key_for_last_cleanup_relay_nonce(prefix, chain_id, channel_id);
        let last_cleaned_up_nonce =
            load_decode::<_, Nonce>(backend, last_cleanup_relay_nonce_key.as_slice())?;

        let mut from_nonce = match last_cleaned_up_nonce {
            None => Nonce::zero(),
            Some(last_nonce) => last_nonce.saturating_add(Nonce::one()),
        };

        tracing::debug!(
            "[{:?}]Cleaning Relay xdm keys for {:?} channel: {:?} from: {:?} to: {:?}",
            to_hex(prefix, false),
            chain_id,
            channel_id,
            from_nonce,
            latest_relay_nonce
        );

        while from_nonce <= latest_relay_nonce {
            to_delete.push(xdm_keys::get_key_for_xdm_relay(
                prefix,
                (chain_id, channel_id, from_nonce),
            ));
            from_nonce = from_nonce.saturating_add(Nonce::one());
        }

        to_insert.push((last_cleanup_relay_nonce_key, latest_relay_nonce.encode()));
    }

    if let Some(latest_relay_response_nonce) = channel_nonce.relay_response_msg_nonce {
        let last_cleanup_relay_response_nonce_key =
            xdm_keys::get_key_for_last_cleanup_relay_response_nonce(prefix, chain_id, channel_id);
        let last_cleaned_up_nonce =
            load_decode::<_, Nonce>(backend, last_cleanup_relay_response_nonce_key.as_slice())?;

        let mut from_nonce = match last_cleaned_up_nonce {
            None => Nonce::zero(),
            Some(last_nonce) => last_nonce.saturating_add(Nonce::one()),
        };

        tracing::debug!(
            "[{:?}]Cleaning Relay response xdm keys for {:?} channel: {:?} from: {:?} to: {:?}",
            to_hex(prefix, false),
            chain_id,
            channel_id,
            from_nonce,
            latest_relay_response_nonce
        );

        while from_nonce <= latest_relay_response_nonce {
            to_delete.push(xdm_keys::get_key_for_xdm_relay_response(
                prefix,
                (chain_id, channel_id, from_nonce),
            ));
            from_nonce = from_nonce.saturating_add(Nonce::one());
        }

        to_insert.push((
            last_cleanup_relay_response_nonce_key,
            latest_relay_response_nonce.encode(),
        ));
    }

    backend.insert_aux(
        &to_insert
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect::<Vec<_>>(),
        &to_delete.iter().map(|k| k.as_slice()).collect::<Vec<_>>(),
    )
}

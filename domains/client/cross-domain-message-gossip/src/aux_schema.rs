//! Schema for channel update storage.

use parity_scale_codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, Info, Result as ClientResult};
use sp_core::H256;
use sp_messenger::messages::{ChainId, ChannelId, ChannelState, Nonce};
use sp_messenger::XdmId;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use subspace_runtime_primitives::BlockNumber;

const CHANNEL_DETAIL: &[u8] = b"channel_detail";

fn channel_detail_key(
    src_chain_id: ChainId,
    dst_chain_id: ChainId,
    channel_id: ChannelId,
) -> Vec<u8> {
    (CHANNEL_DETAIL, src_chain_id, dst_chain_id, channel_id).encode()
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

/// Load the channel state of self_chain_id on chain_id.
pub fn get_channel_state<Backend>(
    backend: &Backend,
    self_chain_id: ChainId,
    chain_id: ChainId,
    channel_id: ChannelId,
) -> ClientResult<Option<ChannelDetail>>
where
    Backend: AuxStore,
{
    load_decode(
        backend,
        channel_detail_key(chain_id, self_chain_id, channel_id).as_slice(),
    )
}

/// Set the channel state of self_chain_id on chain_id.
pub fn set_channel_state<Backend>(
    backend: &Backend,
    self_chain_id: ChainId,
    chain_id: ChainId,
    channel_detail: ChannelDetail,
) -> ClientResult<()>
where
    Backend: AuxStore,
{
    backend.insert_aux(
        &[(
            channel_detail_key(chain_id, self_chain_id, channel_detail.channel_id).as_slice(),
            channel_detail.encode().as_slice(),
        )],
        vec![],
    )
}

mod xdm_keys {
    use parity_scale_codec::Encode;
    use sp_messenger::XdmId;

    const XDM: &[u8] = b"xdm";
    const XDM_RELAY: &[u8] = b"relay_msg";
    const XDM_RELAY_RESPONSE: &[u8] = b"relay_msg_response";

    pub(super) fn get_key_for_xdm_id(xdm_id: XdmId) -> Vec<u8> {
        match xdm_id {
            XdmId::RelayMessage(id) => (XDM, XDM_RELAY, id).encode(),
            XdmId::RelayResponseMessage(id) => (XDM, XDM_RELAY_RESPONSE, id).encode(),
        }
    }
}

#[derive(Debug, Encode, Decode, Clone)]
pub(super) struct BlockId<Block: BlockT> {
    pub(super) number: NumberFor<Block>,
    pub(super) hash: Block::Hash,
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
    xdm_id: XdmId,
    block_id: BlockId<Block>,
) -> ClientResult<()>
where
    Backend: AuxStore,
    Block: BlockT,
{
    let key = xdm_keys::get_key_for_xdm_id(xdm_id);
    backend.insert_aux(&[(key.as_slice(), block_id.encode().as_slice())], vec![])
}

/// Returns the maybe last processed block number for given xdm.
pub fn get_xdm_processed_block_number<Backend, Block>(
    backend: &Backend,
    xdm_id: XdmId,
) -> ClientResult<Option<BlockId<Block>>>
where
    Backend: AuxStore,
    Block: BlockT,
{
    load_decode(backend, xdm_keys::get_key_for_xdm_id(xdm_id).as_slice())
}

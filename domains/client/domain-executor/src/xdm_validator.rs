use futures::FutureExt;
use sc_client_api::BlockBackend;
use sc_transaction_pool::{ChainApi, FullChainApi};
use sc_transaction_pool_api::error::Error as TxPoolError;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error, HeaderBackend, HeaderMetadata};
use sp_core::traits::SpawnNamed;
use sp_messenger::MessengerApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, BlockIdTo, Header, NumberFor};
use sp_runtime::transaction_validity::TransactionSource;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_transaction_pool::{BlockExtrinsicOf, ValidateExtrinsic, ValidationFuture};
use system_runtime_primitives::SystemDomainApi;

/// Verifies if the xdm has the correct proof generated from known parent block.
/// This is used by Core domain nodes and also System domain nodes
/// Core domains nodes use this to verify an XDM coming from other domains.
/// System domain node use this to verify the XDM while validating fraud proof.
/// Returns either true if the XDM is valid else false.
/// Returns Error when required calls to fetch header info fails.
fn verify_xdm_with_system_domain_client<Client, Block, SBlock, PBlock>(
    system_domain_client: &Arc<Client>,
    extrinsic: &SBlock::Extrinsic,
) -> Result<bool, Error>
where
    Client: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    Client::Api: MessengerApi<SBlock, NumberFor<SBlock>>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    Block: BlockT,
    SBlock: BlockT,
    PBlock: BlockT,
{
    let api = system_domain_client.runtime_api();
    let best_hash = system_domain_client.info().best_hash;
    if let Ok(Some(state_roots)) = api.extract_xdm_proof_state_roots(best_hash, extrinsic) {
        // verify system domain state root
        let header = system_domain_client
            .header(state_roots.system_domain_block_info.block_hash)?
            .ok_or(Error::MissingHeader(format!(
                "hash: {}",
                state_roots.system_domain_block_info.block_hash
            )))?;

        if *header.number() != state_roots.system_domain_block_info.block_number {
            return Ok(false);
        }

        if *header.state_root() != state_roots.system_domain_state_root {
            return Ok(false);
        }

        // verify core domain state root if there is one
        if let Some((domain_id, core_domain_info, core_domain_state_root)) =
            state_roots.core_domain_info
        {
            if let Some(expected_core_domain_state_root) = api.core_domain_state_root_at(
                best_hash,
                domain_id,
                core_domain_info.block_number,
                core_domain_info.block_hash,
            )? {
                if expected_core_domain_state_root != core_domain_state_root {
                    return Ok(false);
                }
            }
        }
    }

    Ok(true)
}

pub struct CoreDomainXDMValidator<SDC, PBlock, SBlock> {
    _data: PhantomData<(PBlock, SBlock)>,
    system_domain_client: Arc<SDC>,
}

impl<SDC, PBlock, SBlock> CoreDomainXDMValidator<SDC, PBlock, SBlock> {
    pub fn new(system_domain_client: Arc<SDC>) -> Self {
        Self {
            _data: Default::default(),
            system_domain_client,
        }
    }
}

impl<SDC, PBlock, SBlock> Clone for CoreDomainXDMValidator<SDC, PBlock, SBlock> {
    fn clone(&self) -> Self {
        Self {
            _data: Default::default(),
            system_domain_client: self.system_domain_client.clone(),
        }
    }
}

impl<Block, Client, SDC, SBlock, PBlock>
    ValidateExtrinsic<Block, Client, FullChainApi<Client, Block>>
    for CoreDomainXDMValidator<SDC, PBlock, SBlock>
where
    Block: BlockT,
    SDC: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SDC::Api: MessengerApi<SBlock, NumberFor<SBlock>>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    Block: BlockT,
    SBlock: BlockT,
    Block::Extrinsic: Into<SBlock::Extrinsic>,
    PBlock: BlockT,
    Client: ProvideRuntimeApi<Block>
        + BlockBackend<Block>
        + BlockIdTo<Block>
        + HeaderBackend<Block>
        + HeaderMetadata<Block, Error = sp_blockchain::Error>
        + Send
        + Sync
        + 'static,
    Client::Api: TaggedTransactionQueue<Block>,
{
    fn validate_extrinsic(
        &self,
        at: Block::Hash,
        source: TransactionSource,
        uxt: BlockExtrinsicOf<Block>,
        _spawner: Box<dyn SpawnNamed>,
        chain_api: Arc<FullChainApi<Client, Block>>,
    ) -> ValidationFuture {
        let result = verify_xdm_with_system_domain_client::<SDC, Block, SBlock, PBlock>(
            &self.system_domain_client,
            &(uxt.clone().into()),
        );
        match result {
            Ok(valid) => {
                if valid {
                    chain_api.validate_transaction(&BlockId::Hash(at), source, uxt)
                } else {
                    tracing::trace!(target: "xdm_validator", "Dropped invalid XDM extrinsic");
                    async move { Err(TxPoolError::ImmediatelyDropped.into()) }.boxed()
                }
            }
            Err(err) => {
                tracing::trace!(target: "xdm_validator", error = ?err, "Failed to verify XDM");
                async move { Err(TxPoolError::ImmediatelyDropped.into()) }.boxed()
            }
        }
    }
}

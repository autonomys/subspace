use crate::state_root_extractor::StateRootExtractor;
use futures::FutureExt;
use sc_client_api::BlockBackend;
use sc_transaction_pool::{ChainApi, FullChainApi};
use sc_transaction_pool_api::error::Error as TxPoolError;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::{Error, HeaderBackend, HeaderMetadata};
use sp_core::traits::SpawnNamed;
use sp_domains::ExecutorApi;
use sp_messenger::MessengerApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{Block as BlockT, BlockIdTo, CheckedSub, Header, NumberFor};
use sp_runtime::transaction_validity::TransactionSource;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use std::marker::PhantomData;
use std::sync::Arc;
use subspace_transaction_pool::{BlockExtrinsicOf, ValidationFuture, VerifyExtrinsic};
use system_runtime_primitives::SystemDomainApi;

/// Verifies if the xdm has the correct proof generated from known parent block.
/// This is used by Core domain nodes.
/// Core domains nodes use this to verify an XDM coming from other domains.
/// Returns either true if the XDM is valid else false.
/// Returns Error when required calls to fetch header info fails.
pub(crate) fn verify_xdm_with_system_domain_client<Client, Block, SBlock, PBlock>(
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

        // verify core domain state root and the if the number is K-deep.
        if let Some((domain_id, core_domain_info, core_domain_state_root)) =
            state_roots.core_domain_info
        {
            let best_number = api.head_receipt_number(best_hash, domain_id)?;
            if let Some(confirmed_number) =
                best_number.checked_sub(&api.confirmation_depth(best_hash)?)
            {
                if confirmed_number < core_domain_info.block_number {
                    return Ok(false);
                }
            }

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

/// Verifies if the xdm has the correct proof generated from known parent block.
/// This is used by the System domain to validate Extrinsics.
/// Returns either true if the XDM is valid else false.
/// Returns Error when required calls to fetch header info fails.
pub(crate) fn verify_xdm_with_primary_chain_client<PClient, PBlock, SBlock, SRE>(
    primary_chain_client: &Arc<PClient>,
    state_root_extractor: &SRE,
    extrinsic: &SBlock::Extrinsic,
) -> Result<bool, Error>
where
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: ExecutorApi<PBlock, SBlock::Hash>,
    SBlock: BlockT,
    PBlock: BlockT,
    NumberFor<PBlock>: From<NumberFor<SBlock>>,
    PBlock::Hash: From<SBlock::Hash>,
    SRE: StateRootExtractor<SBlock>,
{
    let at = state_root_extractor.block_hash();
    if let Ok(state_roots) = state_root_extractor.extract_state_roots(at, extrinsic) {
        // verify system domain state root
        let best_hash = primary_chain_client.info().best_hash;
        let primary_runtime = primary_chain_client.runtime_api();
        if let Some(system_domain_state_root) = primary_runtime.system_domain_state_root_at(
            best_hash,
            state_roots.system_domain_block_info.block_number.into(),
            state_roots.system_domain_block_info.block_hash,
        )? {
            if system_domain_state_root != state_roots.system_domain_state_root.into() {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

/// A verifier for XDM messages on System domain.
pub struct SystemDomainXDMVerifier<PClient, PBlock, SBlock, Verifier, SRE> {
    _data: PhantomData<(PBlock, SBlock)>,
    primary_chain_client: Arc<PClient>,
    state_root_extractor: SRE,
    inner_verifier: Verifier,
}

impl<PClient, PBlock, SBlock, Verifier, SRE>
    SystemDomainXDMVerifier<PClient, PBlock, SBlock, Verifier, SRE>
{
    pub fn new(
        primary_chain_client: Arc<PClient>,
        state_root_extractor: SRE,
        inner_verifier: Verifier,
    ) -> Self {
        Self {
            _data: Default::default(),
            primary_chain_client,
            state_root_extractor,
            inner_verifier,
        }
    }
}

impl<PClient, PBlock, SBlock, Verifier, SRE> Clone
    for SystemDomainXDMVerifier<PClient, PBlock, SBlock, Verifier, SRE>
where
    Verifier: Clone,
    SRE: Clone,
{
    fn clone(&self) -> Self {
        Self {
            _data: Default::default(),
            primary_chain_client: self.primary_chain_client.clone(),
            state_root_extractor: self.state_root_extractor.clone(),
            inner_verifier: self.inner_verifier.clone(),
        }
    }
}

impl<PClient, SClient, PBlock, SBlock, Verifier, SRE>
    VerifyExtrinsic<SBlock, SClient, FullChainApi<SClient, SBlock>>
    for SystemDomainXDMVerifier<PClient, PBlock, SBlock, Verifier, SRE>
where
    PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + 'static,
    PClient::Api: ExecutorApi<PBlock, SBlock::Hash>,
    SClient: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + 'static,
    SClient::Api: MessengerApi<SBlock, NumberFor<SBlock>>
        + SystemDomainApi<SBlock, NumberFor<PBlock>, PBlock::Hash>,
    SBlock: BlockT,
    PBlock: BlockT,
    NumberFor<PBlock>: From<NumberFor<SBlock>>,
    PBlock::Hash: From<SBlock::Hash>,
    Verifier: VerifyExtrinsic<SBlock, SClient, FullChainApi<SClient, SBlock>>,
    SRE: StateRootExtractor<SBlock>,
{
    fn verify_extrinsic(
        &self,
        at: SBlock::Hash,
        source: TransactionSource,
        uxt: BlockExtrinsicOf<SBlock>,
        spawner: Box<dyn SpawnNamed>,
        chain_api: Arc<FullChainApi<SClient, SBlock>>,
    ) -> ValidationFuture {
        let result = verify_xdm_with_primary_chain_client::<_, _, _, _>(
            &self.primary_chain_client,
            &self.state_root_extractor,
            &uxt,
        );

        match result {
            Ok(valid) => {
                if valid {
                    self.inner_verifier
                        .verify_extrinsic(at, source, uxt, spawner, chain_api)
                } else {
                    tracing::trace!(target: "system_domain_xdm_validator", "Dropped invalid XDM extrinsic");
                    async move { Err(TxPoolError::ImmediatelyDropped.into()) }.boxed()
                }
            }
            Err(err) => {
                tracing::trace!(target: "system_domain_xdm_validator", error = ?err, "Failed to verify XDM");
                async move { Err(TxPoolError::ImmediatelyDropped.into()) }.boxed()
            }
        }
    }
}

/// A Verifier for XDM messages on Core domains.
pub struct CoreDomainXDMVerifier<SDC, PBlock, SBlock> {
    _data: PhantomData<(PBlock, SBlock)>,
    system_domain_client: Arc<SDC>,
}

impl<SDC, PBlock, SBlock> CoreDomainXDMVerifier<SDC, PBlock, SBlock> {
    pub fn new(system_domain_client: Arc<SDC>) -> Self {
        Self {
            _data: Default::default(),
            system_domain_client,
        }
    }
}

impl<SDC, PBlock, SBlock> Clone for CoreDomainXDMVerifier<SDC, PBlock, SBlock> {
    fn clone(&self) -> Self {
        Self {
            _data: Default::default(),
            system_domain_client: self.system_domain_client.clone(),
        }
    }
}

impl<Block, Client, SDC, SBlock, PBlock> VerifyExtrinsic<Block, Client, FullChainApi<Client, Block>>
    for CoreDomainXDMVerifier<SDC, PBlock, SBlock>
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
        + HeaderMetadata<Block, Error = Error>
        + Send
        + Sync
        + 'static,
    Client::Api: TaggedTransactionQueue<Block>,
{
    fn verify_extrinsic(
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
                    tracing::trace!(target: "core_domain_xdm_validator", "Dropped invalid XDM extrinsic");
                    async move { Err(TxPoolError::ImmediatelyDropped.into()) }.boxed()
                }
            }
            Err(err) => {
                tracing::trace!(target: "core_domain_xdm_validator", error = ?err, "Failed to verify XDM");
                async move { Err(TxPoolError::ImmediatelyDropped.into()) }.boxed()
            }
        }
    }
}

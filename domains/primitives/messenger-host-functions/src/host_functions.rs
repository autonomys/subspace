use crate::StorageKeyRequest;
use domain_block_preprocessor::stateless_runtime::StatelessRuntime;
use sc_executor::RuntimeVersionOf;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::{ChainId, DomainId, DomainsApi};
use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use std::marker::PhantomData;
use std::sync::Arc;

/// Trait to query messenger specific details.
pub trait MessengerHostFunctions: Send + Sync {
    /// Returns the storage key for the given request.
    fn get_storage_key(&self, req: StorageKeyRequest) -> Option<Vec<u8>>;
}

sp_externalities::decl_extension! {
    pub struct MessengerExtension(Arc<dyn MessengerHostFunctions>);
}

impl MessengerExtension {
    /// Create a new instance of [`MessengerExtension`].
    pub fn new(inner: Arc<dyn MessengerHostFunctions>) -> Self {
        Self(inner)
    }
}

/// Implementation of Messenger host function.
pub struct MessengerHostFunctionsImpl<Block, Client, DomainBlock, Executor> {
    consensus_client: Arc<Client>,
    executor: Arc<Executor>,
    _phantom: PhantomData<(Block, DomainBlock)>,
}

impl<Block, Client, DomainBlock, Executor>
    MessengerHostFunctionsImpl<Block, Client, DomainBlock, Executor>
{
    pub fn new(consensus_client: Arc<Client>, executor: Arc<Executor>) -> Self {
        MessengerHostFunctionsImpl {
            consensus_client,
            executor,
            _phantom: Default::default(),
        }
    }
}

impl<Block, Client, DomainBlock, Executor>
    MessengerHostFunctionsImpl<Block, Client, DomainBlock, Executor>
where
    Block: BlockT,
    DomainBlock: BlockT,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: DomainsApi<Block, DomainBlock::Header>,
{
    fn get_domain_runtime_code(
        &self,
        consensus_block_hash: Block::Hash,
        domain_id: DomainId,
    ) -> Option<Vec<u8>> {
        let runtime_api = self.consensus_client.runtime_api();
        // Use the parent hash to get the actual used domain runtime code
        // TODO: update once we can get the actual used domain runtime code by `consensus_block_hash`
        let consensus_block_header = self
            .consensus_client
            .header(consensus_block_hash)
            .ok()
            .flatten()?;
        runtime_api
            .domain_runtime_code(*consensus_block_header.parent_hash(), domain_id)
            .ok()
            .flatten()
    }
}

impl<Block, Client, DomainBlock, Executor> MessengerHostFunctions
    for MessengerHostFunctionsImpl<Block, Client, DomainBlock, Executor>
where
    Block: BlockT,
    Block::Hash: From<H256>,
    DomainBlock: BlockT,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api: MessengerApi<Block, NumberFor<Block>> + DomainsApi<Block, DomainBlock::Header>,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn get_storage_key(&self, req: StorageKeyRequest) -> Option<Vec<u8>> {
        let best_hash = self.consensus_client.info().best_hash;
        let runtime_api = self.consensus_client.runtime_api();
        match req {
            StorageKeyRequest::ConfirmedDomainBlockStorageKey(domain_id) => runtime_api
                .confirmed_domain_block_storage_key(best_hash, domain_id)
                .map(Some),
            StorageKeyRequest::OutboxStorageKey {
                message_id,
                chain_id: ChainId::Consensus,
            } => runtime_api
                .outbox_storage_key(best_hash, message_id)
                .map(Some),
            StorageKeyRequest::OutboxStorageKey {
                message_id,
                chain_id: ChainId::Domain(domain_id),
            } => {
                let runtime_code = self.get_domain_runtime_code(best_hash, domain_id)?;
                let domain_stateless_runtime = StatelessRuntime::<DomainBlock, _>::new(
                    self.executor.clone(),
                    runtime_code.into(),
                );
                domain_stateless_runtime
                    .outbox_storage_key(message_id)
                    .map(Some)
            }
            StorageKeyRequest::InboxResponseStorageKey {
                message_id,
                chain_id: ChainId::Consensus,
            } => runtime_api
                .inbox_response_storage_key(best_hash, message_id)
                .map(Some),
            StorageKeyRequest::InboxResponseStorageKey {
                message_id,
                chain_id: ChainId::Domain(domain_id),
            } => {
                let runtime_code = self.get_domain_runtime_code(best_hash, domain_id)?;
                let domain_stateless_runtime = StatelessRuntime::<DomainBlock, _>::new(
                    self.executor.clone(),
                    runtime_code.into(),
                );
                domain_stateless_runtime
                    .inbox_response_storage_key(message_id)
                    .map(Some)
            }
        }
        .expect(
            "Runtime Api should not fail in host function, there is no recovery from this; qed.",
        )
    }
}

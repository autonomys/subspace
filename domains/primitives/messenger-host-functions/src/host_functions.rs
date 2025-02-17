use crate::StorageKeyRequest;
use domain_block_preprocessor::stateless_runtime::StatelessRuntime;
use sc_executor::RuntimeVersionOf;
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_core::traits::CodeExecutor;
use sp_core::H256;
use sp_domains::{DomainId, DomainsApi};
use sp_messenger::messages::ChainId;
pub use sp_messenger::MessengerApi;
use sp_runtime::traits::{Block as BlockT, Header, NumberFor};
use std::marker::PhantomData;
use std::sync::Arc;

/// Trait to query messenger specific details.
pub trait MessengerHostFunctions: Send + Sync {
    /// Returns the storage key for the given request.
    fn get_storage_key(&self, req: StorageKeyRequest) -> Option<Vec<u8>>;

    /// Checks if the given src_chain_id is in the dst_chain's allowlist
    fn is_src_chain_in_dst_chain_allowlist(
        &self,
        src_chain_id: ChainId,
        dst_chain_id: ChainId,
    ) -> bool;
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
    domain_executor: Arc<Executor>,
    _phantom: PhantomData<(Block, DomainBlock)>,
}

impl<Block, Client, DomainBlock, Executor>
    MessengerHostFunctionsImpl<Block, Client, DomainBlock, Executor>
{
    pub fn new(consensus_client: Arc<Client>, domain_executor: Arc<Executor>) -> Self {
        MessengerHostFunctionsImpl {
            consensus_client,
            domain_executor,
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
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn get_domain_runtime(
        &self,
        consensus_block_hash: Block::Hash,
        domain_id: DomainId,
    ) -> Option<StatelessRuntime<Block, DomainBlock, Executor>> {
        let runtime_api = self.consensus_client.runtime_api();
        // Use the parent hash to get the actual used domain runtime code
        // TODO: update once we can get the actual used domain runtime code by `consensus_block_hash`
        let consensus_block_header = self
            .consensus_client
            .header(consensus_block_hash)
            .ok()
            .flatten()?;
        let domain_runtime = runtime_api
            .domain_runtime_code(*consensus_block_header.parent_hash(), domain_id)
            .ok()
            .flatten()?;

        // we need the initial state here so that SelfChainId is initialised on domain
        let domain_state = runtime_api
            .domain_instance_data(*consensus_block_header.parent_hash(), domain_id)
            .ok()
            .flatten()
            .map(|(data, _)| data.raw_genesis.into_storage())?;
        let mut domain_stateless_runtime = StatelessRuntime::<Block, DomainBlock, _>::new(
            self.domain_executor.clone(),
            domain_runtime.into(),
        );

        domain_stateless_runtime.set_storage(domain_state);
        Some(domain_stateless_runtime)
    }
}

impl<Block, Client, DomainBlock, Executor> MessengerHostFunctions
    for MessengerHostFunctionsImpl<Block, Client, DomainBlock, Executor>
where
    Block: BlockT,
    Block::Hash: From<H256>,
    DomainBlock: BlockT,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block>,
    Client::Api:
        MessengerApi<Block, NumberFor<Block>, Block::Hash> + DomainsApi<Block, DomainBlock::Header>,
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
                message_key,
                chain_id: ChainId::Consensus,
            } => runtime_api
                .outbox_storage_key(best_hash, message_key)
                .map(Some),
            StorageKeyRequest::OutboxStorageKey {
                message_key,
                chain_id: ChainId::Domain(domain_id),
            } => {
                let domain_stateless_runtime = self.get_domain_runtime(best_hash, domain_id)?;
                domain_stateless_runtime
                    .outbox_storage_key(message_key)
                    .map(Some)
            }
            StorageKeyRequest::InboxResponseStorageKey {
                message_key,
                chain_id: ChainId::Consensus,
            } => runtime_api
                .inbox_response_storage_key(best_hash, message_key)
                .map(Some),
            StorageKeyRequest::InboxResponseStorageKey {
                message_key,
                chain_id: ChainId::Domain(domain_id),
            } => {
                let domain_stateless_runtime = self.get_domain_runtime(best_hash, domain_id)?;
                domain_stateless_runtime
                    .inbox_response_storage_key(message_key)
                    .map(Some)
            }
        }
        .expect(
            "Runtime Api should not fail in host function, there is no recovery from this; qed.",
        )
    }

    fn is_src_chain_in_dst_chain_allowlist(
        &self,
        src_chain_id: ChainId,
        dst_chain_id: ChainId,
    ) -> bool {
        let best_hash = self.consensus_client.info().best_hash;
        let runtime_api = self.consensus_client.runtime_api();

        // TODO: remove version check before next network
        let messenger_api_version = runtime_api
            .api_version::<dyn DomainsApi<Block, Block::Header>>(best_hash)
            .ok()
            .flatten()
            // It is safe to return a default version of 1, since there will always be version 1.
            .unwrap_or(1);

        if messenger_api_version >= 3 {
            let allowlist = runtime_api
                .chain_allowlist(best_hash, dst_chain_id)
                .ok()
                .unwrap_or_default();
            allowlist.contains(&src_chain_id)
        } else {
            // if the consensus runtime is not upgraded but domains are upgrade,
            // we return still return false
            // This is since new runtime would always check allowlist on dst_chain and message is
            // rejected and this will break the XDM request and response protocol.
            // Rejecting means, new channels wont be created until consensus rutime is upgraded.
            false
        }
    }
}

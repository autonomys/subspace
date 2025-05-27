//! Custom genesis block builder to inject correct genesis block.

use hex_literal::hex;
use sc_chain_spec::{construct_genesis_block, resolve_state_version_from_wasm, BuildGenesisBlock};
use sc_client_api::{Backend, BlockImportOperation};
use sc_executor::RuntimeVersionOf;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::storage::Storage;
use sp_core::H256;
use sp_domains::{DomainId, DomainsApi};
use sp_runtime::traits::{Block as BlockT, HashingFor};
use sp_runtime::BuildStorage;
use std::marker::PhantomData;
use std::sync::Arc;

/// Custom genesis block builder to inject correct genesis block for Domains.
pub struct CustomGenesisBlockBuilder<CClient, CBlock: BlockT, Block: BlockT, B, E> {
    domain_id: DomainId,
    consensus_client: Arc<CClient>,
    genesis_storage: Storage,
    commit_genesis_state: bool,
    backend: Arc<B>,
    executor: E,
    _data: PhantomData<(CBlock, Block)>,
}

impl<CClient, CBlock, Block: BlockT, B: Backend<Block>, E: RuntimeVersionOf>
    CustomGenesisBlockBuilder<CClient, CBlock, Block, B, E>
where
    Block: BlockT,
    B: Backend<Block>,
    E: RuntimeVersionOf,
    CBlock: BlockT,
{
    /// Constructs a new instance of Genesis block builder
    pub fn new(
        domain_id: DomainId,
        consensus_client: Arc<CClient>,
        build_genesis_storage: &dyn BuildStorage,
        commit_genesis_state: bool,
        backend: Arc<B>,
        executor: E,
    ) -> sp_blockchain::Result<Self> {
        let genesis_storage = build_genesis_storage
            .build_storage()
            .map_err(sp_blockchain::Error::Storage)?;
        Ok(Self {
            domain_id,
            consensus_client,
            genesis_storage,
            commit_genesis_state,
            backend,
            executor,
            _data: Default::default(),
        })
    }
}

impl<CClient, CBlock, Block: BlockT, B: Backend<Block>, E: RuntimeVersionOf>
    BuildGenesisBlock<Block> for CustomGenesisBlockBuilder<CClient, CBlock, Block, B, E>
where
    Block: BlockT,
    Block::Hash: From<H256>,
    B: Backend<Block>,
    E: RuntimeVersionOf,
    CBlock: BlockT,
    CBlock::Hash: From<H256>,
    CClient: ProvideRuntimeApi<CBlock> + HeaderBackend<CBlock>,
    CClient::Api: DomainsApi<CBlock, Block::Header>,
{
    type BlockImportOperation = <B as Backend<Block>>::BlockImportOperation;

    fn build_genesis_block(self) -> sp_blockchain::Result<(Block, Self::BlockImportOperation)> {
        let Self {
            domain_id,
            consensus_client,
            genesis_storage,
            commit_genesis_state,
            backend,
            executor,
            _data,
        } = self;

        let maybe_expected_state_root = {
            let runtime_api = consensus_client.runtime_api();
            let consensus_best_hash = consensus_client.info().best_hash;

            match runtime_api.genesis_state_root(consensus_best_hash, domain_id)? {
                Some(hash) => Some(hash.into()),
                None => {
                    // TODO: remove this once the taurus runtime is upgraded
                    // if network is taurus, then we may not have it on runtime before runtime is
                    // upgraded, so instead return the known domain-0's state root.
                    if consensus_client.info().genesis_hash
                        == H256::from(hex!(
                            "295aeafca762a304d92ee1505548695091f6082d3f0aa4d092ac3cd6397a6c5e"
                        ))
                        .into()
                        && domain_id == DomainId::new(0)
                    {
                        Some(
                            H256::from(hex!(
                                "530eae1878202aa0ab5997eadf2b7245ee78f44a35ab25ff84151fab489aa334"
                            ))
                            .into(),
                        )
                    } else {
                        None
                    }
                }
            }
        };

        let genesis_state_version =
            resolve_state_version_from_wasm::<_, HashingFor<Block>>(&genesis_storage, &executor)?;
        let mut op = backend.begin_operation()?;
        let state_root =
            op.set_genesis_state(genesis_storage, commit_genesis_state, genesis_state_version)?;

        let genesis_block = if let Some(expected_state_root) = maybe_expected_state_root
            && expected_state_root != state_root
        {
            construct_genesis_block::<Block>(expected_state_root, genesis_state_version)
        } else {
            construct_genesis_block::<Block>(state_root, genesis_state_version)
        };

        Ok((genesis_block, op))
    }
}

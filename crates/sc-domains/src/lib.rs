//! Domain specific Host functions and Extension factory

use sc_client_api::execution_extensions::ExtensionsFactory as ExtensionsFactoryT;
use sc_executor::RuntimeVersionOf;
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::H256;
use sp_core::traits::CodeExecutor;
use sp_domains::DomainsApi;
use sp_domains_fraud_proof::FraudProofApi;
use sp_domains_fraud_proof::storage_proof::{
    FraudProofStorageKeyProviderInstance, FraudProofStorageKeyRequest,
};
use sp_externalities::Extensions;
use sp_messenger_host_functions::{MessengerApi, MessengerExtension, MessengerHostFunctionsImpl};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor, One};
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
use sp_subspace_mmr::host_functions::{MmrApi, SubspaceMmrExtension, SubspaceMmrHostFunctionsImpl};
use std::marker::PhantomData;
use std::sync::Arc;

pub mod domain_block_er;
pub mod spec_wrapper;

/// Host functions required for Subspace domain
#[cfg(not(feature = "runtime-benchmarks"))]
pub type HostFunctions = (
    sp_auto_id::auto_id_runtime_interface::HostFunctions,
    sp_io::SubstrateHostFunctions,
    sp_messenger_host_functions::HostFunctions,
    sp_subspace_mmr::DomainHostFunctions,
);

/// Host functions required for Subspace domain
#[cfg(feature = "runtime-benchmarks")]
pub type HostFunctions = (
    sp_auto_id::auto_id_runtime_interface::HostFunctions,
    sp_io::SubstrateHostFunctions,
    sp_messenger_host_functions::HostFunctions,
    sp_subspace_mmr::DomainHostFunctions,
    frame_benchmarking::benchmarking::HostFunctions,
);

/// Runtime executor for Domains
pub type RuntimeExecutor = sc_executor::WasmExecutor<HostFunctions>;

/// Extensions factory for subspace domains.
pub struct ExtensionsFactory<CClient, CBlock, Block, Executor> {
    consensus_client: Arc<CClient>,
    executor: Arc<Executor>,
    confirmation_depth_k: u32,
    _marker: PhantomData<(CBlock, Block)>,
}

impl<CClient, CBlock, Block, Executor> ExtensionsFactory<CClient, CBlock, Block, Executor> {
    pub fn new(
        consensus_client: Arc<CClient>,
        executor: Arc<Executor>,
        confirmation_depth_k: u32,
    ) -> Self {
        Self {
            consensus_client,
            executor,
            confirmation_depth_k,
            _marker: Default::default(),
        }
    }
}

impl<CClient, CBlock, Block, Executor> ExtensionsFactoryT<Block>
    for ExtensionsFactory<CClient, CBlock, Block, Executor>
where
    Block: BlockT,
    CBlock: BlockT,
    CBlock::Hash: From<H256> + Into<H256>,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + 'static,
    CClient::Api: MmrApi<CBlock, H256, NumberFor<CBlock>>
        + MessengerApi<CBlock, NumberFor<CBlock>, CBlock::Hash>
        + DomainsApi<CBlock, Block::Header>,
    Executor: CodeExecutor + RuntimeVersionOf,
{
    fn extensions_for(
        &self,
        _block_hash: Block::Hash,
        _block_number: NumberFor<Block>,
    ) -> Extensions {
        let mut exts = Extensions::new();
        exts.register(SubspaceMmrExtension::new(Arc::new(
            SubspaceMmrHostFunctionsImpl::<CBlock, _>::new(
                self.consensus_client.clone(),
                self.confirmation_depth_k,
            ),
        )));

        exts.register(MessengerExtension::new(Arc::new(
            MessengerHostFunctionsImpl::<CBlock, _, Block, _>::new(
                self.consensus_client.clone(),
                self.executor.clone(),
            ),
        )));

        exts.register(sp_auto_id::host_functions::HostFunctionExtension::new(
            Arc::new(sp_auto_id::host_functions::HostFunctionsImpl),
        ));

        exts
    }
}

pub struct FPStorageKeyProvider<CBlock, DomainHeader, CClient> {
    consensus_client: Arc<CClient>,
    _phantom: PhantomData<(CBlock, DomainHeader)>,
}

impl<CBlock, DomainHeader, CClient> Clone for FPStorageKeyProvider<CBlock, DomainHeader, CClient> {
    fn clone(&self) -> Self {
        Self {
            consensus_client: self.consensus_client.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<CBlock, DomainHeader, CClient> FPStorageKeyProvider<CBlock, DomainHeader, CClient> {
    pub fn new(consensus_client: Arc<CClient>) -> Self {
        Self {
            consensus_client,
            _phantom: Default::default(),
        }
    }
}

impl<CBlock, DomainHeader, CClient> FraudProofStorageKeyProviderInstance<NumberFor<CBlock>>
    for FPStorageKeyProvider<CBlock, DomainHeader, CClient>
where
    CBlock: BlockT,
    DomainHeader: HeaderT,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + 'static,
    CClient::Api: FraudProofApi<CBlock, DomainHeader>,
{
    fn storage_key(&self, req: FraudProofStorageKeyRequest<NumberFor<CBlock>>) -> Option<Vec<u8>> {
        let best_hash = self.consensus_client.info().best_hash;
        self.consensus_client
            .runtime_api()
            .fraud_proof_storage_key(best_hash, req)
            .ok()
    }
}

/// Generate MMR proof for the block `to_prove` in the current best fork.
///
/// The returned proof can be later used to verify stateless (without query offchain MMR leaf) and
/// extract the state root at `to_prove`.
pub fn generate_mmr_proof<CClient, CBlock>(
    consensus_client: &Arc<CClient>,
    to_prove: NumberFor<CBlock>,
) -> sp_blockchain::Result<ConsensusChainMmrLeafProof<NumberFor<CBlock>, CBlock::Hash, H256>>
where
    CBlock: BlockT,
    CClient: HeaderBackend<CBlock> + ProvideRuntimeApi<CBlock> + 'static,
    CClient::Api: MmrApi<CBlock, H256, NumberFor<CBlock>>,
{
    let api = consensus_client.runtime_api();
    let prove_at_hash = consensus_client.info().best_hash;
    let prove_at_number = consensus_client.info().best_number;

    if to_prove >= prove_at_number {
        return Err(sp_blockchain::Error::Application(Box::from(format!(
            "Can't generate MMR proof for block {to_prove:?} >= best block {prove_at_number:?}"
        ))));
    }

    let (mut leaves, proof) = api
        // NOTE: the mmr leaf data is added in the next block so to generate the MMR proof of
        // block `to_prove` we need to use `to_prove + 1` here.
        .generate_proof(
            prove_at_hash,
            vec![to_prove + One::one()],
            Some(prove_at_number),
        )?
        .map_err(|err| {
            sp_blockchain::Error::Application(Box::from(format!(
                "Failed to generate MMR proof: {err}"
            )))
        })?;
    debug_assert!(leaves.len() == 1, "should always be of length 1");
    let leaf = leaves
        .pop()
        .ok_or(sp_blockchain::Error::Application(Box::from(
            "Unexpected missing mmr leaf".to_string(),
        )))?;

    Ok(ConsensusChainMmrLeafProof {
        consensus_block_number: prove_at_number,
        consensus_block_hash: prove_at_hash,
        opaque_mmr_leaf: leaf,
        proof,
    })
}

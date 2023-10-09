use crate::InvalidDomainExtrinsicRootInfo;
use sp_api::BlockT;
use sp_blockchain::HeaderBackend;
use sp_core::H256;
use std::marker::PhantomData;
use std::sync::Arc;

/// Trait to query and verify Domains Fraud proof.
pub trait FraudProofHostFunctions: Send + Sync {
    /// Returns the required info to verify invalid domain extrinsic root.
    fn get_invalid_domain_extrinsic_root_info(
        &self,
        consensus_block_hash: H256,
    ) -> Option<InvalidDomainExtrinsicRootInfo>;
}

sp_externalities::decl_extension! {
    /// Domains fraud proof host function
    pub struct FraudProofExtension(std::sync::Arc<dyn FraudProofHostFunctions>);
}

impl FraudProofExtension {
    /// Create a new instance of [`FraudProofExtension`].
    pub fn new(inner: std::sync::Arc<dyn FraudProofHostFunctions>) -> Self {
        Self(inner)
    }
}

/// Trait Impl to query and verify Domains Fraud proof.
#[allow(dead_code)]
pub struct FraudProofHostFunctionsImpl<Block, Client> {
    consensus_client: Arc<Client>,
    _phantom: PhantomData<Block>,
}

impl<Block, Client> FraudProofHostFunctionsImpl<Block, Client> {
    pub fn new(consensus_client: Arc<Client>) -> Self {
        FraudProofHostFunctionsImpl {
            consensus_client,
            _phantom: Default::default(),
        }
    }
}

impl<Block, Client> FraudProofHostFunctions for FraudProofHostFunctionsImpl<Block, Client>
where
    Block: BlockT,
    Block::Hash: From<H256>,
    Client: HeaderBackend<Block>,
{
    fn get_invalid_domain_extrinsic_root_info(
        &self,
        _consensus_block_hash: H256,
    ) -> Option<InvalidDomainExtrinsicRootInfo> {
        // TODO: will update in the following commits.
        Some(InvalidDomainExtrinsicRootInfo {
            block_randomness: Default::default(),
            timestamp_extrinsic: vec![],
        })
    }
}

use sp_api::{HeaderT, ProvideRuntimeApi};
use sp_core::traits::FetchRuntimeCode;
use sp_domains::{DomainId, DomainsApi};
use sp_domains_fraud_proof::fraud_proof::VerificationError;
use sp_runtime::traits::Block as BlockT;
use std::borrow::Cow;
use std::sync::Arc;

pub(crate) struct DomainRuntimeCodeFetcher(pub(crate) Vec<u8>);

impl FetchRuntimeCode for DomainRuntimeCodeFetcher {
    fn fetch_runtime_code(&self) -> Option<Cow<[u8]>> {
        Some(Cow::Borrowed(self.0.as_ref()))
    }
}

pub(crate) fn retrieve_domain_runtime_code<CBlock, CClient, DomainHeader>(
    domain_id: DomainId,
    at: CBlock::Hash,
    consensus_client: &Arc<CClient>,
) -> Result<DomainRuntimeCodeFetcher, VerificationError>
where
    CBlock: BlockT,
    DomainHeader: HeaderT,
    CClient: ProvideRuntimeApi<CBlock>,
    CClient::Api: DomainsApi<CBlock, DomainHeader>,
{
    let wasm_bundle = consensus_client
        .runtime_api()
        .domain_runtime_code(at, domain_id)
        .map_err(VerificationError::RuntimeApi)?
        .ok_or_else(|| {
            VerificationError::RuntimeCode(format!("No runtime code for {domain_id:?}"))
        })?;

    Ok(DomainRuntimeCodeFetcher(wasm_bundle))
}

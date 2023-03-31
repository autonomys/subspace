use crate::runtime_api::ExtractedStateRoots;
use codec::Encode;
use sp_api::{ApiError, BlockT, RuntimeApiInfo, RuntimeVersion};
use sp_messenger::MessengerApi;
use sp_runtime::traits::NumberFor;

pub(crate) fn extract_xdm_proof_state_roots_with_runtime<MAPI, SBlock>(
    runtime_version: RuntimeVersion,
    messenger_api: &MAPI,
    best_hash: SBlock::Hash,
    ext: &SBlock::Extrinsic,
) -> Result<Option<ExtractedStateRoots<SBlock>>, ApiError>
where
    SBlock: BlockT,
    MAPI: MessengerApi<SBlock, NumberFor<SBlock>>,
{
    let messenger_api_version = runtime_version
        .api_version(&<dyn MessengerApi<SBlock, NumberFor<SBlock>> as RuntimeApiInfo>::ID)
        .ok_or(ApiError::Application(
            format!("Could not find `MessengerApi` api for block `{best_hash:?}`.").into(),
        ))?;

    extract_xdm_proof_state_roots_with_client::<MAPI, SBlock>(
        messenger_api_version,
        messenger_api,
        best_hash,
        ext,
    )
}

pub(crate) fn extract_xdm_proof_state_roots_with_client<MAPI, SBlock>(
    messenger_api_version: u32,
    messenger_api: &MAPI,
    best_hash: SBlock::Hash,
    ext: &SBlock::Extrinsic,
) -> Result<Option<ExtractedStateRoots<SBlock>>, ApiError>
where
    SBlock: BlockT,
    MAPI: MessengerApi<SBlock, NumberFor<SBlock>>,
{
    if messenger_api_version >= 2 {
        // Calling latest version of MessengerApi
        messenger_api.extract_xdm_proof_state_roots(best_hash, ext.encode())
    } else {
        // Calling earlier versions of MessengerApi
        // Since there is only one version at the moment, we can directly call it without checking version, in future if more versions are added
        // we need more else if branches.
        #[allow(deprecated)]
        messenger_api.extract_xdm_proof_state_roots_before_version_2(best_hash, ext)
    }
}

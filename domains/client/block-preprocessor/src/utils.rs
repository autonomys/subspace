use crate::runtime_api::ExtractedStateRoots;
use codec::Encode;
use sp_api::{ApiError, ApiExt, BlockT, RuntimeApiInfo, RuntimeVersion};
use sp_messenger::MessengerApi;
use sp_runtime::traits::NumberFor;

fn call_extract_xdm_proof_state_roots<MAPI, SBlock>(
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

    call_extract_xdm_proof_state_roots::<MAPI, SBlock>(
        messenger_api_version,
        messenger_api,
        best_hash,
        ext,
    )
}

pub(crate) fn extract_xdm_proof_state_roots_with_client<API, SBlock>(
    runtime_api: &API,
    best_hash: SBlock::Hash,
    ext: &SBlock::Extrinsic,
) -> Result<Option<ExtractedStateRoots<SBlock>>, ApiError>
where
    SBlock: BlockT,
    API: MessengerApi<SBlock, NumberFor<SBlock>> + ApiExt<SBlock>,
{
    let messenger_api_version = runtime_api
        .api_version::<dyn MessengerApi<SBlock, NumberFor<SBlock>>>(best_hash)?
        .ok_or_else(|| {
            ApiError::Application(
                format!("Could not find `MessengerApi` api for block `{best_hash:?}`.").into(),
            )
        })?;

    call_extract_xdm_proof_state_roots::<API, SBlock>(
        messenger_api_version,
        runtime_api,
        best_hash,
        ext,
    )
}

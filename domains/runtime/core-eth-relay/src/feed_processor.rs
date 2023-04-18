use crate::{AccountId, FeedId, Runtime};
use codec::{Decode, Encode};
use frame_support::dispatch::{RawOrigin, TypeInfo};
use pallet_feeds::feed_processor::{FeedMetadata, FeedObjectMapping, FeedProcessor};
use snowbridge_ethereum_beacon_client::{
    FinalizedHeaderUpdateOf, HeaderUpdateOf, Pallet, SyncCommitteePeriodUpdateOf,
};
use sp_core::TypeId;
use sp_runtime::traits::AccountIdConversion;
use sp_runtime::DispatchError;
use sp_std::prelude::*;

/// A feed processor identifier. It is used by the feed processor to derive soverign account id
#[derive(Clone, Copy, Eq, PartialEq, Encode, Decode, TypeInfo)]
pub struct FeedProcessorId(pub [u8; 8]);

impl TypeId for FeedProcessorId {
    const TYPE_ID: [u8; 4] = *b"feed";
}

#[derive(Encode, Decode)]
pub struct FeedProcessorData<T: snowbridge_ethereum_beacon_client::Config> {
    pub sync_committee_update: Option<SyncCommitteePeriodUpdateOf<T>>,
    pub finalized_header_update: Option<FinalizedHeaderUpdateOf<T>>,
    pub header_update: Option<HeaderUpdateOf<T>>,
}

impl<T: snowbridge_ethereum_beacon_client::Config> FeedProcessorData<T> {
    /// checks if the feed data we got is valid or not.
    /// As of now, only constraint is at least one component need to be `Some`
    pub fn is_valid(&self) -> bool {
        self.sync_committee_update.is_some()
            || self.finalized_header_update.is_some()
            || self.header_update.is_some()
    }
}

/// Type representing implementation of the ethereum feed processor
struct EthereumFeedProcessorImpl {
    derived_account_id: AccountId,
}

impl EthereumFeedProcessorImpl {
    pub fn new(processor_id: FeedProcessorId) -> EthereumFeedProcessorImpl {
        EthereumFeedProcessorImpl {
            derived_account_id: processor_id.into_account_truncating(),
        }
    }
}

impl FeedProcessor<FeedId> for EthereumFeedProcessorImpl {
    fn put(&self, _feed_id: FeedId, object: &[u8]) -> Result<Option<FeedMetadata>, DispatchError> {
        let feed_data = FeedProcessorData::<Runtime>::decode(&mut &*object).map_err(|_e| {
            DispatchError::Other("unable to decode feed processor data in ethereum feed processor")
        })?;

        if !feed_data.is_valid() {
            return Err(DispatchError::Other("feed processor data is invalid"));
        }

        let mut maybe_metadata: Option<FeedMetadata> = None;

        // Indicating that this feed processor signed the request
        let feed_processor_origin = RawOrigin::Signed(self.derived_account_id.clone());

        if feed_data.sync_committee_update.is_some() {
            let sync_committee_period_update = feed_data
                .sync_committee_update
                .expect("already checked for Some variant; qed");

            Pallet::<Runtime>::sync_committee_period_update(
                feed_processor_origin.clone().into(),
                sync_committee_period_update,
            )?;
        }

        if feed_data.finalized_header_update.is_some() {
            let finalized_header_update = feed_data
                .finalized_header_update
                .expect("already checked for Some variant; qed");

            Pallet::<Runtime>::import_finalized_header(
                feed_processor_origin.clone().into(),
                finalized_header_update,
            )?;
        }

        if feed_data.header_update.is_some() {
            let header_update = feed_data
                .header_update
                .expect("already checked for Some variant; qed");

            maybe_metadata = Some(
                (
                    header_update.execution_header.block_hash,
                    header_update.execution_header.block_number,
                )
                    .encode(),
            );

            Pallet::<Runtime>::import_execution_header(
                feed_processor_origin.into(),
                header_update,
            )?;
        }

        Ok(maybe_metadata)
    }

    fn object_mappings(&self, _feed_id: FeedId, object: &[u8]) -> Vec<FeedObjectMapping> {
        let feed_data = match FeedProcessorData::<Runtime>::decode(&mut &*object) {
            Ok(feed_data) => feed_data,
            // we just return empty if we failed to decode as this is not called in runtime
            Err(_) => return vec![],
        };

        // If there is no header update in feed data, there is nothing to index.
        if feed_data.header_update.is_none() {
            return vec![];
        }

        let header_update = feed_data
            .header_update
            .expect("already checked for none; qed");

        // calculating header update offset as per the encoding size hints.
        // We are adding one to account for byte pushed at encoding to identify
        // `Option` enum variant.
        let maybe_header_update_offset = u32::try_from(
            feed_data.sync_committee_update.size_hint()
                + feed_data.finalized_header_update.size_hint()
                + 1,
        );

        // Type conversion failed this would mean size of data structure is too large
        // While this is unlikely, We should just return empty vec in that case.
        if maybe_header_update_offset.is_err() {
            return vec![];
        }

        let header_update_offset =
            maybe_header_update_offset.expect("already checked for error above; qed");

        // we send two mappings pointed to the same object
        // block height and block hash
        // this would be easier for sync client to crawl through the descendants by block height
        // if you already have a block hash, you can fetch the same block with it as well
        vec![
            FeedObjectMapping::Custom {
                key: header_update.execution_header.block_hash.encode(),
                offset: header_update_offset,
            },
            FeedObjectMapping::Custom {
                key: header_update.execution_header.block_number.encode(),
                offset: header_update_offset,
            },
        ]
    }
}

/// FeedProcessorId represents the available FeedProcessor impls
#[derive(Default, Debug, Clone, Copy, Encode, Decode, TypeInfo, Eq, PartialEq)]
pub enum FeedProcessorKind {
    /// Ethereum execution headers feed processor
    #[default]
    EthereumLike,
}

pub(crate) fn feed_processor(
    identity: FeedProcessorId,
    feed_processor_kind: FeedProcessorKind,
) -> Box<dyn FeedProcessor<FeedId>> {
    match feed_processor_kind {
        FeedProcessorKind::EthereumLike => Box::new(EthereumFeedProcessorImpl::new(identity)),
    }
}

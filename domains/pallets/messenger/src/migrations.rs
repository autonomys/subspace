//! Migration module for pallet-messenger
#[cfg(not(feature = "std"))]
extern crate alloc;
use crate::{Config, Pallet};
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use frame_support::migrations::VersionedMigration;
use frame_support::traits::UncheckedOnRuntimeUpgrade;
use frame_support::weights::Weight;
use sp_core::sp_std;
#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::vec::Vec;

pub type VersionCheckedMigrateDomainsV0ToV1<T> = VersionedMigration<
    0,
    1,
    VersionUncheckedMigrateV0ToV1<T>,
    Pallet<T>,
    <T as frame_system::Config>::DbWeight,
>;

pub struct VersionUncheckedMigrateV0ToV1<T>(sp_std::marker::PhantomData<T>);
impl<T: Config> UncheckedOnRuntimeUpgrade for VersionUncheckedMigrateV0ToV1<T> {
    fn on_runtime_upgrade() -> Weight {
        messenger_migration::migrate_messenger_storages::<T>()
    }
}

mod messenger_migration {
    use super::{BTreeMap, Vec};
    use crate::{
        BalanceOf, Config, InboxResponses as InboxResponsesNew, Outbox as OutboxNew,
        OutboxMessageCount, Pallet,
    };
    use frame_support::pallet_prelude::OptionQuery;
    use frame_support::weights::Weight;
    use frame_support::{storage_alias, Identity};
    use sp_core::Get;
    use sp_domains::{ChainId, ChannelId};
    use sp_messenger::messages::{Message, Nonce};

    #[storage_alias]
    pub(super) type InboxResponses<T: Config> = CountedStorageMap<
        Pallet<T>,
        Identity,
        (ChainId, ChannelId, Nonce),
        Message<BalanceOf<T>>,
        OptionQuery,
    >;

    #[storage_alias]
    pub(super) type Outbox<T: Config> = CountedStorageMap<
        Pallet<T>,
        Identity,
        (ChainId, ChannelId, Nonce),
        Message<BalanceOf<T>>,
        OptionQuery,
    >;

    pub(super) fn migrate_messenger_storages<T: Config>() -> Weight {
        let mut reads = 0;
        let mut writes = 0;
        let inbox_responses = InboxResponses::<T>::drain().collect::<Vec<_>>();
        inbox_responses.into_iter().for_each(|(key, msg)| {
            // we do one read from the old storage
            reads += 1;

            // we do one write to old storage and one write to new storage
            writes += 2;

            InboxResponsesNew::<T>::insert(key, msg);
        });

        let outbox = Outbox::<T>::drain().collect::<Vec<_>>();
        let mut outbox_count = BTreeMap::new();
        outbox.into_iter().for_each(|(key, msg)| {
            // we do one read from the old storage
            reads += 1;

            // we do one write to old storage and one write to new storage
            writes += 2;

            // total outbox count
            outbox_count
                .entry((key.0, key.1))
                .and_modify(|count| *count += 1)
                .or_insert(1);

            OutboxNew::<T>::insert(key, msg);
        });

        outbox_count.into_iter().for_each(|(key, count)| {
            // we do one write to the outbox message count
            writes += 1;
            OutboxMessageCount::<T>::insert(key, count);
        });

        T::DbWeight::get().reads_writes(reads, writes)
    }
}

#[cfg(test)]
mod tests {
    use crate::migrations::messenger_migration::{
        migrate_messenger_storages, InboxResponses, Outbox,
    };
    use crate::mock::chain_a::{new_test_ext, Runtime, SelfChainId};
    use crate::{InboxResponses as InboxResponsesNew, Outbox as OutboxNew, OutboxMessageCount};
    use frame_support::weights::RuntimeDbWeight;
    use sp_core::Get;
    use sp_domains::{ChainId, ChannelId};
    use sp_messenger::endpoint::{Endpoint, EndpointRequest};
    use sp_messenger::messages::{Message, Nonce, Payload, RequestResponse, VersionedPayload};

    #[test]
    fn test_messenger_storage_migration() {
        let mut ext = new_test_ext();
        let msg = Message {
            src_chain_id: ChainId::Consensus,
            dst_chain_id: SelfChainId::get(),
            channel_id: Default::default(),
            nonce: Default::default(),
            payload: VersionedPayload::V0(Payload::Endpoint(RequestResponse::Request(
                EndpointRequest {
                    src_endpoint: Endpoint::Id(0),
                    dst_endpoint: Endpoint::Id(0),
                    payload: vec![],
                },
            ))),
            last_delivered_message_response_nonce: None,
        };
        ext.execute_with(|| {
            // one inbox response
            InboxResponses::<Runtime>::insert(
                (ChainId::Consensus, ChannelId::zero(), Nonce::zero()),
                msg.clone(),
            );

            // outbox responses
            Outbox::<Runtime>::insert(
                (ChainId::Consensus, ChannelId::zero(), Nonce::zero()),
                msg.clone(),
            );
            Outbox::<Runtime>::insert(
                (ChainId::Consensus, ChannelId::zero(), Nonce::one()),
                msg.clone(),
            );
            Outbox::<Runtime>::insert(
                (ChainId::Consensus, ChannelId::one(), Nonce::zero()),
                msg.clone(),
            );
        });

        ext.commit_all().unwrap();

        ext.execute_with(|| {
            let weights = migrate_messenger_storages::<Runtime>();
            // 1 read and 2 writes for inbox response
            // 3 reads and 6 writes for outbox
            // 2 writes for Outbox message count
            let db_weights: RuntimeDbWeight = <Runtime as frame_system::Config>::DbWeight::get();
            assert_eq!(weights, db_weights.reads_writes(4, 10),);

            assert_eq!(
                InboxResponsesNew::<Runtime>::get((
                    ChainId::Consensus,
                    ChannelId::zero(),
                    Nonce::zero()
                )),
                Some(msg.clone())
            );

            assert_eq!(
                OutboxNew::<Runtime>::get((ChainId::Consensus, ChannelId::zero(), Nonce::zero())),
                Some(msg.clone())
            );

            assert_eq!(
                OutboxNew::<Runtime>::get((ChainId::Consensus, ChannelId::zero(), Nonce::one())),
                Some(msg.clone())
            );

            assert_eq!(
                OutboxNew::<Runtime>::get((ChainId::Consensus, ChannelId::one(), Nonce::zero())),
                Some(msg.clone())
            );

            assert_eq!(
                OutboxMessageCount::<Runtime>::get((ChainId::Consensus, ChannelId::zero())),
                2
            );

            assert_eq!(
                OutboxMessageCount::<Runtime>::get((ChainId::Consensus, ChannelId::one())),
                1
            );
        });
    }
}

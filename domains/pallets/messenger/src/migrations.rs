//! Migration module for pallet-messenger
#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::vec::Vec;

// TODO: remove post migration on taurus for both consensus and evm chain.
pub(crate) mod messenger_migration {
    use super::{BTreeMap, Vec};
    use crate::pallet::{InboxResponseMessageWeightTags, OutboxMessageWeightTags};
    use crate::{Config, Pallet};
    use frame_support::pallet_prelude::{Decode, Encode, OptionQuery, TypeInfo};
    use frame_support::storage_alias;
    use sp_domains::ChainId;
    use sp_messenger::messages::{MessageId, MessageWeightTag};

    #[storage_alias]
    pub(super) type MessageWeightTags<T: Config> = StorageValue<Pallet<T>, WeightTags, OptionQuery>;

    #[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
    pub(crate) struct WeightTags {
        pub(crate) outbox: BTreeMap<(ChainId, MessageId), MessageWeightTag>,
        pub(crate) inbox_responses: BTreeMap<(ChainId, MessageId), MessageWeightTag>,
    }

    pub(crate) fn migrate_message_weight_tags<T: Config>(count: u64) -> (u64, u64) {
        let mut reads = 0;
        let mut writes = 0;

        reads += 1;
        let Some(mut weight_tags) = MessageWeightTags::<T>::get() else {
            // nothing to process, exit
            return (reads, writes);
        };

        // migrate outbox weight tags
        while writes < count {
            match weight_tags.outbox.pop_first() {
                // no more weight tags in outbox
                None => break,
                Some(((chain_id, message_id), weight_tag)) => {
                    OutboxMessageWeightTags::<T>::insert((chain_id, message_id), weight_tag);
                    writes += 1;
                }
            }
        }

        // migrate inbox responses weight tags
        while writes < count {
            match weight_tags.inbox_responses.pop_first() {
                // no more weight tags in outbox
                None => break,
                Some(((chain_id, message_id), weight_tag)) => {
                    InboxResponseMessageWeightTags::<T>::insert((chain_id, message_id), weight_tag);
                    writes += 1;
                }
            }
        }

        writes += 1;
        if weight_tags.outbox.is_empty() && weight_tags.inbox_responses.is_empty() {
            MessageWeightTags::<T>::kill();
        } else {
            MessageWeightTags::<T>::set(Some(weight_tags));
        }

        (reads, writes)
    }

    pub(crate) fn remove_inbox_response_weight_tags<T: Config>(tags: Vec<(ChainId, MessageId)>) {
        let mut maybe_weight_tags = MessageWeightTags::<T>::get();
        tags.into_iter().for_each(|(chain_id, message_id)| {
            InboxResponseMessageWeightTags::<T>::remove((chain_id, message_id));
            if let Some(weight_tags) = maybe_weight_tags.as_mut() {
                weight_tags.inbox_responses.remove(&(chain_id, message_id));
            }
        });
        MessageWeightTags::<T>::set(maybe_weight_tags);
    }

    pub(crate) fn remove_outbox_weight_tag<T: Config>(tag: (ChainId, MessageId)) {
        if OutboxMessageWeightTags::<T>::contains_key(tag) {
            OutboxMessageWeightTags::<T>::remove(tag);
        } else {
            MessageWeightTags::<T>::mutate(|maybe_weight_tags| {
                if let Some(weight_tags) = maybe_weight_tags.as_mut() {
                    weight_tags.outbox.remove(&tag);
                }
            });
        }
    }

    pub(crate) fn get_weight_tags<T: Config>() -> WeightTags {
        let mut weight_tags = MessageWeightTags::<T>::get().unwrap_or_default();
        InboxResponseMessageWeightTags::<T>::iter().for_each(|(key, weight_tag)| {
            weight_tags.inbox_responses.insert(key, weight_tag);
        });

        OutboxMessageWeightTags::<T>::iter().for_each(|(key, weight_tag)| {
            weight_tags.outbox.insert(key, weight_tag);
        });

        weight_tags
    }
}

#[cfg(test)]
mod tests {
    use crate::migrations::messenger_migration::{
        migrate_message_weight_tags, MessageWeightTags, WeightTags,
    };
    use crate::mock::chain_a::{new_test_ext, Runtime};
    use crate::pallet::{InboxResponseMessageWeightTags, OutboxMessageWeightTags};
    use sp_domains::{ChainId, ChannelId};
    use sp_messenger::messages::{MessageWeightTag, Nonce};

    #[test]
    fn test_messenger_storage_migration() {
        let mut ext = new_test_ext();
        let chain_id = ChainId::Consensus;
        let channel_id = ChannelId::one();
        let weight_tag = MessageWeightTag::ProtocolChannelOpen;
        ext.execute_with(|| {
            let mut weight_tags = WeightTags::default();
            for nonce in 0..50 {
                weight_tags.outbox.insert(
                    (chain_id, (channel_id, Nonce::from(nonce))),
                    weight_tag.clone(),
                );

                weight_tags.inbox_responses.insert(
                    (chain_id, (channel_id, Nonce::from(nonce))),
                    weight_tag.clone(),
                );
            }

            MessageWeightTags::<Runtime>::set(Some(weight_tags));
        });
        ext.commit_all().unwrap();

        // migrate 50 outbox weight tags
        // should migrate all outbox weight tags
        ext.execute_with(|| {
            assert!(OutboxMessageWeightTags::<Runtime>::iter_keys()
                .collect::<Vec<_>>()
                .is_empty());
            assert!(InboxResponseMessageWeightTags::<Runtime>::iter_keys()
                .collect::<Vec<_>>()
                .is_empty());

            let (reads, writes) = migrate_message_weight_tags::<Runtime>(50);
            assert_eq!(reads, 1);
            // 50 migration writes and 1 write for previous storage
            assert_eq!(writes, 51);

            assert_eq!(
                OutboxMessageWeightTags::<Runtime>::iter_keys()
                    .collect::<Vec<_>>()
                    .len(),
                50
            );

            assert!(InboxResponseMessageWeightTags::<Runtime>::iter_keys()
                .collect::<Vec<_>>()
                .is_empty());
            assert!(MessageWeightTags::<Runtime>::exists())
        });
        ext.commit_all().unwrap();

        // migrate 50 inbox response weight tags
        // should migrate all weight tags
        ext.execute_with(|| {
            assert_eq!(
                OutboxMessageWeightTags::<Runtime>::iter_keys()
                    .collect::<Vec<_>>()
                    .len(),
                50
            );
            assert!(InboxResponseMessageWeightTags::<Runtime>::iter_keys()
                .collect::<Vec<_>>()
                .is_empty());

            assert!(MessageWeightTags::<Runtime>::exists());

            let (reads, writes) = migrate_message_weight_tags::<Runtime>(50);
            assert_eq!(reads, 1);
            // 50 migration writes and 1 write for previous storage
            assert_eq!(writes, 51);

            assert_eq!(
                OutboxMessageWeightTags::<Runtime>::iter_keys()
                    .collect::<Vec<_>>()
                    .len(),
                50
            );

            assert_eq!(
                InboxResponseMessageWeightTags::<Runtime>::iter_keys()
                    .collect::<Vec<_>>()
                    .len(),
                50
            );
            assert!(!MessageWeightTags::<Runtime>::exists());
        });
        ext.commit_all().unwrap();
    }
}

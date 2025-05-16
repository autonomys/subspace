//! Migration module for pallet-messenger

#[cfg(not(feature = "std"))]
extern crate alloc;
use crate::migrations::v1_to_v2::migrate_channels::migrate_channels;
use crate::{BalanceOf, Channels as ChannelStorageV1, Config, Pallet};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::marker::PhantomData;
use frame_support::migrations::VersionedMigration;
use frame_support::pallet_prelude::{Decode, Encode, OptionQuery, TypeInfo};
use frame_support::traits::UncheckedOnRuntimeUpgrade;
use frame_support::weights::Weight;
use frame_support::{Identity, storage_alias};
use sp_domains::{ChainId, ChannelId};
use sp_messenger::messages::{Channel as ChannelV1, ChannelState, Nonce};

pub type VersionCheckedMigrateDomainsV1ToV2<T> = VersionedMigration<
    1,
    2,
    VersionUncheckedMigrateV1ToV2<T>,
    Pallet<T>,
    <T as frame_system::Config>::DbWeight,
>;

pub struct VersionUncheckedMigrateV1ToV2<T>(PhantomData<T>);
impl<T: Config> UncheckedOnRuntimeUpgrade for VersionUncheckedMigrateV1ToV2<T> {
    fn on_runtime_upgrade() -> Weight {
        migrate_channels::<T>()
    }
}

/// Fee model to send a request and receive a response from another chain.
#[derive(Default, Debug, Encode, Decode, Clone, Copy, Eq, PartialEq, TypeInfo)]
pub struct FeeModel<Balance> {
    /// Fee to relay message from one chain to another
    pub relay_fee: Balance,
}

#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
struct Channel<Balance, AccountId> {
    /// Channel identifier.
    pub channel_id: ChannelId,
    /// State of the channel.
    pub state: ChannelState,
    /// Next inbox nonce.
    pub next_inbox_nonce: Nonce,
    /// Next outbox nonce.
    pub next_outbox_nonce: Nonce,
    /// Latest outbox message nonce for which response was received from dst_chain.
    pub latest_response_received_message_nonce: Option<Nonce>,
    /// Maximum outgoing non-delivered messages.
    pub max_outgoing_messages: u32,
    /// Fee model for this channel between the chains.
    pub fee: FeeModel<Balance>,
    /// Owner of the channel
    /// Owner maybe None if the channel was initiated on the other chain.
    pub maybe_owner: Option<AccountId>,
    /// The amount of funds put on hold by the owner account for this channel
    pub channel_reserve_fee: Balance,
}

impl<Balance, AccountId> From<Channel<Balance, AccountId>> for ChannelV1<Balance, AccountId> {
    fn from(value: Channel<Balance, AccountId>) -> Self {
        ChannelV1 {
            channel_id: value.channel_id,
            state: value.state,
            next_inbox_nonce: value.next_inbox_nonce,
            next_outbox_nonce: value.next_outbox_nonce,
            latest_response_received_message_nonce: value.latest_response_received_message_nonce,
            max_outgoing_messages: value.max_outgoing_messages,
            maybe_owner: value.maybe_owner,
            channel_reserve_fee: value.channel_reserve_fee,
        }
    }
}

pub(crate) mod migrate_channels {
    use super::*;
    use sp_messenger::messages::ChannelStateWithNonce;
    use sp_runtime::traits::Get;

    #[storage_alias]
    pub(super) type Channels<T: Config> = StorageDoubleMap<
        Pallet<T>,
        Identity,
        ChainId,
        Identity,
        ChannelId,
        Channel<BalanceOf<T>, <T as frame_system::Config>::AccountId>,
        OptionQuery,
    >;

    pub(super) fn migrate_channels<T: Config>() -> Weight {
        let mut count = 0;
        Channels::<T>::drain().for_each(|(chain_id, channel_id, channel)| {
            let channel_v1: ChannelV1<BalanceOf<T>, T::AccountId> = channel.into();
            ChannelStorageV1::<T>::insert(chain_id, channel_id, channel_v1);
            count += 1;
        });

        T::DbWeight::get().reads_writes(count, count)
    }

    pub(crate) fn get_channel<T: Config>(
        chain_id: ChainId,
        channel_id: ChannelId,
    ) -> Option<ChannelV1<BalanceOf<T>, T::AccountId>> {
        ChannelStorageV1::<T>::get(chain_id, channel_id).or_else(|| {
            Channels::<T>::get(chain_id, channel_id).map(|old_channel| old_channel.into())
        })
    }

    pub(crate) fn get_channels_and_states<T: Config>()
    -> Vec<(ChainId, ChannelId, ChannelStateWithNonce)> {
        let keys: Vec<(ChainId, ChannelId)> = ChannelStorageV1::<T>::iter_keys().collect();
        keys.into_iter()
            .filter_map(|(chain_id, channel_id)| {
                get_channel::<T>(chain_id, channel_id).map(|channel| {
                    let state = channel.state;
                    let state_with_nonce = match state {
                        ChannelState::Initiated => ChannelStateWithNonce::Initiated,
                        ChannelState::Open => ChannelStateWithNonce::Open,
                        ChannelState::Closed => ChannelStateWithNonce::Closed {
                            next_outbox_nonce: channel.next_outbox_nonce,
                            next_inbox_nonce: channel.next_inbox_nonce,
                        },
                    };

                    (chain_id, channel_id, state_with_nonce)
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::migrate_channels::Channels;
    use super::*;
    use crate::mock::chain_a::{Runtime, new_test_ext};
    use frame_support::weights::RuntimeDbWeight;
    use sp_runtime::traits::Get;

    #[test]
    fn test_channel_migration() {
        let mut ext = new_test_ext();
        let chain_id = ChainId::Consensus;
        let channel_id = ChannelId::zero();
        let channel = Channel {
            channel_id,
            state: ChannelState::Open,
            next_inbox_nonce: Nonce::zero(),
            next_outbox_nonce: Nonce::one(),
            latest_response_received_message_nonce: Some(Nonce::from(100u32)),
            max_outgoing_messages: 100,
            fee: FeeModel { relay_fee: 100 },
            maybe_owner: Some(100u64),
            channel_reserve_fee: 200,
        };

        let channel_v1 = ChannelV1 {
            channel_id,
            state: ChannelState::Open,
            next_inbox_nonce: Nonce::zero(),
            next_outbox_nonce: Nonce::one(),
            latest_response_received_message_nonce: Some(Nonce::from(100u32)),
            max_outgoing_messages: 100,
            maybe_owner: Some(100u64),
            channel_reserve_fee: 200,
        };

        ext.execute_with(|| Channels::<Runtime>::insert(chain_id, channel_id, channel));

        ext.commit_all().unwrap();

        ext.execute_with(|| {
            let weight = migrate_channels::<Runtime>();
            let channel = ChannelStorageV1::<Runtime>::get(chain_id, channel_id).unwrap();
            let db_weights: RuntimeDbWeight = <Runtime as frame_system::Config>::DbWeight::get();
            assert_eq!(weight, db_weights.reads_writes(1, 1),);
            assert_eq!(channel, channel_v1);
        })
    }
}

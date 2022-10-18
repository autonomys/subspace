//! Relayer specific functionality

use crate::{Config, Decode, Encode, Error, Event, Pallet, Relayers, RelayersInfo, TypeInfo};
use frame_support::ensure;
use frame_support::traits::ReservableCurrency;
use sp_runtime::traits::Get;
use sp_runtime::DispatchResult;

/// Relayer address to which rewards are paid.
pub type RelayerId<T> = <T as frame_system::Config>::AccountId;

/// Type that holds relayer details within this domain.
#[derive(Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo, Copy)]
pub struct RelayerInfo<AccountId, Balance> {
    /// Someone who owns this relayer.
    pub owner: AccountId,
    /// Amount deposited to become a relayer.
    pub deposit_reserved: Balance,
}

impl<T: Config> Pallet<T> {
    /// Reserve the deposit and add a new relayer to the relayer set.
    pub(crate) fn do_join_relayer_set(
        owner: T::AccountId,
        relayer_id: RelayerId<T>,
    ) -> DispatchResult {
        // ensure relayer is not already relaying.
        ensure!(
            !RelayersInfo::<T>::contains_key(&relayer_id),
            Error::<T>::AlreadyRelayer
        );

        // reserve the deposit
        T::Currency::reserve(&owner, T::RelayerDeposit::get())?;

        // add the relayer to the pool
        RelayersInfo::<T>::insert(
            relayer_id.clone(),
            RelayerInfo {
                owner: owner.clone(),
                deposit_reserved: T::RelayerDeposit::get(),
            },
        );

        // append relayer_id to the list
        Relayers::<T>::mutate(|relayers| -> DispatchResult {
            relayers
                .try_push(relayer_id.clone())
                .map_err(|_| Error::<T>::MaximumRelayerCount.into())
        })?;

        Self::deposit_event(Event::<T>::RelayerJoined { owner, relayer_id });
        Ok(())
    }
}

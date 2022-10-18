//! Relayer specific functionality

use crate::{
    Config, Decode, Encode, Error, Event, NextRelayerIdx, Pallet, Relayers, RelayersInfo, TypeInfo,
};
use frame_support::ensure;
use frame_support::traits::ReservableCurrency;
use sp_runtime::traits::Get;
use sp_runtime::{ArithmeticError, DispatchError, DispatchResult};

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

    pub(crate) fn next_relayer() -> Result<RelayerId<T>, DispatchError> {
        let relayers = Relayers::<T>::get();
        if relayers.is_empty() {
            return Err(Error::<T>::NoRelayersToAssign.into());
        }

        // pick the next relayer_id
        let next_relayer_idx = NextRelayerIdx::<T>::get() as usize % relayers.len();
        let relayer_id = relayers
            .get(next_relayer_idx)
            .expect("should always be present due to modulus above")
            .to_owned();

        // update next relayer index
        let next_relayer_idx = next_relayer_idx
            .checked_add(1)
            .ok_or(DispatchError::Arithmetic(ArithmeticError::Overflow))?;
        NextRelayerIdx::<T>::put(next_relayer_idx as u32);

        Ok(relayer_id)
    }
}

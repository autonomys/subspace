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

    /// Selects the next relayer that needs to relay a message.
    /// Relayer is selected using round robin selection.
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

    /// Unreserve the deposit and remove relayer to the relayer set.
    /// Also adjust the next relayer index so that we wont skip any relayer due to relayer exit.
    pub(crate) fn do_exit_relayer_set(
        caller: T::AccountId,
        relayer_id: RelayerId<T>,
    ) -> DispatchResult {
        // ensure relayer is in the set.
        let relayer = RelayersInfo::<T>::take(relayer_id.clone()).ok_or(Error::<T>::NotRelayer)?;

        // ensure caller is the owner of the relayer
        ensure!(relayer.owner == caller, Error::<T>::NotOwner);

        // release the deposit
        T::Currency::unreserve(&caller, relayer.deposit_reserved);

        // remove relayer_id from the list
        let idx = Relayers::<T>::mutate(|relayers| -> Result<usize, DispatchError> {
            let idx = relayers
                .into_iter()
                .position(|id| *id == relayer_id.clone())
                .expect("should be present due existence of RelayerInfo");
            relayers.remove(idx);
            Ok(idx)
        })?;

        // if the existed relayer index is >= next_relayer_idx,
        // we do not need to shift the next_index.
        // but if the idx is less than next_idx,
        // then we need to adjust the index so that so we wont miss any relayer in the round robin.
        let mut next_relayer_idx = NextRelayerIdx::<T>::get();
        if idx < next_relayer_idx as usize {
            next_relayer_idx = next_relayer_idx
                .checked_sub(1)
                .ok_or(DispatchError::Arithmetic(ArithmeticError::Underflow))?;
            NextRelayerIdx::<T>::put(next_relayer_idx)
        }

        Self::deposit_event(Event::<T>::RelayerExited {
            owner: caller,
            relayer_id,
        });
        Ok(())
    }
}

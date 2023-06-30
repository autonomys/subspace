//! Staking for domains

use crate::pallet::{DomainStakingSummary, NextOperatorId, OperatorIdOwner, OperatorPools};
use crate::{BalanceOf, Config, FreezeIdentifier};
use codec::{Decode, Encode};
use frame_support::traits::fungible::{InspectFreeze, MutateFreeze};
use frame_support::{ensure, PalletError};
use scale_info::TypeInfo;
use sp_core::Get;
use sp_domains::{DomainId, EpochIndex, ExecutorPublicKey, OperatorId};
use sp_runtime::traits::Zero;
use sp_runtime::Percent;
use sp_std::collections::btree_map::BTreeMap;
use sp_std::vec;
use sp_std::vec::Vec;

/// Type that represents an operator pool details.
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct OperatorPool<Balance, NominatorId> {
    pub signing_key: ExecutorPublicKey,
    pub current_domain_id: DomainId,
    pub minimum_nominator_stake: Balance,
    pub nomination_tax: Percent,
    /// Total active stake for the current pool.
    pub current_total_stake: Balance,
    /// Total stake for the current pool in the next epoch.
    pub next_total_stake: Balance,
    /// Total shares of the nominators and the operator in this pool.
    pub total_shares: Balance,
    pub is_frozen: bool,
    /// Nominators under this operator pool.
    pub nominators: BTreeMap<NominatorId, Nominator<Balance>>,
    /// Pending transfers that will take effect in the next epoch.
    pub pending_transfers: Vec<PendingTransfer<NominatorId, Balance>>,
}

/// Type that represents an nominator details under a specific operator pool
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct Nominator<Balance> {
    pub shares: Balance,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum Transfer<Balance> {
    Withdraw(Balance),
    Deposit(Balance),
}

/// Type that represents a pending transfer
#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct PendingTransfer<NominatorId, Balance> {
    pub nominator_id: NominatorId,
    pub transfer: Transfer<Balance>,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct StakingSummary<OperatorId, Balance> {
    /// Current epoch index for the domain.
    pub current_epoch_index: EpochIndex,
    /// Total active stake for the current epoch.
    pub current_total_stake: Balance,
    /// Total stake for the next epoch.
    pub next_total_stake: Balance,
    /// Current operators for this epoch
    pub current_operators: Vec<OperatorId>,
    /// Operators for the next epoch.
    pub next_operators: Vec<OperatorId>,
}

#[derive(TypeInfo, Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub struct OperatorConfig<Balance> {
    pub signing_key: ExecutorPublicKey,
    pub minimum_nominator_stake: Balance,
    pub nomination_tax: Percent,
}

#[derive(TypeInfo, Encode, Decode, PalletError, Debug, PartialEq)]
pub enum Error {
    MaxOperatorId,
    DomainNotInitialized,
    InsufficientBalance,
    BalanceFreeze,
    MinimumOperatorStake,
}

pub(crate) fn do_register_operator<T: Config>(
    operator_owner: T::AccountId,
    domain_id: DomainId,
    amount: BalanceOf<T>,
    config: OperatorConfig<BalanceOf<T>>,
) -> Result<OperatorId, Error> {
    DomainStakingSummary::<T>::try_mutate(domain_id, |maybe_domain_stake_summary| {
        let operator_id = NextOperatorId::<T>::get();
        let next_operator_id = operator_id.checked_add(1).ok_or(Error::MaxOperatorId)?;
        NextOperatorId::<T>::set(next_operator_id);

        OperatorIdOwner::<T>::insert(operator_id, operator_owner.clone());

        // reserve stake balance
        ensure!(
            amount >= T::MinOperatorStake::get(),
            Error::MinimumOperatorStake
        );

        ensure!(
            T::Currency::balance_freezable(&operator_owner) >= amount,
            Error::InsufficientBalance
        );

        T::Currency::set_freeze(
            &T::FreezeIdentifier::staking_freeze_id(),
            &operator_owner,
            amount,
        )
        .map_err(|_| Error::BalanceFreeze)?;

        let domain_stake_summary = maybe_domain_stake_summary
            .as_mut()
            .ok_or(Error::DomainNotInitialized)?;

        let OperatorConfig {
            signing_key,
            minimum_nominator_stake,
            nomination_tax,
        } = config;

        let operator = OperatorPool {
            signing_key,
            current_domain_id: domain_id,
            minimum_nominator_stake,
            nomination_tax,
            current_total_stake: Zero::zero(),
            next_total_stake: Zero::zero(),
            total_shares: Zero::zero(),
            is_frozen: false,
            nominators: BTreeMap::new(),
            pending_transfers: vec![PendingTransfer {
                nominator_id: operator_owner,
                transfer: Transfer::Deposit(amount),
            }],
        };
        OperatorPools::<T>::insert(operator_id, operator);
        // update stake summary to include new operator for next epoch
        domain_stake_summary.next_operators.push(operator_id);

        Ok(operator_id)
    })
}

#[cfg(test)]
mod tests {
    use crate::pallet::{DomainStakingSummary, NextOperatorId, OperatorIdOwner, OperatorPools};
    use crate::staking::{OperatorConfig, PendingTransfer, StakingSummary, Transfer};
    use crate::tests::{new_test_ext, RuntimeOrigin, Test};
    use frame_support::assert_ok;
    use frame_support::traits::fungible::Mutate;
    use sp_core::{Pair, U256};
    use sp_domains::{DomainId, ExecutorPair};
    use subspace_runtime_primitives::SSC;

    type Balances = pallet_balances::Pallet<Test>;
    type Domains = crate::Pallet<Test>;

    #[test]
    fn register_operator() {
        let domain_id = DomainId::new(0);
        let operator_account = 1;
        let operator_free_balance = 1500 * SSC;
        let operator_stake = 1000 * SSC;
        let pair = ExecutorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            Balances::set_balance(&operator_account, operator_free_balance);
            assert!(Balances::usable_balance(operator_account) == operator_free_balance);

            DomainStakingSummary::<Test>::insert(
                domain_id,
                StakingSummary {
                    current_epoch_index: 0,
                    current_total_stake: 0,
                    next_total_stake: 0,
                    current_operators: vec![],
                    next_operators: vec![],
                },
            );

            let operator_config = OperatorConfig {
                signing_key: pair.public(),
                minimum_nominator_stake: 0,
                nomination_tax: Default::default(),
            };

            let res = Domains::register_operator(
                RuntimeOrigin::signed(operator_account),
                domain_id,
                operator_stake,
                operator_config,
            );
            assert_ok!(res);

            assert_eq!(NextOperatorId::<Test>::get(), 1);
            // operator_id should be 0 and be registered
            assert_eq!(OperatorIdOwner::<Test>::get(0).unwrap(), operator_account);
            let operator_pool = OperatorPools::<Test>::get(0).unwrap();
            assert_eq!(
                operator_pool.pending_transfers[0],
                PendingTransfer {
                    nominator_id: operator_account,
                    transfer: Transfer::Deposit(operator_stake),
                }
            );

            assert_eq!(
                Balances::usable_balance(operator_account),
                operator_free_balance - operator_stake
            );
        });
    }
}

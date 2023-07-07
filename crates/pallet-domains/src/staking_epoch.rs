//! Staking epoch transition for domain
#![allow(dead_code)]

use crate::pallet::{DomainStakingSummary, Operators, PendingOperatorSwitches};
use crate::Config;
use frame_support::log::error;
use sp_domains::{DomainId, OperatorId};

#[derive(Debug)]
enum Error {
    MissingOperator,
    OperatorFrozen,
    MissingDomainStakeSummary,
}

/// Add all the switched operators to new domain.
pub(crate) fn do_finalize_switch_operator_domain<T: Config>(domain_id: DomainId) {
    if let Some(operators) = PendingOperatorSwitches::<T>::take(domain_id) {
        for operator_id in operators {
            if let Err(err) = switch_operator::<T>(operator_id) {
                error!("Failed to switch operator[{operator_id:?}]: {err:?}",)
            }
        }
    }
}

fn switch_operator<T: Config>(operator_id: OperatorId) -> Result<(), Error> {
    Operators::<T>::try_mutate(operator_id, |maybe_operator| {
        let operator = maybe_operator.as_mut().ok_or(Error::MissingOperator)?;

        if operator.is_frozen {
            return Err(Error::OperatorFrozen);
        }

        operator.current_domain_id = operator.next_domain_id;
        DomainStakingSummary::<T>::try_mutate(operator.current_domain_id, |maybe_stake_summary| {
            let stake_summary = maybe_stake_summary
                .as_mut()
                .ok_or(Error::MissingDomainStakeSummary)?;

            stake_summary.next_operators.push(operator_id);

            Ok(())
        })
    })
}

#[cfg(test)]
mod tests {
    use crate::pallet::{
        DomainStakingSummary, OperatorIdOwner, Operators, PendingOperatorSwitches,
    };
    use crate::staking::{Operator, StakingSummary};
    use crate::staking_epoch::do_finalize_switch_operator_domain;
    use crate::tests::{new_test_ext, Test};
    use sp_core::{Pair, U256};
    use sp_domains::{DomainId, OperatorPair};
    use sp_runtime::traits::Zero;
    use subspace_runtime_primitives::SSC;

    type Balances = pallet_balances::Pallet<Test>;
    type Domains = crate::Pallet<Test>;

    #[test]
    fn finalize_operator_domain_switch() {
        let old_domain_id = DomainId::new(0);
        let new_domain_id = DomainId::new(1);
        let operator_account = 1;
        let operator_id = 1;
        let pair = OperatorPair::from_seed(&U256::from(0u32).into());

        let mut ext = new_test_ext();
        ext.execute_with(|| {
            DomainStakingSummary::<Test>::insert(
                new_domain_id,
                StakingSummary {
                    current_epoch_index: 0,
                    current_total_stake: 0,
                    current_operators: vec![],
                    next_operators: vec![],
                },
            );

            OperatorIdOwner::<Test>::insert(operator_id, operator_account);
            Operators::<Test>::insert(
                operator_id,
                Operator {
                    signing_key: pair.public(),
                    current_domain_id: old_domain_id,
                    next_domain_id: new_domain_id,
                    minimum_nominator_stake: 100 * SSC,
                    nomination_tax: Default::default(),
                    current_total_stake: Zero::zero(),
                    current_epoch_rewards: Zero::zero(),
                    total_shares: Zero::zero(),
                    is_frozen: false,
                },
            );

            PendingOperatorSwitches::<Test>::append(old_domain_id, operator_id);
            do_finalize_switch_operator_domain::<Test>(old_domain_id);

            let operator = Operators::<Test>::get(operator_id).unwrap();
            assert_eq!(operator.current_domain_id, new_domain_id);
            assert_eq!(operator.next_domain_id, new_domain_id);
            assert_eq!(PendingOperatorSwitches::<Test>::get(old_domain_id), None);

            let domain_stake_summary = DomainStakingSummary::<Test>::get(new_domain_id).unwrap();
            assert!(domain_stake_summary.next_operators.contains(&operator_id));
        });
    }
}

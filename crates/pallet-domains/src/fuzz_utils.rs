// Copyright 2025 Security Research Labs GmbH
// Permission to use, copy, modify, and/or distribute this software for
// any purpose with or without fee is hereby granted.
//
// THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL
// WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE
// FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
// DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
// AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
// OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use alloc::collections::BTreeSet;
use frame_system::Account;
use pallet_balances::{Holds, TotalIssuance};
use sp_core::H256;
use sp_domains::{DomainId, OperatorId};
use sp_runtime::traits::One;

use crate::staking::{
    Operator, OperatorStatus, SharePrice, mark_invalid_bundle_author, unmark_invalid_bundle_author,
};
use crate::staking_epoch::do_finalize_domain_current_epoch;
use crate::{
    BalanceOf, Config, DeactivatedOperators, Deposits, DeregisteredOperators, DomainBlockNumberFor,
    DomainStakingSummary, HeadDomainNumber, InvalidBundleAuthors, Operators, PendingSlashes,
    ReceiptHashFor,
};

/// Fetch the next epoch's operators from the DomainStakingSummary
#[allow(clippy::type_complexity)]
pub fn get_next_operators<T: Config>(
    domain_id: DomainId,
) -> Vec<Operator<BalanceOf<T>, T::Share, DomainBlockNumberFor<T>, ReceiptHashFor<T>>> {
    let domain_summary = DomainStakingSummary::<T>::get(domain_id)
        .expect("invariant violated: We must have DomainStakingSummary");
    let mut prev_ops = vec![];
    for operator_id in &domain_summary.next_operators {
        let operator = Operators::<T>::get(*operator_id).expect(
            "invariant violated: Operator in next_operator set is not present in Operators",
        );
        prev_ops.push(operator)
    }
    prev_ops
}

/// Finalize the epoch and transition to the next one
pub fn conclude_domain_epoch<T: Config>(domain_id: DomainId) {
    let head_domain_number = HeadDomainNumber::<T>::get(domain_id);
    HeadDomainNumber::<T>::set(domain_id, head_domain_number + One::one());
    do_finalize_domain_current_epoch::<T>(domain_id)
        .expect("invariant violated: we must be able to finalize domain epoch");
}

/// Mark an operator as having produced an invalid bundle
pub fn fuzz_mark_invalid_bundle_authors<T: Config<DomainHash = H256>>(
    operator: OperatorId,
    domain_id: DomainId,
) -> Option<H256> {
    let pending_slashes = PendingSlashes::<T>::get(domain_id).unwrap_or_default();
    let mut invalid_bundle_authors_in_epoch = InvalidBundleAuthors::<T>::get(domain_id);
    let mut stake_summary = DomainStakingSummary::<T>::get(domain_id).unwrap();
    if pending_slashes.contains(&operator) {
        return None;
    }
    let er = H256::random();
    mark_invalid_bundle_author::<T>(
        operator,
        er,
        &mut stake_summary,
        &mut invalid_bundle_authors_in_epoch,
    )
    .expect("invariant violated: could not mark operator as invalid bundle author");
    DomainStakingSummary::<T>::insert(domain_id, stake_summary);
    InvalidBundleAuthors::<T>::insert(domain_id, invalid_bundle_authors_in_epoch);
    Some(er)
}

/// Unmark an operator as having produced an invalid bundle
pub fn fuzz_unmark_invalid_bundle_authors<T: Config<DomainHash = H256>>(
    domain_id: DomainId,
    operator: OperatorId,
    er: H256,
) {
    let pending_slashes = PendingSlashes::<T>::get(domain_id).unwrap_or_default();
    let mut invalid_bundle_authors_in_epoch = InvalidBundleAuthors::<T>::get(domain_id);
    let mut stake_summary = DomainStakingSummary::<T>::get(domain_id).unwrap();

    if pending_slashes.contains(&operator)
        || crate::Pallet::<T>::is_operator_pending_to_slash(domain_id, operator)
    {
        return;
    }

    unmark_invalid_bundle_author::<T>(
        operator,
        er,
        &mut stake_summary,
        &mut invalid_bundle_authors_in_epoch,
    )
    .expect("invariant violated: could not unmark operator as invalid bundle author");

    DomainStakingSummary::<T>::insert(domain_id, stake_summary);
    InvalidBundleAuthors::<T>::insert(domain_id, invalid_bundle_authors_in_epoch);
}

/// Fetch operators who are pending slashing
pub fn get_pending_slashes<T: Config>(domain_id: DomainId) -> BTreeSet<OperatorId> {
    PendingSlashes::<T>::get(domain_id).unwrap_or_default()
}

/// Check staking invariants before epoch finalization
pub fn check_invariants_before_finalization<T: Config>(domain_id: DomainId) {
    let domain_summary = DomainStakingSummary::<T>::get(domain_id).unwrap();
    // INVARIANT: all current_operators are registered and not slashed nor have invalid bundles
    for operator_id in &domain_summary.next_operators {
        let operator = Operators::<T>::get(*operator_id).unwrap();
        if !matches!(
            operator.status::<T>(*operator_id),
            OperatorStatus::Registered
        ) {
            panic!("operator set violated");
        }
    }
    // INVARIANT: No operator is common between DeactivatedOperator and DeregisteredOperator
    let deactivated_operators = DeactivatedOperators::<T>::get(domain_id);
    let deregistered_operators = DeregisteredOperators::<T>::get(domain_id);
    for operator_id in &deregistered_operators {
        assert!(deactivated_operators.contains(operator_id) == false);
    }
}

/// Check staking invariants after epoch finalization
#[allow(clippy::type_complexity)]
pub fn check_invariants_after_finalization<T: Config<Balance = u128, Share = u128>>(
    domain_id: DomainId,
    prev_ops: Vec<Operator<BalanceOf<T>, T::Share, DomainBlockNumberFor<T>, ReceiptHashFor<T>>>,
) {
    let domain_summary = DomainStakingSummary::<T>::get(domain_id).unwrap();
    for operator_id in domain_summary.current_operators.keys() {
        let operator = Operators::<T>::get(operator_id).unwrap();
        // INVARIANT: 0 < SharePrice < 1
        SharePrice::new::<T>(operator.current_total_shares, operator.current_total_stake)
            .expect("SharePrice to be present");
    }

    // INVARIANT: DeactivatedOperators is empty
    let deactivated_operators = DeactivatedOperators::<T>::get(domain_id);
    assert!(deactivated_operators.len() == 0);
    // INVARIANT: DeregisteredOperators is empty
    let deregistered_operators = DeregisteredOperators::<T>::get(domain_id);
    assert!(deregistered_operators.len() == 0);

    // INVARIANT: Total domain stake == accumulated operators' curent_stake.
    let aggregated_stake: BalanceOf<T> = domain_summary
        .current_operators
        .values()
        .fold(0, |acc, stake| acc.saturating_add(*stake));

    assert!(aggregated_stake == domain_summary.current_total_stake);
    // INVARIANT: all current_operators are registered and not slashed nor have invalid bundles
    for operator_id in domain_summary.current_operators.keys() {
        let operator = Operators::<T>::get(operator_id).unwrap();
        if !matches!(
            operator.status::<T>(*operator_id),
            OperatorStatus::Registered
        ) {
            panic!("operator set violated");
        }
        // INVARIANT: Shares add up
        let mut shares: T::Share = 0;
        for (operator, _nominator, deposit) in Deposits::<T>::iter() {
            if *operator_id == operator {
                shares += deposit.known.shares;
            }
        }
        assert!(shares <= operator.current_total_shares);
    }

    // INVARIANT: all operators which were part of the next operator set before finalization are present now
    assert_eq!(prev_ops.len(), domain_summary.current_operators.len());
}

/// Check general Substrate invariants that must always hold
pub fn check_general_invariants<
    T: Config<Balance = u128>
        + pallet_balances::Config<Balance = u128>
        + frame_system::Config<AccountData = pallet_balances::AccountData<u128>>,
>(
    initial_total_issuance: BalanceOf<T>,
) {
    // After execution of all blocks, we run invariants
    let mut counted_free: <T as pallet_balances::Config>::Balance = 0;
    let mut counted_reserved: <T as pallet_balances::Config>::Balance = 0;
    for (account, info) in Account::<T>::iter() {
        let consumers = info.consumers;
        let providers = info.providers;
        assert!(
            !(consumers > 0 && providers == 0),
            "Invalid account consumers or providers state"
        );
        counted_free += info.data.free;
        counted_reserved += info.data.reserved;
        let max_lock: <T as pallet_balances::Config>::Balance =
            pallet_balances::Locks::<T>::get(&account)
                .iter()
                .map(|l| l.amount)
                .max()
                .unwrap_or_default();
        assert_eq!(
            max_lock, info.data.frozen,
            "Max lock should be equal to frozen balance"
        );
        let sum_holds: <T as pallet_balances::Config>::Balance =
            Holds::<T>::get(&account).iter().map(|l| l.amount).sum();
        assert!(
            sum_holds <= info.data.reserved,
            "Sum of all holds ({sum_holds}) should be less than or equal to reserved balance {}",
            info.data.reserved
        );
    }
    let total_issuance = TotalIssuance::<T>::get();
    let counted_issuance = counted_free + counted_reserved;
    assert_eq!(total_issuance, counted_issuance);
    assert!(total_issuance >= initial_total_issuance);
}

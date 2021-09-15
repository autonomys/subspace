// Copyright (C) 2020-2021 Parity Technologies (UK) Ltd.
// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//!
//! An opt-in utility module for reporting equivocations.
//!
//! This module defines an offence type for PoC equivocations
//! and some utility traits to wire together:
//! - a system for reporting offences;
//! - a system for submitting unsigned transactions;
//! - a way to get the current block author;
//!
//! These can be used in an offchain context in order to submit equivocation
//! reporting extrinsics (from the client that's import PoC blocks).
//! And in a runtime context, so that the PoC pallet can validate the
//! equivocation proofs in the extrinsic and report the offences.
//!
//! IMPORTANT:
//! When using this module for enabling equivocation reporting it is required
//! that the `ValidateUnsigned` for the PoC pallet is used in the runtime
//! definition.
//!

use frame_support::traits::Get;
use sp_consensus_poc::offence::{Kind, Offence, OffenceError, ReportOffence};
use sp_consensus_poc::{EquivocationProof, FarmerId, Slot};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionPriority, TransactionSource, TransactionValidity,
    TransactionValidityError, ValidTransaction,
};
use sp_runtime::DispatchResult;
use sp_std::prelude::*;

use crate::{Call, Config, Pallet};

/// A trait with utility methods for handling equivocation reports in PoC.
/// The trait provides methods for reporting an offence triggered by a valid
/// equivocation report, checking the current block author (to declare as the
/// reporter), and also for creating and submitting equivocation report
/// extrinsics (useful only in offchain context).
pub trait HandleEquivocation<T: Config> {
    /// The longevity, in blocks, that the equivocation report is valid for. When using the staking
    /// pallet this should be equal to the bonding duration (in blocks, not eras).
    type ReportLongevity: Get<u64>;

    /// Report an offence proved by the given reporters.
    fn report_offence(offence: PoCEquivocationOffence<FarmerId>) -> Result<(), OffenceError>;

    /// Returns true if all of the offenders at the given time slot have already been reported.
    fn is_known_offence(offenders: &[FarmerId], time_slot: &Slot) -> bool;

    /// Create and dispatch an equivocation report extrinsic.
    fn submit_equivocation_report(
        equivocation_proof: EquivocationProof<T::Header>,
    ) -> DispatchResult;
}

impl<T: Config> HandleEquivocation<T> for () {
    type ReportLongevity = ();

    fn report_offence(_offence: PoCEquivocationOffence<FarmerId>) -> Result<(), OffenceError> {
        Ok(())
    }

    fn is_known_offence(_offenders: &[FarmerId], _time_slot: &Slot) -> bool {
        true
    }

    fn submit_equivocation_report(
        _equivocation_proof: EquivocationProof<T::Header>,
    ) -> DispatchResult {
        Ok(())
    }
}

/// Generic equivocation handler. This type implements `HandleEquivocation`
/// using existing subsystems that are part of frame (type bounds described
/// below) and will dispatch to them directly, it's only purpose is to wire all
/// subsystems together.
pub struct EquivocationHandler<R, L> {
    _phantom: sp_std::marker::PhantomData<(R, L)>,
}

impl<R, L> Default for EquivocationHandler<R, L> {
    fn default() -> Self {
        Self {
            _phantom: Default::default(),
        }
    }
}

impl<T, R, L> HandleEquivocation<T> for EquivocationHandler<R, L>
where
    T: Config + frame_system::offchain::SendTransactionTypes<Call<T>>,
    // A system for reporting offences after valid equivocation reports are
    // processed.
    R: ReportOffence<FarmerId, PoCEquivocationOffence<FarmerId>>,
    // The longevity (in blocks) that the equivocation report is valid for. When using the staking
    // pallet this should be the bonding duration.
    L: Get<u64>,
{
    type ReportLongevity = L;

    fn report_offence(offence: PoCEquivocationOffence<FarmerId>) -> Result<(), OffenceError> {
        R::report_offence(offence)
    }

    fn is_known_offence(offenders: &[FarmerId], time_slot: &Slot) -> bool {
        R::is_known_offence(offenders, time_slot)
    }

    fn submit_equivocation_report(
        equivocation_proof: EquivocationProof<T::Header>,
    ) -> DispatchResult {
        use frame_system::offchain::SubmitTransaction;

        let call = Call::report_equivocation(Box::new(equivocation_proof));

        match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
            Ok(()) => log::info!(
                target: "runtime::poc",
                "Submitted PoC equivocation report.",
            ),
            Err(e) => log::error!(
                target: "runtime::poc",
                "Error submitting equivocation report: {:?}",
                e,
            ),
        }

        Ok(())
    }
}

/// Methods for the `ValidateUnsigned` implementation:
/// It restricts calls to `report_equivocation` to local calls (i.e. extrinsics generated on this
/// node) or that already in a block. This guarantees that only block authors can include
/// equivocation reports.
impl<T: Config> Pallet<T> {
    pub fn validate_equivocation_report(
        source: TransactionSource,
        call: &Call<T>,
    ) -> TransactionValidity {
        if let Call::report_equivocation(equivocation_proof) = call {
            // Discard equivocation report not coming from the local node
            if !matches!(
                source,
                TransactionSource::Local | TransactionSource::InBlock
            ) {
                log::warn!(
                    target: "runtime::poc",
                    "Rejecting report equivocation extrinsic because it is not local/in-block.",
                );

                return InvalidTransaction::Call.into();
            }

            // check report staleness
            is_known_offence::<T>(equivocation_proof)?;

            let longevity =
                <T::HandleEquivocation as HandleEquivocation<T>>::ReportLongevity::get();

            ValidTransaction::with_tag_prefix("PoCEquivocation")
                // We assign the `(maximum - 1)` priority for any equivocation report (`-1` is
                // to make sure potential root block transactions are always included no matter
                // what).
                .priority(TransactionPriority::MAX - 1)
                // Only one equivocation report for the same offender at the same slot.
                .and_provides((
                    equivocation_proof.offender.clone(),
                    *equivocation_proof.slot,
                ))
                .longevity(longevity)
                // We don't propagate this. This can never be included on a remote node.
                .propagate(false)
                .build()
        } else {
            InvalidTransaction::Call.into()
        }
    }

    pub fn pre_dispatch_equivocation_report(
        call: &Call<T>,
    ) -> Result<(), TransactionValidityError> {
        if let Call::report_equivocation(equivocation_proof) = call {
            is_known_offence::<T>(equivocation_proof)
        } else {
            Err(InvalidTransaction::Call.into())
        }
    }
}

fn is_known_offence<T: Config>(
    equivocation_proof: &EquivocationProof<T::Header>,
) -> Result<(), TransactionValidityError> {
    // check if the offence has already been reported,
    // and if so then we can discard the report.
    if T::HandleEquivocation::is_known_offence(
        &[equivocation_proof.offender.clone()],
        &equivocation_proof.slot,
    ) {
        Err(InvalidTransaction::Stale.into())
    } else {
        Ok(())
    }
}

/// A PoC equivocation offence report.
///
/// When a validator released two or more blocks at the same slot.
pub struct PoCEquivocationOffence<FullIdentification> {
    /// A PoC slot in which this incident happened.
    pub slot: Slot,
    /// The authority that produced the equivocation.
    pub offender: FullIdentification,
}

impl<FullIdentification: Clone> Offence<FullIdentification>
    for PoCEquivocationOffence<FullIdentification>
{
    const ID: Kind = *b"poc:equivocation";
    type TimeSlot = Slot;

    fn offenders(&self) -> Vec<FullIdentification> {
        vec![self.offender.clone()]
    }

    fn time_slot(&self) -> Self::TimeSlot {
        self.slot
    }
}

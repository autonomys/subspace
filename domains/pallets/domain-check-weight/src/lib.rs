// Copyright (C) 2024 Subspace Labs, Inc.
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

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::dispatch::{DispatchInfo, PostDispatchInfo};
use frame_support::traits::Get;
use frame_system::limits::BlockWeights;
use frame_system::{Config, ConsumedWeight};
use scale_info::TypeInfo;
use sp_runtime::traits::{DispatchInfoOf, Dispatchable, PostDispatchInfoOf, SignedExtension};
use sp_runtime::transaction_validity::{TransactionValidity, TransactionValidityError};
use sp_runtime::DispatchResult;
use sp_weights::Weight;

/// Wrapper of [`frame_system::CheckWeight`]
///
/// It performs the same check as [`frame_system::CheckWeight`] except the `max_total/max_block` weight limit
/// check is removed from the `pre_dispatch/pre_dispatch_unsigned` because the total weight of a domain block
/// is based on probability instead of a hard limit.
#[derive(Encode, Decode, Clone, Eq, PartialEq, Default, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct CheckWeight<T: Config + Send + Sync>(core::marker::PhantomData<T>);

impl<T: Config + Send + Sync> CheckWeight<T>
where
    T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
{
    /// Creates new `SignedExtension` to check weight of the extrinsic.
    pub fn new() -> Self {
        Self(Default::default())
    }

    /// Check the block length and the max extrinsic weight and notes the new weight and length value.
    ///
    /// It is same as the [`frame_system::CheckWeight::do_pre_dispatch`] except the `max_total/max_block`
    /// weight limit check is removed.
    pub fn do_pre_dispatch(
        info: &DispatchInfoOf<T::RuntimeCall>,
        len: usize,
    ) -> Result<(), TransactionValidityError> {
        // Check the block lenght and the max extrinsic weight
        frame_system::CheckWeight::<T>::do_validate(info, len)?;

        let next_len = frame_system::Pallet::<T>::all_extrinsics_len().saturating_add(len as u32);

        let next_weight = {
            let all_weight = frame_system::Pallet::<T>::block_weight();
            let maximum_weight = T::BlockWeights::get();
            calculate_consumed_weight::<T::RuntimeCall>(&maximum_weight, all_weight, info, len)
        };

        frame_system::AllExtrinsicsLen::<T>::put(next_len);
        frame_system::BlockWeight::<T>::put(next_weight);

        Ok(())
    }
}

/// Calculate the new block weight value with the given extrinsic
fn calculate_consumed_weight<Call>(
    maximum_weight: &BlockWeights,
    mut all_weight: ConsumedWeight,
    info: &DispatchInfoOf<Call>,
    len: usize,
) -> ConsumedWeight
where
    Call: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
{
    // Also Consider extrinsic length as proof weight.
    let extrinsic_weight = info
        .weight
        .saturating_add(maximum_weight.get(info.class).base_extrinsic)
        .saturating_add(Weight::from_parts(0, len as u64));

    // Saturating add the weight
    all_weight.accrue(extrinsic_weight, info.class);

    all_weight
}

impl<T: Config + Send + Sync> SignedExtension for CheckWeight<T>
where
    T::RuntimeCall: Dispatchable<Info = DispatchInfo, PostInfo = PostDispatchInfo>,
{
    type AccountId = T::AccountId;
    type Call = T::RuntimeCall;
    type AdditionalSigned = ();
    type Pre = ();
    const IDENTIFIER: &'static str = "CheckWeight";

    fn additional_signed(&self) -> core::result::Result<(), TransactionValidityError> {
        Ok(())
    }

    fn pre_dispatch(
        self,
        _who: &Self::AccountId,
        _call: &Self::Call,
        info: &DispatchInfoOf<Self::Call>,
        len: usize,
    ) -> Result<(), TransactionValidityError> {
        Self::do_pre_dispatch(info, len)
    }

    fn validate(
        &self,
        _who: &Self::AccountId,
        _call: &Self::Call,
        info: &DispatchInfoOf<Self::Call>,
        len: usize,
    ) -> TransactionValidity {
        frame_system::CheckWeight::<T>::do_validate(info, len)
    }

    fn pre_dispatch_unsigned(
        _call: &Self::Call,
        info: &DispatchInfoOf<Self::Call>,
        len: usize,
    ) -> Result<(), TransactionValidityError> {
        Self::do_pre_dispatch(info, len)
    }

    fn validate_unsigned(
        _call: &Self::Call,
        info: &DispatchInfoOf<Self::Call>,
        len: usize,
    ) -> TransactionValidity {
        frame_system::CheckWeight::<T>::do_validate(info, len)
    }

    fn post_dispatch(
        pre: Option<Self::Pre>,
        info: &DispatchInfoOf<Self::Call>,
        post_info: &PostDispatchInfoOf<Self::Call>,
        len: usize,
        result: &DispatchResult,
    ) -> Result<(), TransactionValidityError> {
        <frame_system::CheckWeight<T> as SignedExtension>::post_dispatch(
            pre, info, post_info, len, result,
        )
    }
}

impl<T: Config + Send + Sync> core::fmt::Debug for CheckWeight<T> {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "CheckWeight")
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut core::fmt::Formatter) -> core::fmt::Result {
        Ok(())
    }
}

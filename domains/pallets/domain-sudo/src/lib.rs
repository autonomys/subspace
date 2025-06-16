// Copyright (C) 2023 Subspace Labs, Inc.
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

//! Pallet Domain sudo

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub use pallet::*;

#[frame_support::pallet]
mod pallet {
    #[cfg(not(feature = "std"))]
    use alloc::boxed::Box;
    use frame_support::dispatch::{GetDispatchInfo, RawOrigin};
    use frame_support::pallet_prelude::*;
    use frame_support::traits::UnfilteredDispatchable;
    use frame_system::ensure_none;
    use frame_system::pallet_prelude::OriginFor;
    use sp_domain_sudo::{INHERENT_IDENTIFIER, InherentError, InherentType, IntoRuntimeCall};

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type RuntimeCall: Parameter
            + UnfilteredDispatchable<RuntimeOrigin = Self::RuntimeOrigin>
            + GetDispatchInfo;
        type IntoRuntimeCall: IntoRuntimeCall<<Self as Config>::RuntimeCall>;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A sudo call just took place.
        Sudid {
            /// The result of the call made by the sudo user.
            sudo_result: DispatchResult,
        },
    }

    /// Pallet Domain Sudo
    #[pallet::pallet]
    #[pallet::without_storage_info]
    pub struct Pallet<T>(_);

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Calls the underlying RuntimeCall with Root origin.
        #[pallet::call_index(0)]
        #[pallet::weight({
            let dispatch_info = call.get_dispatch_info();
            (dispatch_info.call_weight.saturating_add(dispatch_info.extension_weight), DispatchClass::Mandatory)
        })]
        pub fn sudo(origin: OriginFor<T>, call: Box<<T as Config>::RuntimeCall>) -> DispatchResult {
            ensure_none(origin)?;

            let res = call.dispatch_bypass_filter(RawOrigin::Root.into());
            Self::deposit_event(Event::Sudid {
                sudo_result: res.map(|_| ()).map_err(|e| e.error),
            });

            Ok(())
        }
    }

    #[pallet::inherent]
    impl<T: Config> ProvideInherent for Pallet<T> {
        type Call = Call<T>;
        type Error = InherentError;
        const INHERENT_IDENTIFIER: InherentIdentifier = INHERENT_IDENTIFIER;

        fn create_inherent(data: &InherentData) -> Option<Self::Call> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Domain sudo inherent data not correctly encoded")
                .expect("Domain sudo inherent data must be provided");

            if let Some(encoded_call) = inherent_data.maybe_call {
                let call = Box::new(T::IntoRuntimeCall::runtime_call(encoded_call));
                Some(Call::sudo { call })
            } else {
                None
            }
        }

        fn is_inherent_required(data: &InherentData) -> Result<Option<Self::Error>, Self::Error> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Domain sudo inherent data not correctly encoded")
                .expect("Domain sudo inherent data must be provided");

            Ok(if inherent_data.maybe_call.is_none() {
                None
            } else {
                Some(InherentError::MissingRuntimeCall)
            })
        }

        fn check_inherent(call: &Self::Call, data: &InherentData) -> Result<(), Self::Error> {
            let inherent_data = data
                .get_data::<InherentType>(&INHERENT_IDENTIFIER)
                .expect("Domain sudo inherent data not correctly encoded")
                .expect("Domain sudo inherent data must be provided");

            if let Some(encoded_call) = inherent_data.maybe_call {
                let runtime_call = Box::new(T::IntoRuntimeCall::runtime_call(encoded_call));
                if let Call::sudo { call } = call
                    && call != &runtime_call
                {
                    return Err(InherentError::IncorrectRuntimeCall);
                }
            } else {
                return Err(InherentError::MissingRuntimeCall);
            }

            Ok(())
        }

        fn is_inherent(call: &Self::Call) -> bool {
            matches!(call, Call::sudo { .. })
        }
    }
}

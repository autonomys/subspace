// Copyright (C) 2019-2021 Parity Technologies (UK) Ltd.
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

//! Inherents for Subspace consensus

use sp_inherents::{Error, InherentData, InherentIdentifier};

use sp_std::result::Result;

/// The Subspace inherent identifier.
pub const INHERENT_IDENTIFIER: InherentIdentifier = *b"subspace";

/// The type of the Subspace inherent data.
pub type SubspaceInherentData = sp_consensus_slots::Slot;

/// Auxiliary trait to extract Subspace inherent data.
pub trait SubspaceInherentDataTrait {
    /// Get Subspace inherent data.
    fn subspace_inherent_data(&self) -> Result<Option<SubspaceInherentData>, Error>;

    /// Replace Subspace inherent data.
    fn replace_subspace_inherent_data(&mut self, new: SubspaceInherentData);
}

impl SubspaceInherentDataTrait for InherentData {
    fn subspace_inherent_data(&self) -> Result<Option<SubspaceInherentData>, Error> {
        self.get_data(&INHERENT_IDENTIFIER)
    }

    fn replace_subspace_inherent_data(&mut self, new: SubspaceInherentData) {
        self.replace_data(INHERENT_IDENTIFIER, &new);
    }
}

/// Provides the slot duration inherent data for Subspace.
// TODO: Remove in the future. https://github.com/paritytech/substrate/issues/8029
#[cfg(feature = "std")]
pub struct InherentDataProvider {
    slot: SubspaceInherentData,
}

#[cfg(feature = "std")]
impl InherentDataProvider {
    /// Create new inherent data provider from the given `slot`.
    pub fn new(slot: SubspaceInherentData) -> Self {
        Self { slot }
    }

    /// Creates the inherent data provider by calculating the slot from the given
    /// `timestamp` and `duration`.
    pub fn from_timestamp_and_duration(
        timestamp: sp_timestamp::Timestamp,
        duration: std::time::Duration,
    ) -> Self {
        let slot = SubspaceInherentData::from(
            (timestamp.as_duration().as_millis() / duration.as_millis()) as u64,
        );

        Self { slot }
    }

    /// Returns the `slot` of this inherent data provider.
    pub fn slot(&self) -> SubspaceInherentData {
        self.slot
    }
}

#[cfg(feature = "std")]
impl sp_std::ops::Deref for InherentDataProvider {
    type Target = SubspaceInherentData;

    fn deref(&self) -> &Self::Target {
        &self.slot
    }
}

#[cfg(feature = "std")]
#[async_trait::async_trait]
impl sp_inherents::InherentDataProvider for InherentDataProvider {
    fn provide_inherent_data(&self, inherent_data: &mut InherentData) -> Result<(), Error> {
        inherent_data.put_data(INHERENT_IDENTIFIER, &self.slot)
    }

    async fn try_handle_error(
        &self,
        _: &InherentIdentifier,
        _: &[u8],
    ) -> Option<Result<(), Error>> {
        // There is no error anymore
        None
    }
}

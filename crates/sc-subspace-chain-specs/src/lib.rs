// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Chain specification data structures tailored for Subspace.

mod utils;

use crate::utils::SerializableChainSpec;
use sc_chain_spec::{ChainSpecExtension, RuntimeGenesis};
use serde::{Deserialize, Serialize};

/// The extensions for the [`ConsensusChainSpec`].
#[derive(Serialize, Deserialize, ChainSpecExtension)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[serde(bound = "")]
pub struct ChainSpecExtensions<ExecutionGenesisConfig>
where
    ExecutionGenesisConfig: RuntimeGenesis + 'static,
{
    /// Chain spec of execution chain.
    pub execution_chain_spec: ExecutionChainSpec<ExecutionGenesisConfig>,
}

impl<ExecutionGenesisConfig> Clone for ChainSpecExtensions<ExecutionGenesisConfig>
where
    ExecutionGenesisConfig: RuntimeGenesis + 'static,
{
    fn clone(&self) -> Self {
        Self {
            execution_chain_spec: self.execution_chain_spec.clone(),
        }
    }
}

/// Specialized `ChainSpec` for the consensus runtime.
pub type ConsensusChainSpec<GenesisConfig, ExecutionGenesisConfig> =
    SerializableChainSpec<GenesisConfig, ChainSpecExtensions<ExecutionGenesisConfig>>;

/// Specialized `ChainSpec` for the execution runtime.
pub type ExecutionChainSpec<ExecutionGenesisConfig> = SerializableChainSpec<ExecutionGenesisConfig>;

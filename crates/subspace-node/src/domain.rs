// Copyright (C) 2023 Subspace Labs, Inc.
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

pub(crate) mod cli;
pub(crate) mod domain_instance_starter;
pub mod evm_chain_spec;

pub use self::cli::{DomainCli, Subcommand as DomainSubcommand};
pub use self::domain_instance_starter::{create_configuration, DomainInstanceStarter};
pub use evm_domain_runtime::AccountId as AccountId20;
use sc_executor::NativeExecutionDispatch;

/// EVM domain executor instance.
pub struct EVMDomainExecutorDispatch;

impl NativeExecutionDispatch for EVMDomainExecutorDispatch {
    #[cfg(feature = "runtime-benchmarks")]
    type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
    #[cfg(not(feature = "runtime-benchmarks"))]
    type ExtendHostFunctions = ();

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        evm_domain_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        evm_domain_runtime::native_version()
    }
}

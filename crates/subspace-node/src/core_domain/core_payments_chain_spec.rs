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

//! Secondary chain configurations.

use crate::chain_spec_utils::{chain_spec_properties, get_account_id_from_seed};
use core_payments_domain_runtime::{
    AccountId, BalancesConfig, GenesisConfig, SystemConfig, WASM_BINARY,
};
use sc_service::ChainType;
use sc_subspace_chain_specs::ExecutionChainSpec;
use sp_core::crypto::Ss58Codec;
use subspace_runtime_primitives::SSC;

pub type ChainSpec = ExecutionChainSpec<GenesisConfig>;

pub fn development_config() -> ExecutionChainSpec<GenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Development",
        // ID
        "core_payments_domain_dev",
        ChainType::Development,
        move || {
            testnet_genesis(vec![
                get_account_id_from_seed("Alice"),
                get_account_id_from_seed("Bob"),
                get_account_id_from_seed("Alice//stash"),
                get_account_id_from_seed("Bob//stash"),
            ])
        },
        vec![],
        None,
        None,
        None,
        Some(chain_spec_properties()),
        None,
    )
}

pub fn local_testnet_config() -> ExecutionChainSpec<GenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Local Testnet",
        // ID
        "core_payments_domain_local_testnet",
        ChainType::Local,
        move || {
            testnet_genesis(vec![
                get_account_id_from_seed("Alice"),
                get_account_id_from_seed("Bob"),
                get_account_id_from_seed("Charlie"),
                get_account_id_from_seed("Dave"),
                get_account_id_from_seed("Eve"),
                get_account_id_from_seed("Ferdie"),
                get_account_id_from_seed("Alice//stash"),
                get_account_id_from_seed("Bob//stash"),
                get_account_id_from_seed("Charlie//stash"),
                get_account_id_from_seed("Dave//stash"),
                get_account_id_from_seed("Eve//stash"),
                get_account_id_from_seed("Ferdie//stash"),
            ])
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        Some("template-local"),
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        None,
    )
}

pub fn gemini_3a_config() -> ExecutionChainSpec<GenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Subspace Gemini 3a Core Payments Domain",
        // ID
        "subspace_gemini_3a_core_payments_domain",
        ChainType::Local,
        move || {
            testnet_genesis(vec![
                // Genesis executor
                AccountId::from_ss58check("5Df6w8CgYY8kTRwCu8bjBsFu46fy4nFa61xk6dUbL6G4fFjQ")
                    .expect("Wrong executor account address"),
            ])
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        Some("subspace-gemini-3a-core-payments-domain"),
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        None,
    )
}

fn testnet_genesis(endowed_accounts: Vec<AccountId>) -> GenesisConfig {
    GenesisConfig {
        system: SystemConfig {
            code: WASM_BINARY
                .expect("WASM binary was not build, please build it!")
                .to_vec(),
        },
        transaction_payment: Default::default(),
        balances: BalancesConfig {
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, 1_000_000 * SSC))
                .collect(),
        },
    }
}

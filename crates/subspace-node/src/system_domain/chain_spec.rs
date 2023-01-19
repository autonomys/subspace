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

//! System domain configurations.

use crate::chain_spec_utils::{
    chain_spec_properties, get_account_id_from_seed, get_public_key_from_seed,
};
use domain_runtime_primitives::RelayerId;
use frame_support::weights::Weight;
use sc_service::ChainType;
use sc_subspace_chain_specs::ExecutionChainSpec;
use sp_core::crypto::Ss58Codec;
use sp_domains::ExecutorPublicKey;
use sp_runtime::Percent;
use subspace_core_primitives::crypto::blake2b_256_hash;
use subspace_runtime_primitives::SSC;
use system_domain_runtime::{
    AccountId, Balance, BalancesConfig, DomainRegistryConfig, ExecutorRegistryConfig,
    GenesisConfig, Hash, MessengerConfig, SudoConfig, SystemConfig, WASM_BINARY,
};

type DomainConfig = sp_domains::DomainConfig<Hash, Balance, Weight>;

pub fn development_config() -> ExecutionChainSpec<GenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Development",
        // ID
        "system_domain_dev",
        ChainType::Development,
        move || {
            testnet_genesis(
                vec![
                    get_account_id_from_seed("Alice"),
                    get_account_id_from_seed("Bob"),
                    get_account_id_from_seed("Alice//stash"),
                    get_account_id_from_seed("Bob//stash"),
                ],
                vec![(
                    get_account_id_from_seed("Alice"),
                    1_000 * SSC,
                    get_account_id_from_seed("Alice"),
                    get_public_key_from_seed::<ExecutorPublicKey>("Alice"),
                )],
                vec![(
                    get_account_id_from_seed("Alice"),
                    1_000 * SSC,
                    // TODO: proper genesis domain config
                    DomainConfig {
                        wasm_runtime_hash: blake2b_256_hash(
                            system_domain_runtime::CORE_PAYMENTS_WASM_BUNDLE,
                        )
                        .into(),
                        max_bundle_size: 1024 * 1024,
                        bundle_slot_probability: (1, 1),
                        max_bundle_weight: Weight::MAX,
                        min_operator_stake: 100 * SSC,
                    },
                    get_account_id_from_seed("Alice"),
                    Percent::one(),
                )],
                Some(get_account_id_from_seed("Alice")),
                vec![(
                    get_account_id_from_seed("Alice"),
                    get_account_id_from_seed("Alice"),
                )],
            )
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
        "system_domain_local_testnet",
        ChainType::Local,
        move || {
            testnet_genesis(
                vec![
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
                ],
                vec![(
                    get_account_id_from_seed("Alice"),
                    1_000 * SSC,
                    get_account_id_from_seed("Alice"),
                    get_public_key_from_seed::<ExecutorPublicKey>("Alice"),
                )],
                vec![(
                    get_account_id_from_seed("Alice"),
                    1_000 * SSC,
                    // TODO: proper genesis domain config
                    DomainConfig {
                        wasm_runtime_hash: blake2b_256_hash(
                            system_domain_runtime::CORE_PAYMENTS_WASM_BUNDLE,
                        )
                        .into(),
                        max_bundle_size: 1024 * 1024,
                        bundle_slot_probability: (1, 1),
                        max_bundle_weight: Weight::MAX,
                        min_operator_stake: 100 * SSC,
                    },
                    get_account_id_from_seed("Alice"),
                    Percent::one(),
                )],
                Some(get_account_id_from_seed("Alice")),
                vec![
                    (
                        get_account_id_from_seed("Alice"),
                        get_account_id_from_seed("Alice"),
                    ),
                    (
                        get_account_id_from_seed("Bob"),
                        get_account_id_from_seed("Bob"),
                    ),
                ],
            )
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

pub fn gemini_3c_config() -> ExecutionChainSpec<GenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Subspace Gemini 3c System Domain",
        // ID
        "subspace_gemini_3c_system_domain",
        ChainType::Local,
        move || {
            let sudo_account =
                AccountId::from_ss58check("5CXTmJEusve5ixyJufqHThmy4qUrrm6FyLCR7QfE4bbyMTNC")
                    .expect("Invalid Sudo account.");
            testnet_genesis(
                vec![
                    // Genesis executor
                    AccountId::from_ss58check("5Df6w8CgYY8kTRwCu8bjBsFu46fy4nFa61xk6dUbL6G4fFjQ")
                        .expect("Wrong executor account address"),
                ],
                vec![(
                    AccountId::from_ss58check("5Df6w8CgYY8kTRwCu8bjBsFu46fy4nFa61xk6dUbL6G4fFjQ")
                        .expect("Wrong executor account address"),
                    1_000 * SSC,
                    AccountId::from_ss58check("5FsxcczkSUnpqhcSgugPZsSghxrcKx5UEsRKL5WyPTL6SAxB")
                        .expect("Wrong executor reward address"),
                    ExecutorPublicKey::from_ss58check(
                        "5FuuXk1TL8DKQMvg7mcqmP8t9FhxUdzTcYC9aFmebiTLmASx",
                    )
                    .expect("Wrong executor public key"),
                )],
                vec![(
                    AccountId::from_ss58check("5Df6w8CgYY8kTRwCu8bjBsFu46fy4nFa61xk6dUbL6G4fFjQ")
                        .expect("Wrong executor account address"),
                    1_000 * SSC,
                    DomainConfig {
                        wasm_runtime_hash: blake2b_256_hash(
                            system_domain_runtime::CORE_PAYMENTS_WASM_BUNDLE,
                        )
                        .into(),
                        max_bundle_size: 4 * 1024 * 1024,
                        bundle_slot_probability: (1, 1),
                        max_bundle_weight: Weight::MAX,
                        min_operator_stake: 100 * SSC,
                    },
                    AccountId::from_ss58check("5Df6w8CgYY8kTRwCu8bjBsFu46fy4nFa61xk6dUbL6G4fFjQ")
                        .expect("Wrong executor account address"),
                    Percent::one(),
                )],
                Some(sudo_account),
                Default::default(),
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        Some("subspace-gemini-3c-system-domain"),
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        None,
    )
}

pub fn x_net_2_config() -> ExecutionChainSpec<GenesisConfig> {
    ExecutionChainSpec::from_genesis(
        // Name
        "Subspace X-Net 2 Execution",
        // ID
        "subspace_x_net_2a_execution",
        ChainType::Local,
        move || {
            testnet_genesis(
                vec![
                    // Genesis executor
                    AccountId::from_ss58check("5Df6w8CgYY8kTRwCu8bjBsFu46fy4nFa61xk6dUbL6G4fFjQ")
                        .expect("Wrong executor account address"),
                ],
                vec![(
                    AccountId::from_ss58check("5Df6w8CgYY8kTRwCu8bjBsFu46fy4nFa61xk6dUbL6G4fFjQ")
                        .expect("Wrong executor account address"),
                    1_000 * SSC,
                    AccountId::from_ss58check("5FsxcczkSUnpqhcSgugPZsSghxrcKx5UEsRKL5WyPTL6SAxB")
                        .expect("Wrong executor reward address"),
                    ExecutorPublicKey::from_ss58check(
                        "5FuuXk1TL8DKQMvg7mcqmP8t9FhxUdzTcYC9aFmebiTLmASx",
                    )
                    .expect("Wrong executor public key"),
                )],
                vec![(
                    get_account_id_from_seed("Alice"),
                    1_000 * SSC,
                    // TODO: proper genesis domain config
                    DomainConfig {
                        wasm_runtime_hash: blake2b_256_hash(
                            system_domain_runtime::CORE_PAYMENTS_WASM_BUNDLE,
                        )
                        .into(),
                        max_bundle_size: 1024 * 1024,
                        bundle_slot_probability: (1, 1),
                        max_bundle_weight: Weight::MAX,
                        min_operator_stake: 100 * SSC,
                    },
                    get_account_id_from_seed("Alice"),
                    Percent::one(),
                )],
                None,
                Default::default(),
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        Some("subspace-x-net-2a-execution"),
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        None,
    )
}

fn testnet_genesis(
    endowed_accounts: Vec<AccountId>,
    executors: Vec<(AccountId, Balance, AccountId, ExecutorPublicKey)>,
    domains: Vec<(AccountId, Balance, DomainConfig, AccountId, Percent)>,
    maybe_sudo_account: Option<AccountId>,
    relayers: Vec<(AccountId, RelayerId)>,
) -> GenesisConfig {
    GenesisConfig {
        system: SystemConfig {
            code: WASM_BINARY
                .expect("WASM binary was not build, please build it!")
                .to_vec(),
        },
        sudo: SudoConfig {
            // Assign network admin rights.
            key: maybe_sudo_account,
        },
        transaction_payment: Default::default(),
        balances: BalancesConfig {
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, 1_000_000 * SSC))
                .collect(),
        },
        executor_registry: ExecutorRegistryConfig {
            executors,
            slot_probability: (1, 1),
        },
        domain_registry: DomainRegistryConfig { domains },
        messenger: MessengerConfig { relayers },
    }
}

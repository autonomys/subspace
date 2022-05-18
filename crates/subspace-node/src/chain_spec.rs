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

//! Subspace chain configurations.

use crate::chain_spec_utils::{
    chain_spec_properties, get_account_id_from_seed, get_public_key_from_seed,
    SerializableChainSpec,
};
use crate::secondary_chain;
use crate::secondary_chain::chain_spec::ExecutionChainSpec;
use sc_chain_spec::ChainSpecExtension;
use sc_service::ChainType;
use sc_telemetry::TelemetryEndpoints;
use serde::{Deserialize, Serialize};
use sp_core::crypto::Ss58Codec;
use sp_executor::ExecutorId;
use subspace_runtime::{
    BalancesConfig, ExecutorConfig, GenesisConfig, SudoConfig, SystemConfig, VestingConfig,
    MILLISECS_PER_BLOCK, SSC, WASM_BINARY,
};
use subspace_runtime_primitives::{AccountId, Balance, BlockNumber};

const POLKADOT_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";
const SUBSPACE_TELEMETRY_URL: &str = "wss://telemetry.subspace.network/submit/";
const TESTNET_CHAIN_SPEC: &[u8] = include_bytes!("../res/chain-spec-raw-snapshot-2022-mar-09.json");
// const TESTNET_BOOTSTRAP_NODE: &str = "/dns/farm-rpc.subspace.network/tcp/30333/p2p/12D3KooWPjMZuSYj35ehced2MTJFf95upwpHKgKUrFRfHwohzJXr";

/// List of accounts which should receive token grants, amounts are specified in SSC.
const TOKEN_GRANTS: &[(&str, u128)] = &[
    (
        "5Dns1SVEeDqnbSm2fVUqHJPCvQFXHVsgiw28uMBwmuaoKFYi",
        3_000_000,
    ),
    (
        "5DxtHHQL9JGapWCQARYUAWj4yDcwuhg9Hsk5AjhEzuzonVyE",
        1_500_000,
    ),
    ("5EHhw9xuQNdwieUkNoucq2YcateoMVJQdN8EZtmRy3roQkVK", 133_333),
    ("5C5qYYCQBnanGNPGwgmv6jiR2MxNPrGnWYLPFEyV1Xdy2P3x", 178_889),
    ("5GBWVfJ253YWVPHzWDTos1nzYZpa9TemP7FpQT9RnxaFN6Sz", 350_000),
    ("5F9tEPid88uAuGbjpyegwkrGdkXXtaQ9sGSWEnYrfVCUCsen", 111_111),
    ("5DkJFCv3cTBsH5y1eFT94DXMxQ3EmVzYojEA88o56mmTKnMp", 244_444),
    ("5G23o1yxWgVNQJuL4Y9UaCftAFvLuMPCRe7BCARxCohjoHc9", 311_111),
    ("5GhHwuJoK1b7uUg5oi8qUXxWHdfgzv6P5CQSdJ3ffrnPRgKM", 317_378),
    ("5EqBwtqrCV427xCtTsxnb9X2Qay39pYmKNk9wD9Kd62jLS97", 300_000),
    ("5D9pNnGCiZ9UqhBQn5n71WFVaRLvZ7znsMvcZ7PHno4zsiYa", 600_000),
    ("5DXfPcXUcP4BG8LBSkJDrfFNApxjWySR6ARfgh3v27hdYr5S", 430_000),
    ("5CXSdDJgzRTj54f9raHN2Z5BNPSMa2ETjqCTUmpaw3ECmwm4", 330_000),
    ("5DqKxL7bQregQmUfFgzTMfRKY4DSvA1KgHuurZWYmxYSCmjY", 200_000),
    ("5CfixiS93yTwHQbzzfn8P2tMxhKXdTx7Jam9htsD7XtiMFtn", 27_800),
    ("5FZe9YzXeEXe7sK5xLR8yCmbU8bPJDTZpNpNbToKvSJBUiEo", 18_067),
    ("5FZwEgsvZz1vpeH7UsskmNmTpbfXvAcojjgVfShgbRqgC1nx", 27_800),
];

/// The extensions for the [`ConsensusChainSpec`].
#[derive(Clone, Serialize, Deserialize, ChainSpecExtension)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChainSpecExtensions {
    /// Chain spec of execution chain.
    pub execution_chain_spec: ExecutionChainSpec,
}

/// The `ChainSpec` parameterized for the consensus runtime.
pub type ConsensusChainSpec = SerializableChainSpec<GenesisConfig, ChainSpecExtensions>;

pub fn testnet_config_json() -> Result<ConsensusChainSpec, String> {
    ConsensusChainSpec::from_json_bytes(TESTNET_CHAIN_SPEC)
}
pub fn testnet_config_compiled() -> Result<ConsensusChainSpec, String> {
    Ok(ConsensusChainSpec::from_genesis(
        // Name
        "Subspace testnet",
        // ID
        "subspace_test",
        ChainType::Custom("Subspace testnet".to_string()),
        || {
            let sudo_account =
                AccountId::from_ss58check("5CXTmJEusve5ixyJufqHThmy4qUrrm6FyLCR7QfE4bbyMTNC")
                    .expect("Wrong root account address");

            let mut balances = vec![(sudo_account.clone(), 1_000 * SSC)];
            let vesting_schedules = TOKEN_GRANTS
                .iter()
                .flat_map(|&(account_address, amount)| {
                    let account_id = AccountId::from_ss58check(account_address)
                        .expect("Wrong vesting account address");
                    let amount: Balance = amount * SSC;

                    // TODO: Adjust start block to real value before mainnet launch
                    let start_block = 100_000_000;
                    let one_month_in_blocks =
                        u32::try_from(3600 * 24 * 30 * MILLISECS_PER_BLOCK / 1000)
                            .expect("One month of blocks always fits in u32; qed");

                    // Add balance so it can be locked
                    balances.push((account_id.clone(), amount));

                    [
                        // 1/4 of tokens are released after 1 year.
                        (
                            account_id.clone(),
                            start_block,
                            one_month_in_blocks * 12,
                            1,
                            amount / 4,
                        ),
                        // 1/48 of tokens are released every month after that for 3 more years.
                        (
                            account_id,
                            start_block + one_month_in_blocks * 12,
                            one_month_in_blocks,
                            36,
                            amount / 48,
                        ),
                    ]
                })
                .collect::<Vec<_>>();
            subspace_genesis_config(
                WASM_BINARY.expect("Wasm binary must be built for testnet"),
                sudo_account,
                balances,
                vesting_schedules,
                (
                    get_account_id_from_seed("Alice"),
                    get_public_key_from_seed::<ExecutorId>("Alice"),
                ),
            )
        },
        // Bootnodes
        vec![
            // TESTNET_BOOTSTRAP_NODE.parse().expect("Bootstrap node must be correct")
        ],
        // Telemetry
        Some(
            TelemetryEndpoints::new(vec![
                (POLKADOT_TELEMETRY_URL.into(), 1),
                (SUBSPACE_TELEMETRY_URL.into(), 1),
            ])
            .map_err(|error| error.to_string())?,
        ),
        // Protocol ID
        Some("subspace-substrate"),
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        ChainSpecExtensions {
            execution_chain_spec: secondary_chain::chain_spec::local_testnet_config(),
        },
    ))
}

pub fn gemini_config() -> Result<ConsensusChainSpec, String> {
    todo!("Distribute the gemini ChainSpec once finalized")
}

pub fn gemini_config_compiled() -> Result<ConsensusChainSpec, String> {
    Ok(ConsensusChainSpec::from_genesis(
        // Name
        "Subspace Gemini 1",
        // ID
        "subspace_gemini_1",
        ChainType::Custom("Subspace Gemini 1".to_string()),
        || {
            let sudo_account =
                AccountId::from_ss58check("5CXTmJEusve5ixyJufqHThmy4qUrrm6FyLCR7QfE4bbyMTNC")
                    .expect("Wrong root account address");

            let mut balances = vec![(sudo_account.clone(), 1_000 * SSC)];
            let vesting_schedules = TOKEN_GRANTS
                .iter()
                .flat_map(|&(account_address, amount)| {
                    let account_id = AccountId::from_ss58check(account_address)
                        .expect("Wrong vesting account address");
                    let amount: Balance = amount * SSC;

                    // TODO: Adjust start block to real value before mainnet launch
                    let start_block = 100_000_000;
                    let one_month_in_blocks =
                        u32::try_from(3600 * 24 * 30 * MILLISECS_PER_BLOCK / 1000)
                            .expect("One month of blocks always fits in u32; qed");

                    // Add balance so it can be locked
                    balances.push((account_id.clone(), amount));

                    [
                        // 1/4 of tokens are released after 1 year.
                        (
                            account_id.clone(),
                            start_block,
                            one_month_in_blocks * 12,
                            1,
                            amount / 4,
                        ),
                        // 1/48 of tokens are released every month after that for 3 more years.
                        (
                            account_id,
                            start_block + one_month_in_blocks * 12,
                            one_month_in_blocks,
                            36,
                            amount / 48,
                        ),
                    ]
                })
                .collect::<Vec<_>>();
            subspace_genesis_config(
                WASM_BINARY.expect("Wasm binary must be built for Gemini"),
                sudo_account,
                balances,
                vesting_schedules,
                (
                    AccountId::from_ss58check("5Df6w8CgYY8kTRwCu8bjBsFu46fy4nFa61xk6dUbL6G4fFjQ")
                        .expect("Wrong Executor account address"),
                    ExecutorId::from_ss58check("5FuuXk1TL8DKQMvg7mcqmP8t9FhxUdzTcYC9aFmebiTLmASx")
                        .expect("Wrong Executor authority address"),
                ),
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        Some(
            TelemetryEndpoints::new(vec![
                (POLKADOT_TELEMETRY_URL.into(), 1),
                (SUBSPACE_TELEMETRY_URL.into(), 1),
            ])
            .map_err(|error| error.to_string())?,
        ),
        // Protocol ID
        Some("subspace-gemini-1"),
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        ChainSpecExtensions {
            execution_chain_spec: secondary_chain::chain_spec::gemini_config(),
        },
    ))
}

pub fn dev_config() -> Result<ConsensusChainSpec, String> {
    let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;

    Ok(ConsensusChainSpec::from_genesis(
        // Name
        "Subspace development",
        // ID
        "subspace_dev",
        ChainType::Development,
        || {
            subspace_genesis_config(
                wasm_binary,
                // Sudo account
                get_account_id_from_seed("Alice"),
                // Pre-funded accounts
                vec![
                    (get_account_id_from_seed("Alice"), 1_000 * SSC),
                    (get_account_id_from_seed("Bob"), 1_000 * SSC),
                    (get_account_id_from_seed("Alice//stash"), 1_000 * SSC),
                    (get_account_id_from_seed("Bob//stash"), 1_000 * SSC),
                ],
                vec![],
                (
                    get_account_id_from_seed("Alice"),
                    get_public_key_from_seed::<ExecutorId>("Alice"),
                ),
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        None,
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        ChainSpecExtensions {
            execution_chain_spec: secondary_chain::chain_spec::development_config(),
        },
    ))
}

pub fn local_config() -> Result<ConsensusChainSpec, String> {
    let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;

    Ok(ConsensusChainSpec::from_genesis(
        // Name
        "Subspace local",
        // ID
        "subspace_local",
        ChainType::Local,
        || {
            subspace_genesis_config(
                wasm_binary,
                // Sudo account
                get_account_id_from_seed("Alice"),
                // Pre-funded accounts
                vec![
                    (get_account_id_from_seed("Alice"), 1_000 * SSC),
                    (get_account_id_from_seed("Bob"), 1_000 * SSC),
                    (get_account_id_from_seed("Charlie"), 1_000 * SSC),
                    (get_account_id_from_seed("Dave"), 1_000 * SSC),
                    (get_account_id_from_seed("Eve"), 1_000 * SSC),
                    (get_account_id_from_seed("Ferdie"), 1_000 * SSC),
                    (get_account_id_from_seed("Alice//stash"), 1_000 * SSC),
                    (get_account_id_from_seed("Bob//stash"), 1_000 * SSC),
                    (get_account_id_from_seed("Charlie//stash"), 1_000 * SSC),
                    (get_account_id_from_seed("Dave//stash"), 1_000 * SSC),
                    (get_account_id_from_seed("Eve//stash"), 1_000 * SSC),
                    (get_account_id_from_seed("Ferdie//stash"), 1_000 * SSC),
                ],
                vec![],
                (
                    get_account_id_from_seed("Alice"),
                    get_public_key_from_seed::<ExecutorId>("Alice"),
                ),
            )
        },
        // Bootnodes
        vec![],
        // Telemetry
        None,
        // Protocol ID
        None,
        None,
        // Properties
        Some(chain_spec_properties()),
        // Extensions
        ChainSpecExtensions {
            execution_chain_spec: secondary_chain::chain_spec::local_testnet_config(),
        },
    ))
}

/// Configure initial storage state for FRAME modules.
fn subspace_genesis_config(
    wasm_binary: &[u8],
    sudo_account: AccountId,
    balances: Vec<(AccountId, Balance)>,
    // who, start, period, period_count, per_period
    vesting: Vec<(AccountId, BlockNumber, BlockNumber, u32, Balance)>,
    executor_authority: (AccountId, ExecutorId),
) -> GenesisConfig {
    GenesisConfig {
        system: SystemConfig {
            // Add Wasm runtime to storage.
            code: wasm_binary.to_vec(),
        },
        balances: BalancesConfig { balances },
        transaction_payment: Default::default(),
        sudo: SudoConfig {
            // Assign network admin rights.
            key: Some(sudo_account),
        },
        vesting: VestingConfig { vesting },
        executor: ExecutorConfig {
            executor: Some(executor_authority),
        },
    }
}

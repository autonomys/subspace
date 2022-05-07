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

use cirrus_runtime::{AccountId, Signature};
use frame_support::traits::Get;
use sc_chain_spec::GenericChainSpec;
use sc_service::{ChainType, Properties};
use sp_core::{sr25519, Pair, Public};
use sp_runtime::traits::{IdentifyAccount, Verify};
use subspace_runtime::{SS58Prefix, DECIMAL_PLACES};

/// Specialized `ChainSpec` for the normal parachain runtime.
pub type ExecutionChainSpec = GenericChainSpec<cirrus_runtime::GenesisConfig>;

/// Helper function to generate a crypto pair from seed
pub fn get_pair_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("static values are valid; qed")
        .public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Helper function to generate an account ID from seed
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_pair_from_seed::<TPublic>(seed)).into_account()
}

pub fn development_config() -> ExecutionChainSpec {
    let mut properties = Properties::new();
    properties.insert("ss58Format".into(), <SS58Prefix as Get<u16>>::get().into());
    properties.insert("tokenDecimals".into(), DECIMAL_PLACES.into());
    properties.insert("tokenSymbol".into(), "tSSC".into());

    ExecutionChainSpec::from_genesis(
        // Name
        "Development",
        // ID
        "execution_dev",
        ChainType::Development,
        move || {
            testnet_genesis(vec![
                get_account_id_from_seed::<sr25519::Public>("Alice"),
                get_account_id_from_seed::<sr25519::Public>("Bob"),
                get_account_id_from_seed::<sr25519::Public>("Charlie"),
                get_account_id_from_seed::<sr25519::Public>("Dave"),
                get_account_id_from_seed::<sr25519::Public>("Eve"),
                get_account_id_from_seed::<sr25519::Public>("Ferdie"),
                get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
                get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
                get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
                get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
                get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
                get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
            ])
        },
        vec![],
        None,
        None,
        None,
        None,
        None,
    )
}

pub fn local_testnet_config() -> ExecutionChainSpec {
    let mut properties = Properties::new();
    properties.insert("ss58Format".into(), <SS58Prefix as Get<u16>>::get().into());
    properties.insert("tokenDecimals".into(), DECIMAL_PLACES.into());
    properties.insert("tokenSymbol".into(), "tSSC".into());

    ExecutionChainSpec::from_genesis(
        // Name
        "Local Testnet",
        // ID
        "execution_local_testnet",
        ChainType::Local,
        move || {
            testnet_genesis(vec![
                get_account_id_from_seed::<sr25519::Public>("Alice"),
                get_account_id_from_seed::<sr25519::Public>("Bob"),
                get_account_id_from_seed::<sr25519::Public>("Charlie"),
                get_account_id_from_seed::<sr25519::Public>("Dave"),
                get_account_id_from_seed::<sr25519::Public>("Eve"),
                get_account_id_from_seed::<sr25519::Public>("Ferdie"),
                get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
                get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
                get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
                get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
                get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
                get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
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
        Some(properties),
        // Extensions
        None,
    )
}

fn testnet_genesis(endowed_accounts: Vec<AccountId>) -> cirrus_runtime::GenesisConfig {
    cirrus_runtime::GenesisConfig {
        system: cirrus_runtime::SystemConfig {
            code: cirrus_runtime::WASM_BINARY
                .expect("WASM binary was not build, please build it!")
                .to_vec(),
        },
        transaction_payment: Default::default(),
        balances: cirrus_runtime::BalancesConfig {
            balances: endowed_accounts
                .iter()
                .cloned()
                .map(|k| (k, 1 << 60))
                .collect(),
        },
    }
}

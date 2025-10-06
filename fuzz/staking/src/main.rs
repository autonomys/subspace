// Copyright 2025 Security Research Labs GmbH
// Permission to use, copy, modify, and/or distribute this software for
// any purpose with or without fee is hereby granted.
//
// THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL
// WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE
// FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
// DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
// AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
// OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use domain_runtime_primitives::DEFAULT_EVM_CHAIN_ID;
use pallet_domains::fuzz_utils::{
    check_general_invariants, check_invariants_after_finalization,
    check_invariants_before_finalization, conclude_domain_epoch, fuzz_mark_invalid_bundle_authors,
    fuzz_unmark_invalid_bundle_authors, get_next_operators, get_pending_slashes,
};
use pallet_domains::staking::{
    do_deregister_operator, do_mark_operators_as_slashed, do_nominate_operator,
    do_register_operator, do_reward_operators, do_unlock_funds, do_unlock_nominator,
    do_withdraw_stake,
};
use pallet_domains::staking_epoch::do_slash_operator;
use pallet_domains::tests::{AccountId, Balance, BalancesConfig, DOMAIN_ID, Test};
use pallet_domains::{Config, OperatorConfig, SlashedReason};
use parity_scale_codec::Encode;
use sp_core::storage::Storage;
use sp_core::{H256, Pair};
use sp_domains::storage::RawGenesis;
use sp_domains::{
    GenesisDomain, OperatorAllowList, OperatorId, OperatorPair, PermissionedActionAllowedBy,
    RuntimeType,
};
use sp_runtime::{BuildStorage, Percent};
use sp_state_machine::BasicExternalities;
use std::collections::BTreeMap;
use subspace_runtime_primitives::AI3;

const ACTIONS_PER_EPOCH: usize = 5;
const NUM_EPOCHS: usize = 5;
const MIN_NOMINATOR_STAKE: Balance = 20;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FuzzData {
    /// NUM_EPOCHS epochs with N epochs skipped
    pub epochs: [(u8, Epoch); NUM_EPOCHS],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Epoch {
    /// ACTIONS_PER_EPOCH actions split between N users
    actions: [(u8, FuzzAction); ACTIONS_PER_EPOCH],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum FuzzAction {
    RegisterOperator {
        amount: u16,
        tax: u8,
    },
    NominateOperator {
        operator_id: u8,
        amount: u16,
    },
    DeregisterOperator {
        operator_id: u64,
    },
    WithdrawStake {
        nominator_id: u8,
        operator_id: u8,
        shares: u16,
    },
    UnlockFunds {
        operator_id: u8,
        nominator_id: u8,
    },
    UnlockNominator {
        operator_id: u8,
        nominator_id: u8,
    },
    MarkOperatorsAsSlashed {
        operator_id: u8,
        slash_reason: u8, // 0 for InvalidBundle, 1 for BadExecutionReceipt
    },
    MarkInvalidBundleAuthors {
        operator_id: u8,
    },
    UnmarkInvalidBundleAuthors {
        operator_id: u8,
        er_id: u8,
    },
    RewardOperator {
        operator_id: u8,
        amount: u16,
    },
    SlashOperator,
}

fn create_genesis_storage(accounts: &[AccountId], mint: u128) -> Storage {
    let raw_genesis_storage = RawGenesis::dummy(vec![1, 2, 3, 4]).encode();
    let pair = OperatorPair::from_seed(&[*accounts.first().unwrap() as u8; 32]);
    pallet_domains::tests::RuntimeGenesisConfig {
        balances: BalancesConfig {
            balances: accounts.iter().cloned().map(|k| (k, mint)).collect(),
        },
        domains: pallet_domains::tests::DomainsConfig {
            genesis_domains: vec![GenesisDomain {
                runtime_name: "evm".to_owned(),
                runtime_type: RuntimeType::Evm,
                runtime_version: Default::default(),
                raw_genesis_storage,
                owner_account_id: *accounts.first().unwrap(),
                domain_name: "evm-domain".to_owned(),
                bundle_slot_probability: (1, 1),
                operator_allow_list: OperatorAllowList::Anyone,
                signing_key: pair.public(),
                minimum_nominator_stake: MIN_NOMINATOR_STAKE * AI3,
                nomination_tax: Percent::from_percent(5),
                initial_balances: vec![],
                domain_runtime_info: (DEFAULT_EVM_CHAIN_ID, Default::default()).into(),
            }],
            permissioned_action_allowed_by: Some(PermissionedActionAllowedBy::Anyone),
        },
        subspace: Default::default(),
        system: Default::default(),
    }
    .build_storage()
    .unwrap()
}

fn main() {
    let accounts: Vec<AccountId> = (0..5).map(|i| (i as u128)).collect();
    let mint = (u16::MAX as u128) * 2 * AI3;
    let genesis = create_genesis_storage(&accounts, mint);
    ziggy::fuzz!(|data: &[u8]| {
        let Ok(data) = bincode::deserialize::<FuzzData>(data) else {
            return;
        };
        // Clone the genesis storage for this fuzz iteration
        let mut ext = BasicExternalities::new(genesis.clone());
        ext.execute_with(|| {
            fuzz(&data, accounts.clone());
        });
    });
}

fn fuzz(data: &FuzzData, accounts: Vec<AccountId>) {
    let mut operators = BTreeMap::new();
    let mut nominators = BTreeMap::new();
    let mut invalid_ers = Vec::new();

    // Get initial issuance from the pre-setup state
    let initial_issuance = accounts
        .iter()
        .map(<Test as Config>::Currency::free_balance)
        .sum();

    for (skip, epoch) in &data.epochs {
        for (user, action) in epoch.actions.iter() {
            let user = accounts.get(*user as usize % accounts.len()).unwrap();

            match action {
                FuzzAction::RegisterOperator { amount, tax } => {
                    let res = register_operator(*user, *amount as u128, *tax);
                    if let Some(operator) = res {
                        operators.insert(user, operator);
                        nominators
                            .entry(*user)
                            .and_modify(|list: &mut Vec<u64>| list.push(operator))
                            .or_insert(vec![operator]);
                        #[cfg(not(feature = "fuzzing"))]
                        println!(
                            "Registering {user:?} as Operator {operator:?} with amount {amount:?}\n-->{res:?}"
                        );
                    } else {
                        #[cfg(not(feature = "fuzzing"))]
                        println!(
                            "Registering {user:?} as Operator (failed) with amount {amount:?} AI3 \n-->{res:?}"
                        );
                    }
                }
                FuzzAction::NominateOperator {
                    operator_id,
                    amount,
                } => {
                    if operators.is_empty() {
                        #[cfg(not(feature = "fuzzing"))]
                        println!("skipping NominateOperator");
                        continue;
                    }
                    let amount = (*amount as u128).max(MIN_NOMINATOR_STAKE) * AI3;
                    let operator = operators
                        .iter()
                        .collect::<Vec<_>>()
                        .get(*operator_id as usize % operators.len())
                        .unwrap()
                        .1;
                    let res = do_nominate_operator::<Test>(*operator, *user, amount);
                    if res.is_ok() {
                        nominators
                            .entry(*user)
                            .and_modify(|list: &mut Vec<u64>| list.push(*operator))
                            .or_insert(vec![*operator]);
                    }
                    #[cfg(not(feature = "fuzzing"))]
                    println!(
                        "Nominating as Nominator {user:?} for Operator {operator:?} with amount {amount:?}\n-->{res:?}"
                    );
                }
                FuzzAction::DeregisterOperator { operator_id } => {
                    if operators.is_empty() {
                        #[cfg(not(feature = "fuzzing"))]
                        println!("skipping DeregisterOperator");
                        continue;
                    }
                    let (owner, operator) = *operators
                        .iter()
                        .collect::<Vec<_>>()
                        .get(*operator_id as usize % operators.len())
                        .unwrap();
                    let res = do_deregister_operator::<Test>(**owner, *operator);
                    #[cfg(not(feature = "fuzzing"))]
                    println!("de-registering Operator {operator:?} \n-->{res:?}");
                }
                FuzzAction::WithdrawStake {
                    nominator_id,
                    operator_id,
                    shares,
                } => {
                    if operators.is_empty() {
                        #[cfg(not(feature = "fuzzing"))]
                        println!("skipping WithdrawStake");
                        continue;
                    }
                    let (nominator, operators) = *nominators
                        .iter()
                        .collect::<Vec<_>>()
                        .get(*nominator_id as usize % nominators.len())
                        .unwrap();
                    let operator = operators
                        .get(*operator_id as usize % operators.len())
                        .unwrap();
                    let res =
                        do_withdraw_stake::<Test>(*operator, *nominator, *shares as u128 * AI3);
                    #[cfg(not(feature = "fuzzing"))]
                    println!(
                        "Withdrawing stake from Operator {operator:?}  as Nominator {nominator:?} of shares {shares:?}\n-->{res:?}"
                    );
                }
                FuzzAction::UnlockFunds {
                    operator_id,
                    nominator_id,
                } => {
                    if operators.is_empty() {
                        #[cfg(not(feature = "fuzzing"))]
                        println!("skipping UnlockFunds");
                        continue;
                    }
                    let (nominator, operators) = *nominators
                        .iter()
                        .collect::<Vec<_>>()
                        .get(*nominator_id as usize % nominators.len())
                        .unwrap();
                    let operator = operators
                        .get(*operator_id as usize % operators.len())
                        .unwrap();
                    let res = do_unlock_funds::<Test>(*operator, *nominator);
                    #[cfg(not(feature = "fuzzing"))]
                    println!(
                        "Unlocking funds as Nominator {nominator:?} from Operator {operator:?} \n-->{res:?}"
                    );
                }
                FuzzAction::UnlockNominator {
                    operator_id,
                    nominator_id,
                } => {
                    if operators.is_empty() {
                        #[cfg(not(feature = "fuzzing"))]
                        println!("skipping UnlockNominator");
                        continue;
                    }
                    let (nominator, operators) = *nominators
                        .iter()
                        .collect::<Vec<_>>()
                        .get(*nominator_id as usize % nominators.len())
                        .unwrap();
                    let operator = operators
                        .get(*operator_id as usize % operators.len())
                        .unwrap();
                    let res = do_unlock_nominator::<Test>(*operator, *nominator);
                    #[cfg(not(feature = "fuzzing"))]
                    println!(
                        "Unlocking funds as Nominator {nominator:?} from Operator {operator:?} \n-->{res:?}"
                    );
                }
                FuzzAction::MarkOperatorsAsSlashed {
                    operator_id,
                    slash_reason,
                } => {
                    if operators.is_empty() {
                        #[cfg(not(feature = "fuzzing"))]
                        println!("skipping MarkOperatorsAsSlashed");
                        continue;
                    }
                    let operator = operators
                        .iter()
                        .collect::<Vec<_>>()
                        .get(*operator_id as usize % operators.len())
                        .unwrap()
                        .1;
                    let slash_reason = match slash_reason % 2 {
                        0 => SlashedReason::InvalidBundle(0),
                        _ => SlashedReason::BadExecutionReceipt(H256::from([0u8; 32])),
                    };
                    let res = do_mark_operators_as_slashed::<Test>(vec![*operator], slash_reason);
                    #[cfg(not(feature = "fuzzing"))]
                    println!("Marking {operator:?} as slashed\n-->{res:?}");
                    do_slash_operator::<Test>(DOMAIN_ID, u32::MAX).unwrap();
                }
                FuzzAction::SlashOperator => {
                    if operators.is_empty() {
                        #[cfg(not(feature = "fuzzing"))]
                        println!("skipping SlashOperator");
                        continue;
                    }
                    let res = do_slash_operator::<Test>(DOMAIN_ID, u32::MAX);
                    assert!(res.is_ok());
                    #[cfg(not(feature = "fuzzing"))]
                    {
                        let pending_slashes = get_pending_slashes::<Test>(DOMAIN_ID);
                        println!("Slashing: {pending_slashes:?} -->{res:?}");
                    }
                }
                FuzzAction::RewardOperator {
                    operator_id,
                    amount,
                } => {
                    if operators.is_empty() {
                        #[cfg(not(feature = "fuzzing"))]
                        println!("skipping RewardOperator");
                        continue;
                    }
                    let operator = operators
                        .iter()
                        .collect::<Vec<_>>()
                        .get(*operator_id as usize % operators.len())
                        .unwrap()
                        .1;
                    let reward_amount = 10u128 * AI3;
                    let res = do_reward_operators::<Test>(
                        DOMAIN_ID,
                        sp_domains::OperatorRewardSource::Dummy,
                        vec![*operator].into_iter(),
                        reward_amount,
                    );
                    assert!(res.is_ok());
                    #[cfg(not(feature = "fuzzing"))]
                    println!("Rewarding operator {operator:?} with {amount:?} AI3 \n-->{res:?}");
                }
                FuzzAction::MarkInvalidBundleAuthors { operator_id } => {
                    if operators.is_empty() {
                        #[cfg(not(feature = "fuzzing"))]
                        println!("skipping MarkInvalidBundleAuthors");
                        continue;
                    }
                    let operator = operators
                        .iter()
                        .collect::<Vec<_>>()
                        .get(*operator_id as usize % operators.len())
                        .unwrap()
                        .1;
                    if let Some(invalid_er) =
                        fuzz_mark_invalid_bundle_authors::<Test>(*operator, DOMAIN_ID)
                    {
                        invalid_ers.push(invalid_er)
                    }
                }
                FuzzAction::UnmarkInvalidBundleAuthors { operator_id, er_id } => {
                    if operators.is_empty() {
                        #[cfg(not(feature = "fuzzing"))]
                        println!("skipping UnmarkInvalidBundleAuthors");
                        continue;
                    }
                    if invalid_ers.is_empty() {
                        #[cfg(not(feature = "fuzzing"))]
                        println!("skipping UnmarkInvalidBundleAuthors");
                        continue;
                    }
                    let operator = operators
                        .iter()
                        .collect::<Vec<_>>()
                        .get(*operator_id as usize % operators.len())
                        .unwrap()
                        .1;
                    let er = invalid_ers
                        .get(*er_id as usize % invalid_ers.len())
                        .unwrap();
                    fuzz_unmark_invalid_bundle_authors::<Test>(DOMAIN_ID, *operator, *er);
                }
            }
            check_invariants_before_finalization::<Test>(DOMAIN_ID);
            let prev_validator_states = get_next_operators::<Test>(DOMAIN_ID);
            conclude_domain_epoch::<Test>(DOMAIN_ID);
            check_invariants_after_finalization::<Test>(DOMAIN_ID, prev_validator_states);
            check_general_invariants::<Test>(initial_issuance);
            #[cfg(not(feature = "fuzzing"))]
            println!("skipping {skip:?} epochs");
            for _ in 0..*skip {
                conclude_domain_epoch::<Test>(DOMAIN_ID);
            }
        }
    }
}

fn register_operator(operator: AccountId, amount: Balance, tax: u8) -> Option<OperatorId> {
    let pair = OperatorPair::from_seed(&[operator as u8; 32]);
    let config = OperatorConfig {
        signing_key: pair.public(),
        minimum_nominator_stake: MIN_NOMINATOR_STAKE,
        nomination_tax: sp_runtime::Percent::from_percent(tax.min(100)),
    };
    let res = do_register_operator::<Test>(operator, DOMAIN_ID, amount * AI3, config);
    if let Ok((id, _)) = res {
        Some(id)
    } else {
        None
    }
}

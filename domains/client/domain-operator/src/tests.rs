use crate::OperatorSlotInfo;
use crate::aux_schema::BundleMismatchType;
use crate::domain_block_processor::{DomainBlockProcessor, PendingConsensusBlocks};
use crate::domain_bundle_producer::{BundleProducer, TestBundleProducer};
use crate::domain_bundle_proposer::DomainBundleProposer;
use crate::fraud_proof::{FraudProofGenerator, TraceDiffType};
use crate::tests::TxPoolError::InvalidTransaction as TxPoolInvalidTransaction;
use cross_domain_message_gossip::get_channel_state;
use domain_block_builder::BlockBuilderApi;
use domain_runtime_primitives::opaque::Block as DomainBlock;
use domain_runtime_primitives::{AccountId20Converter, AccountIdConverter, Hash};
use domain_test_primitives::{OnchainStateApi, TimestampApi};
use domain_test_service::EcdsaKeyring::{self, Alice, Bob, Charlie, Dave, Eve};
use domain_test_service::Sr25519Keyring::{self, Alice as Sr25519Alice, Ferdie};
use domain_test_service::evm_domain_test_runtime::{
    Header, Runtime as TestRuntime, RuntimeCall, UncheckedExtrinsic as EvmUncheckedExtrinsic,
};
use domain_test_service::{EVM_DOMAIN_ID, EvmDomainNode};
use domain_test_utils::test_ethereum::{
    EvmAccountList, generate_evm_account_list, generate_evm_domain_call, generate_legacy_tx,
};
use domain_test_utils::test_ethereum_tx::{AccountInfo, address_build, contract_address};
use ethereum::TransactionV2 as EthereumTransaction;
use fp_rpc::EthereumRuntimeRPCApi;
use futures::StreamExt;
use pallet_domains::{FraudProofFor, OpaqueBundleOf, OperatorConfig};
use pallet_messenger::ChainAllowlistUpdate;
use parity_scale_codec::{Decode, Encode};
use sc_client_api::{Backend, BlockBackend, BlockchainEvents, HeaderBackend};
use sc_domains::generate_mmr_proof;
use sc_service::{BasePath, Role};
use sc_transaction_pool_api::TransactionPool;
use sc_transaction_pool_api::error::Error as TxPoolError;
use sc_utils::mpsc::tracing_unbounded;
use sp_api::{ApiExt, Core, ProvideRuntimeApi, StorageProof};
use sp_blockchain::ApplyExtrinsicFailed;
use sp_consensus::SyncOracle;
use sp_core::storage::StateVersion;
use sp_core::traits::{FetchRuntimeCode, SpawnEssentialNamed};
use sp_core::{H160, H256, Pair, U256};
use sp_domain_digests::AsPredigest;
use sp_domains::bundle::{BundleValidity, InboxedBundle, InvalidBundleType};
use sp_domains::core_api::DomainCoreApi;
use sp_domains::execution_receipt::{
    BlockFees, ExecutionReceiptMutRef, ExecutionReceiptRef, Transfers,
};
use sp_domains::merkle_tree::MerkleTree;
use sp_domains::{
    ChainId, ChannelId, DomainsApi, HeaderHashingFor, OperatorPublicKey,
    PermissionedActionAllowedBy,
};
use sp_domains_fraud_proof::InvalidTransactionCode;
use sp_domains_fraud_proof::fraud_proof::{
    ApplyExtrinsicMismatch, ExecutionPhase, FinalizeBlockMismatch, FraudProofVariant,
    InvalidBlockFeesProof, InvalidBundlesProofData, InvalidDomainBlockHashProof,
    InvalidExtrinsicsRootProof, InvalidTransfersProof,
};
use sp_messenger::MessengerApi;
use sp_messenger::messages::{CrossDomainMessage, Proof};
use sp_mmr_primitives::{EncodableOpaqueLeaf, LeafProof as MmrProof};
use sp_runtime::generic::{BlockId, DigestItem};
use sp_runtime::traits::{BlakeTwo256, Convert, Hash as HashT, Header as HeaderT, Zero};
use sp_runtime::transaction_validity::{
    InvalidTransaction, TransactionSource, TransactionValidityError,
};
use sp_runtime::{Digest, MultiAddress, OpaqueExtrinsic, Percent, TransactionOutcome};
use sp_state_machine::backend::AsTrieBackend;
use sp_subspace_mmr::ConsensusChainMmrLeafProof;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;
use sp_weights::Weight;
use std::assert_matches::assert_matches;
use std::collections::{BTreeMap, VecDeque};
use std::future::IntoFuture;
use std::sync::Arc;
use std::time::Duration;
use subspace_core_primitives::pot::PotOutput;
use subspace_runtime_primitives::opaque::Block as CBlock;
use subspace_runtime_primitives::{AI3, Balance, BlockHashFor, HeaderFor};
use subspace_test_client::chain_spec::get_from_seed;
use subspace_test_primitives::{DOMAINS_BLOCK_PRUNING_DEPTH, OnchainStateApi as _};
use subspace_test_runtime::Runtime;
use subspace_test_service::{
    MockConsensusNode, produce_block_with, produce_blocks, produce_blocks_until,
};
use tempfile::TempDir;
use tracing::{error, info};

/// The general timeout for test operations that could hang.
const TIMEOUT: Duration = Duration::from_mins(10);

/// A trait that makes it easier to add a timeout to any future: `future.timeout().await?`.
trait TestTimeout: IntoFuture {
    fn timeout(self) -> tokio::time::Timeout<Self::IntoFuture>;
}

impl<F> TestTimeout for F
where
    F: IntoFuture,
{
    fn timeout(self) -> tokio::time::Timeout<Self::IntoFuture> {
        tokio::time::timeout(TIMEOUT, self)
    }
}

// Only used in tests that are temporarily disabled on macOS due to instability (#3385)
#[cfg_attr(target_os = "macos", expect(dead_code))]
fn number_of(consensus_node: &MockConsensusNode, block_hash: Hash) -> u32 {
    consensus_node
        .client
        .number(block_hash)
        .unwrap_or_else(|err| panic!("Failed to fetch number for {block_hash}: {err}"))
        .unwrap_or_else(|| panic!("header {block_hash} not in the chain"))
}

// These functions depend on the macro-constructed `TestRuntime::RuntimeCall` enum, so they can't
// be shared via `sp_domains::test_ethereum`.

/// Generate a self-contained EVM domain extrinsic from a transaction.
/// The returned extrinsic can be passed to `runtime_api().check_extrinsics_and_do_pre_dispatch()`.
pub fn generate_eth_domain_extrinsic(
    account_info: AccountInfo,
    use_create: ethereum::TransactionAction,
    nonce: U256,
    gas_price: U256,
) -> EvmUncheckedExtrinsic {
    // TODO:
    // - randomly choose from the 3 different transaction types
    let tx =
        generate_legacy_tx::<TestRuntime>(account_info, nonce, use_create, vec![0; 100], gas_price);

    generate_eth_domain_sc_extrinsic(tx)
}

/// Generate a self-contained EVM domain extrinsic from a transaction.
/// The returned extrinsic can be passed to `runtime_api().check_extrinsics_and_do_pre_dispatch()`.
pub fn generate_eth_domain_sc_extrinsic(tx: EthereumTransaction) -> EvmUncheckedExtrinsic {
    let call = pallet_ethereum::Call::<TestRuntime>::transact { transaction: tx };
    fp_self_contained::UncheckedExtrinsic::new_bare(RuntimeCall::Ethereum(call))
}

async fn setup_evm_test_nodes(
    ferdie_key: Sr25519Keyring,
    private_evm: bool,
    evm_owner: impl Into<Option<Sr25519Keyring>>,
) -> (TempDir, MockConsensusNode, EvmDomainNode) {
    let evm_owner = evm_owner.into();
    info!(
        sudo = ?Sr25519Alice.to_account_id(),
        ferdie = ?ferdie_key.to_account_id(),
        evm_owner = ?evm_owner.map(|k| k.to_account_id()),
        "Setting up EVM test nodes with {} evm (EVM ovner defaults to sudo)",
        if private_evm { "private" } else { "public" },
    );

    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie with Alice Key since that is the sudo key
    let mut ferdie = MockConsensusNode::run_with_finalization_depth(
        tokio_handle.clone(),
        ferdie_key,
        BasePath::new(directory.path().join("ferdie")),
        None,
        private_evm,
        evm_owner,
    );

    // Run Alice (an evm domain)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    (directory, ferdie, alice)
}

async fn setup_evm_test_accounts(
    ferdie_key: Sr25519Keyring,
    private_evm: bool,
    evm_owner: impl Into<Option<Sr25519Keyring>>,
) -> (TempDir, MockConsensusNode, EvmDomainNode, Vec<AccountInfo>) {
    let (directory, mut ferdie, alice) =
        setup_evm_test_nodes(ferdie_key, private_evm, evm_owner).await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Create more accounts and fund those accounts
    let tx_to_create = 5;
    let account_infos = (0..tx_to_create)
        .map(|i| address_build(i as u128))
        .collect::<Vec<AccountInfo>>();
    let alice_balance = alice.free_balance(Alice.to_account_id());
    for (i, account_info) in account_infos.iter().enumerate() {
        let alice_balance_transfer_extrinsic = alice.construct_extrinsic(
            alice.account_nonce() + i as u32,
            pallet_balances::Call::transfer_allow_death {
                dest: account_info.address.0.into(),
                value: alice_balance / (tx_to_create as u128 + 2),
            },
        );
        alice
            .send_extrinsic(alice_balance_transfer_extrinsic)
            .await
            .expect("Failed to send extrinsic");
    }

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    (directory, ferdie, alice, account_infos)
}

// Open XDM channel between the consensus chain and the EVM domain
async fn open_xdm_channel(ferdie: &mut MockConsensusNode, alice: &mut EvmDomainNode) {
    // add domain to consensus chain allowlist
    ferdie
        .construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
            call: Box::new(subspace_test_runtime::RuntimeCall::Messenger(
                pallet_messenger::Call::update_consensus_chain_allowlist {
                    update: ChainAllowlistUpdate::Add(ChainId::Domain(EVM_DOMAIN_ID)),
                },
            )),
        })
        .await
        .expect("Failed to construct and send consensus chain allowlist update");

    // produce another block so allowlist on consensus is updated
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // add consensus chain to domain chain allow list
    ferdie
        .construct_and_send_extrinsic_with(subspace_test_runtime::RuntimeCall::Messenger(
            pallet_messenger::Call::initiate_domain_update_chain_allowlist {
                domain_id: EVM_DOMAIN_ID,
                update: ChainAllowlistUpdate::Add(ChainId::Consensus),
            },
        ))
        .await
        .expect("Failed to construct and send domain chain allowlist update");

    // produce another block so allowlist on domain are updated
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // Open channel between the Consensus chain and EVM domains
    alice
        .construct_and_send_extrinsic(evm_domain_test_runtime::RuntimeCall::Messenger(
            pallet_messenger::Call::initiate_channel {
                dst_chain_id: ChainId::Consensus,
            },
        ))
        .await
        .expect("Failed to construct and send extrinsic");

    // Wait until channel opens
    produce_blocks_until!(ferdie, alice, {
        alice
            .get_open_channel_for_chain(ChainId::Consensus)
            .is_some()
    })
    .timeout()
    .await
    .unwrap()
    .unwrap();

    produce_blocks!(ferdie, alice, 3).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_private_evm_domain_create_contracts_with_allow_list_default() {
    let (_directory, mut ferdie, alice, account_infos) =
        setup_evm_test_accounts(Sr25519Alice, true, None).await;

    let gas_price = alice
        .client
        .runtime_api()
        .gas_price(alice.client.info().best_hash)
        .unwrap();

    // Any account should be able to create contracts by default
    let mut eth_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[0].address)
        .unwrap()
        .nonce;
    let eth_tx = generate_eth_domain_extrinsic(
        account_infos[0].clone(),
        ethereum::TransactionAction::Create,
        eth_nonce,
        gas_price,
    );
    eth_nonce += U256::one();

    let result = alice.send_extrinsic(eth_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send self-contained extrinsic"
    );

    let mut evm_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[1].address)
        .unwrap()
        .nonce;
    let mut evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[1].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send signed extrinsic"
    );

    // Produce a bundle that contains just the sent extrinsics
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 2);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let gas_price = alice
        .client
        .runtime_api()
        .gas_price(alice.client.info().best_hash)
        .unwrap();

    // Nested should behave exactly the same
    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[1].clone(),
        ethereum::TransactionAction::Create,
        1,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send nested signed extrinsic"
    );

    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[2].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    let evm_ex = alice.construct_unsigned_extrinsic(evm_tx);
    let result = alice.send_extrinsic(evm_ex).await;
    // TODO: fix NoUnsignedValidator error
    assert_matches!(
        result,
        Err(_),
        "Test should fail until the test runtime is given an unsigned validator"
    );

    // Produce a bundle that contains just the sent extrinsics
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    produce_blocks!(ferdie, alice, 3).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_public_evm_domain_create_contracts() {
    let (_directory, mut ferdie, alice, account_infos) =
        setup_evm_test_accounts(Sr25519Alice, false, None).await;

    let gas_price = alice
        .client
        .runtime_api()
        .gas_price(alice.client.info().best_hash)
        .unwrap();

    // Any account should be able to create contracts in a public EVM domain
    let mut eth_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[0].address)
        .unwrap()
        .nonce;
    let eth_tx = generate_eth_domain_extrinsic(
        account_infos[0].clone(),
        ethereum::TransactionAction::Create,
        eth_nonce,
        gas_price,
    );
    eth_nonce += U256::one();

    let result = alice.send_extrinsic(eth_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send self-contained extrinsic"
    );

    let mut evm_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[1].address)
        .unwrap()
        .nonce;
    let mut evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[1].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send signed extrinsic"
    );

    // Produce a bundle that contains just the sent extrinsics
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 2);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let gas_price = alice
        .client
        .runtime_api()
        .gas_price(alice.client.info().best_hash)
        .unwrap();

    // Nested should behave exactly the same
    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[1].clone(),
        ethereum::TransactionAction::Create,
        1,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send nested signed extrinsic"
    );

    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[2].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    let evm_ex = alice.construct_unsigned_extrinsic(evm_tx);
    let result = alice.send_extrinsic(evm_ex).await;
    // TODO: fix NoUnsignedValidator error
    assert_matches!(
        result,
        Err(_),
        "Test should fail until the test runtime is given an unsigned validator"
    );

    // Produce a bundle that contains just the sent extrinsics
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    produce_blocks!(ferdie, alice, 3).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_evm_domain_create_contracts_with_allow_list_reject_all() {
    let (_directory, mut ferdie, alice, account_infos) =
        setup_evm_test_accounts(Sr25519Alice, true, Ferdie).await;

    let gas_price = alice
        .client
        .runtime_api()
        .gas_price(alice.client.info().best_hash)
        .unwrap();

    // Create contracts used for testing contract calls
    let mut eth_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[0].address)
        .unwrap()
        .nonce;
    let mut eth_tx = generate_eth_domain_extrinsic(
        account_infos[0].clone(),
        ethereum::TransactionAction::Create,
        eth_nonce,
        gas_price,
    );
    let eth_contract_address = contract_address(account_infos[0].address, eth_nonce.as_u64());
    eth_nonce += U256::one();

    alice.send_extrinsic(eth_tx).await.unwrap();

    let mut evm_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[1].address)
        .unwrap()
        .nonce;
    let mut evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[1].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    let evm_contract_address = contract_address(account_infos[1].address, evm_nonce.as_u64());
    evm_nonce += U256::one();

    alice.construct_and_send_extrinsic(evm_tx).await.unwrap();

    // Produce a bundle that contains just the sent extrinsics
    let (slot, _bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // set EVM contract allow list on Domain using domain sudo.
    // Sudo on consensus chain will send a sudo call to domain
    // once the call is executed in the domain, list will be updated.
    let allow_list = generate_evm_account_list(&account_infos, EvmAccountList::NoOne);
    ferdie.construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
        call: Box::new(subspace_test_runtime::RuntimeCall::Domains(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    }))})
    .await
    .expect("Failed to construct and send consensus chain sudo call to update EVM contract allow list");

    // Wait until list is updated
    produce_blocks_until!(ferdie, alice, {
        alice.evm_contract_creation_allowed_by() == allow_list
    })
    .timeout()
    .await
    .unwrap()
    .unwrap();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let gas_price = alice
        .client
        .runtime_api()
        .gas_price(alice.client.info().best_hash)
        .unwrap();

    // No account should be able to create contracts
    eth_tx = generate_eth_domain_extrinsic(
        account_infos[0].clone(),
        ethereum::TransactionAction::Create,
        gas_price,
        eth_nonce,
    );
    eth_nonce += U256::one();

    let result = alice.send_extrinsic(eth_tx).await;
    assert_matches!(
        result,
        Err(_),
        "Create contract self-contained extrinsic should have been rejected"
    );

    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[2].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Err(_),
        "Create contract signed extrinsic should have been rejected"
    );

    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[2].clone(),
        ethereum::TransactionAction::Create,
        2,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Err(_),
        "Create contract nested signed extrinsic should have been rejected"
    );

    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[2].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    let evm_ex = alice.construct_unsigned_extrinsic(evm_tx);
    let result = alice.send_extrinsic(evm_ex).await;
    assert_matches!(
        result,
        Err(_),
        "Create contract unsigned extrinsic should have been rejected"
    );

    // But they should be able to call existing contracts
    eth_tx = generate_eth_domain_extrinsic(
        account_infos[1].clone(),
        ethereum::TransactionAction::Call(eth_contract_address),
        eth_nonce,
        gas_price,
    );
    eth_nonce += U256::one();

    let result = alice.send_extrinsic(eth_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Contract call self-contained extrinsic should have been allowed"
    );

    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[3].clone(),
        ethereum::TransactionAction::Call(evm_contract_address),
        0,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Contract call signed extrinsic should have been allowed"
    );

    // Produce a bundle that contains just the sent extrinsics
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let gas_price = alice
        .client
        .runtime_api()
        .gas_price(alice.client.info().best_hash)
        .unwrap();

    // Nested should be able to call existing contracts
    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[3].clone(),
        ethereum::TransactionAction::Call(evm_contract_address),
        3,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Contract call nested signed extrinsic should have been allowed"
    );

    // Produce a bundle that only contain the successful extrinsic
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    produce_blocks!(ferdie, alice, 3).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_evm_domain_create_contracts_with_allow_list_single() {
    let (_directory, mut ferdie, alice, account_infos) =
        setup_evm_test_accounts(Sr25519Alice, true, Ferdie).await;

    let gas_price = alice
        .client
        .runtime_api()
        .gas_price(alice.client.info().best_hash)
        .unwrap();

    // Create contracts used for testing contract calls
    let mut eth_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[0].address)
        .unwrap()
        .nonce;
    let mut eth_tx = generate_eth_domain_extrinsic(
        account_infos[0].clone(),
        ethereum::TransactionAction::Create,
        eth_nonce,
        gas_price,
    );
    eth_nonce += U256::one();

    alice.send_extrinsic(eth_tx).await.unwrap();

    let mut evm_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[1].address)
        .unwrap()
        .nonce;
    let mut evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[1].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    alice.construct_and_send_extrinsic(evm_tx).await.unwrap();

    // Produce a bundle that contains just the sent extrinsics
    let (slot, _bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // 1 account in the allow list
    let allow_list = generate_evm_account_list(&account_infos, EvmAccountList::One);
    ferdie.construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
        call: Box::new(subspace_test_runtime::RuntimeCall::Domains(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    }))})
    .await
    .expect("Failed to construct and send consensus chain sudo call to update EVM contract allow list");

    // Wait until list is updated
    produce_blocks_until!(ferdie, alice, {
        alice.evm_contract_creation_allowed_by() == allow_list
    })
    .timeout()
    .await
    .unwrap()
    .unwrap();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let gas_price = alice
        .client
        .runtime_api()
        .gas_price(alice.client.info().best_hash)
        .unwrap();

    // Only account 0 should be able to create contracts
    eth_tx = generate_eth_domain_extrinsic(
        account_infos[0].clone(),
        ethereum::TransactionAction::Create,
        eth_nonce,
        gas_price,
    );
    eth_nonce += U256::one();

    let result = alice.send_extrinsic(eth_tx.clone()).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send self-contained extrinsic:\n\
        allow list: {allow_list:?},\n\
        tx: {eth_tx:?},\n]
        signer: {:?}, nonce: {:?}, price: {gas_price:?}",
        account_infos[0],
        eth_nonce - U256::one(),
    );

    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[0].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    // This is actually checking alice's account ID, which does the signing in construct_and_send_extrinsic()
    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send signed extrinsic:\n\
        allow list: {allow_list:?},\n\
        tx: {eth_tx:?},\n]
        signer: {:?}, nonce: {:?}, price: {gas_price:?}",
        account_infos[0],
        evm_nonce - U256::one(),
    );

    // Produce a bundle that contains just the sent extrinsics
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 2);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let gas_price = alice
        .client
        .runtime_api()
        .gas_price(alice.client.info().best_hash)
        .unwrap();

    // Nested should also work
    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[0].clone(),
        ethereum::TransactionAction::Create,
        4,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    // This is actually checking alice's account ID, which does the signing in construct_and_send_extrinsic()
    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send nested signed extrinsic:\n\
        allow list: {allow_list:?},\n\
        tx: {eth_tx:?},\n]
        signer: {:?}, nonce: {:?}, price: {gas_price:?}",
        account_infos[0],
        evm_nonce - U256::one(),
    );

    // All other accounts shouldn't be allowed
    eth_tx = generate_eth_domain_extrinsic(
        account_infos[1].clone(),
        ethereum::TransactionAction::Create,
        gas_price,
        eth_nonce,
    );
    eth_nonce += U256::one();

    let result = alice.send_extrinsic(eth_tx).await;
    assert_matches!(
        result,
        Err(_),
        "Create contract self-contained extrinsic should have been rejected"
    );

    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[2].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    // TODO: also check evm signed with other accounts
    let evm_ex = alice.construct_unsigned_extrinsic(evm_tx);
    let result = alice.send_extrinsic(evm_ex).await;
    assert_matches!(
        result,
        Err(_),
        "Create contract unsigned extrinsic should have been rejected"
    );

    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[2].clone(),
        ethereum::TransactionAction::Create,
        5,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    // TODO: also check evm signed with other accounts
    let evm_ex = alice.construct_unsigned_extrinsic(evm_tx);
    let result = alice.send_extrinsic(evm_ex).await;
    assert_matches!(
        result,
        Err(_),
        "Create contract nested unsigned extrinsic should have been rejected"
    );

    // Produce a bundle that only contain the successful extrinsic
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    produce_blocks!(ferdie, alice, 3).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_evm_domain_create_contracts_with_allow_list_multiple() {
    let (_directory, mut ferdie, alice, account_infos) =
        setup_evm_test_accounts(Sr25519Alice, true, Ferdie).await;

    // Multiple accounts in the allow list
    let allow_list = generate_evm_account_list(&account_infos, EvmAccountList::Multiple);
    ferdie.construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
        call: Box::new(subspace_test_runtime::RuntimeCall::Domains(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    }))})
    .await
    .expect("Failed to construct and send consensus chain sudo call to update EVM contract allow list");

    // Wait until list is updated
    produce_blocks_until!(ferdie, alice, {
        alice.evm_contract_creation_allowed_by() == allow_list
    })
    .timeout()
    .await
    .unwrap()
    .unwrap();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let gas_price = alice
        .client
        .runtime_api()
        .gas_price(alice.client.info().best_hash)
        .unwrap();

    // Accounts 0-2 should be able to create contracts
    let mut eth_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[1].address)
        .unwrap()
        .nonce;
    let mut eth_tx = generate_eth_domain_extrinsic(
        account_infos[1].clone(),
        ethereum::TransactionAction::Create,
        eth_nonce,
        gas_price,
    );
    eth_nonce += U256::one();

    let result = alice.send_extrinsic(eth_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send self-contained extrinsic"
    );

    let mut evm_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[2].address)
        .unwrap()
        .nonce;
    let mut evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[2].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    // This is actually checking alice's account ID, which does the signing in construct_and_send_extrinsic()
    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send signed extrinsic"
    );

    // Produce a bundle that contains just the sent extrinsics
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 2);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let gas_price = alice
        .client
        .runtime_api()
        .gas_price(alice.client.info().best_hash)
        .unwrap();

    // Nested should also work
    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[0].clone(),
        ethereum::TransactionAction::Create,
        6,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    // This is actually checking alice's account ID, which does the signing in construct_and_send_extrinsic()
    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send signed extrinsic"
    );

    // All other accounts shouldn't be allowed
    eth_tx = generate_eth_domain_extrinsic(
        account_infos[3].clone(),
        ethereum::TransactionAction::Create,
        gas_price,
        eth_nonce,
    );
    eth_nonce += U256::one();

    let result = alice.send_extrinsic(eth_tx).await;
    assert_matches!(
        result,
        Err(_),
        "Create contract self-contained extrinsic should have been rejected"
    );

    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[4].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    // TODO: also check evm signed with other accounts
    let evm_ex = alice.construct_unsigned_extrinsic(evm_tx);
    let result = alice.send_extrinsic(evm_ex).await;
    assert_matches!(
        result,
        Err(_),
        "Create contract unsigned extrinsic should have been rejected"
    );

    evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[4].clone(),
        ethereum::TransactionAction::Create,
        7,
        evm_nonce,
        gas_price,
    );
    evm_nonce += U256::one();

    // TODO: also check evm signed with other accounts
    let evm_ex = alice.construct_unsigned_extrinsic(evm_tx);
    let result = alice.send_extrinsic(evm_ex).await;
    assert_matches!(
        result,
        Err(_),
        "Create contract nested unsigned extrinsic should have been rejected"
    );

    // Produce a bundle that only contain the successful extrinsic
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    produce_blocks!(ferdie, alice, 3).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_evm_domain_gas_estimates() {
    let (_directory, mut ferdie, alice, account_infos) =
        setup_evm_test_accounts(Sr25519Alice, false, None).await;

    let test_estimate_gas = |evm_call, is_estimate| {
        let <TestRuntime as frame_system::Config>::RuntimeCall::EVM(evm_call) = evm_call else {
            panic!("Unexpected RuntimeCall type");
        };

        match evm_call {
            pallet_evm::Call::create {
                source,
                ref init,
                value,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                nonce,
                ref access_list,
            } => {
                let create_info = alice
                    .client
                    .runtime_api()
                    .create(
                        alice.client.info().best_hash,
                        source,
                        init.clone(),
                        value,
                        gas_limit.into(),
                        Some(max_fee_per_gas),
                        max_priority_fee_per_gas,
                        nonce,
                        // Do we want to estimate gas, or run the call?
                        is_estimate,
                        Some(access_list.clone()),
                    )
                    .expect("test EVM Create runtime call must succeed")
                    .expect("test EVM Create info must succeed");

                assert_eq!(
                    (
                        create_info.used_gas.standard,
                        create_info.used_gas.effective,
                    ),
                    // The exact estimate is not important, but we want to know if it changes
                    (53_408.into(), 53_408.into()),
                    "Incorrect EVM Create gas estimate: {evm_call:?} {create_info:?}",
                );
            }
            pallet_evm::Call::call {
                source,
                target,
                ref input,
                value,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                nonce,
                ref access_list,
            } => {
                let call_info = alice
                    .client
                    .runtime_api()
                    .call(
                        alice.client.info().best_hash,
                        source,
                        target,
                        input.clone(),
                        value,
                        gas_limit.into(),
                        Some(max_fee_per_gas),
                        max_priority_fee_per_gas,
                        nonce,
                        // Do we want to estimate gas, or run the call?
                        is_estimate,
                        Some(access_list.clone()),
                    )
                    .expect("test EVM Call runtime call must succeed")
                    .expect("test EVM Call info must succeed");

                assert_eq!(
                    (call_info.used_gas.standard, call_info.used_gas.effective),
                    // The exact estimate is not important, but we want to know if it changes
                    (21_400.into(), 21_400.into()),
                    "Incorrect EVM Call gas estimate: {evm_call:?} {call_info:?}",
                );
            }
            _ => panic!("Unexpected pallet_evm::Call type"),
        }
    };

    let gas_price = alice
        .client
        .runtime_api()
        .gas_price(alice.client.info().best_hash)
        .unwrap();
    // Estimates
    let evm_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[0].address)
        .unwrap()
        .nonce;
    let evm_create = generate_evm_domain_call::<TestRuntime>(
        account_infos[0].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    test_estimate_gas(evm_create, true);

    let evm_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[0].address)
        .unwrap()
        .nonce;
    let evm_call = generate_evm_domain_call::<TestRuntime>(
        account_infos[0].clone(),
        ethereum::TransactionAction::Call(H160::zero()),
        0,
        evm_nonce,
        gas_price,
    );
    test_estimate_gas(evm_call, true);

    // Really do it, using runtime API calls
    let evm_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[0].address)
        .unwrap()
        .nonce;
    let evm_create = generate_evm_domain_call::<TestRuntime>(
        account_infos[0].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    test_estimate_gas(evm_create, false);

    let evm_contract_address = contract_address(account_infos[0].address, evm_nonce.as_u64());

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let evm_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[0].address)
        .unwrap()
        .nonce;
    let evm_call = generate_evm_domain_call::<TestRuntime>(
        account_infos[0].clone(),
        ethereum::TransactionAction::Call(evm_contract_address),
        0,
        evm_nonce,
        gas_price,
    );
    test_estimate_gas(evm_call, false);

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Really do it, using construct_and_send_extrinsic()
    let evm_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[0].address)
        .unwrap()
        .nonce;
    let evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[0].clone(),
        ethereum::TransactionAction::Create,
        0,
        evm_nonce,
        gas_price,
    );
    let evm_contract_address = contract_address(account_infos[0].address, evm_nonce.as_u64());

    // Use alice's account ID, which does the signing in construct_and_send_extrinsic()
    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send signed extrinsic"
    );

    // Produce a bundle that contains just the sent extrinsics
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);
    assert_eq!(
        receipt.block_fees().clone(),
        // Check the actual block fees for an EVM contract create
        BlockFees {
            consensus_storage_fee: 789,
            domain_execution_fee: 10_813_273_629_579_568,
            burned_balance: 0,
            chain_rewards: [].into(),
        }
    );

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let evm_nonce = alice
        .client
        .runtime_api()
        .account_basic(alice.client.info().best_hash, account_infos[0].address)
        .unwrap()
        .nonce;
    let evm_tx = generate_evm_domain_call::<TestRuntime>(
        account_infos[0].clone(),
        ethereum::TransactionAction::Call(evm_contract_address),
        0,
        evm_nonce,
        gas_price,
    );

    // Use alice's account ID, which does the signing in construct_and_send_extrinsic()
    let result = alice.construct_and_send_extrinsic(evm_tx).await;
    assert_matches!(
        result,
        Ok(_),
        "Unexpectedly failed to send signed extrinsic"
    );

    // Produce a bundle that contains just the sent extrinsics
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);
    assert_eq!(
        receipt.block_fees().clone(),
        // Check the actual block fees for an EVM contract call
        BlockFees {
            consensus_storage_fee: 849,
            domain_execution_fee: 10_812_720_677_240_620,
            burned_balance: 0,
            chain_rewards: [].into(),
        }
    );

    produce_blocks!(ferdie, alice, 3).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_instance_bootstrapper() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    let expected_genesis_state_root = ferdie
        .client
        .runtime_api()
        .genesis_state_root(ferdie.client.info().best_hash, EVM_DOMAIN_ID)
        .unwrap()
        .unwrap();

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    let genesis_state_root = *alice
        .client
        .header(alice.client.info().genesis_hash)
        .unwrap()
        .unwrap()
        .state_root();

    assert_eq!(expected_genesis_state_root, genesis_state_root);

    produce_blocks!(ferdie, alice, 3)
        .await
        .expect("3 consensus blocks produced successfully");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_chain_fork_choice() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();
    assert_eq!(alice.client.info().best_number, 3);

    let domain_hash_3 = alice.client.info().best_hash;
    let common_consensus_hash = ferdie.client.info().best_hash;

    // Fork A produce a consenus block that contains no bundle
    let slot = ferdie.produce_slot();
    let fork_a_block_hash = ferdie
        .produce_block_with_slot_at(slot, common_consensus_hash, Some(vec![]))
        .await
        .unwrap();

    let mut alice_import_notification_stream = alice.client.every_import_notification_stream();

    // Fork B produce a consenus block that contains bundles
    let (slot, _) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let fork_b_block_hash = ferdie
        .produce_block_with_slot_at(slot, common_consensus_hash, None)
        .await
        .unwrap();

    // Fork B is still in the non-canonical fork thus the consensus block and bundle
    // won't be processed
    assert!(alice_import_notification_stream.try_recv().is_err());

    // The consensus fork A is still the best fork, because fork A don't derive any new
    // domain block thus the best domain block is still #3
    assert_eq!(ferdie.client.info().best_hash, fork_a_block_hash);
    assert_eq!(alice.client.info().best_number, 3);
    assert_eq!(alice.client.info().best_hash, domain_hash_3);

    // Produce one more consensus block on fork B to make it the best fork
    let (slot, _) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let fork_b_block_hash = ferdie
        .produce_block_with_slot_at(slot, fork_b_block_hash, Some(vec![]))
        .await
        .unwrap();
    assert_eq!(ferdie.client.info().best_hash, fork_b_block_hash);

    // It should also trigger the operator to processe consensus blocks at fork B
    // thus produce more domain blocks
    let domain_block_4 = alice_import_notification_stream.next().await.unwrap();
    assert_eq!(*domain_block_4.header.number(), 4);
    assert_eq!(alice.client.info().best_number, 4);
    assert_eq!(alice.client.info().best_hash, domain_block_4.header.hash());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_block_production() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    for i in 0..50 {
        let (tx, slot) = if i % 2 == 0 {
            // Produce bundle and include it in the primary block hence produce a domain block
            let (slot, _) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
            // `None` means collect tx from the tx pool
            (None, slot)
        } else {
            // No bundle hence not produce domain block
            (Some(vec![]), ferdie.produce_slot())
        };
        ferdie
            .produce_block_with_slot_at(slot, ferdie.client.info().best_hash, tx)
            .await
            .unwrap();
    }
    // Domain block only produced when there is bundle contains in the primary block
    assert_eq!(ferdie.client.info().best_number, 50);
    assert_eq!(alice.client.info().best_number, 25);

    let consensus_block_hash = ferdie.client.info().best_hash;
    let domain_block_number = alice.client.info().best_number;
    let domain_block_hash = alice.client.info().best_hash;

    // Fork A
    // Produce 5 more primary blocks and producing domain block for every primary block
    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Record the block hashes for later use
    let mut fork_b_parent_hash = ferdie.client.info().best_hash;
    let fork_a_block_hash_3 = alice.client.info().best_hash;

    produce_blocks!(ferdie, alice, 2).await.unwrap();
    assert_eq!(alice.client.info().best_number, domain_block_number + 5);

    // Fork B
    // Produce 6 more primary blocks but only producing 3 domain blocks because there are
    // more primary block on fork B, it will become the best fork of the domain chain
    for _ in 0..3 {
        let slot = ferdie.produce_slot();
        fork_b_parent_hash = ferdie
            .produce_block_with_slot_at(slot, fork_b_parent_hash, Some(vec![]))
            .await
            .unwrap();
    }
    assert_eq!(alice.client.info().best_number, domain_block_number + 3);
    assert_eq!(alice.client.info().best_hash, fork_a_block_hash_3);

    // Fork C
    // Produce 10 more primary blocks and do not produce any domain block but because there are
    // more primary block on fork C, it will become the best fork of the domain chain
    let mut fork_c_parent_hash = consensus_block_hash;
    for _ in 0..10 {
        let slot = ferdie.produce_slot();
        fork_c_parent_hash = ferdie
            .produce_block_with_slot_at(slot, fork_c_parent_hash, Some(vec![]))
            .await
            .unwrap();
    }
    // The best block fall back to an ancestor block
    assert_eq!(alice.client.info().best_number, domain_block_number);
    assert_eq!(alice.client.info().best_hash, domain_block_hash);

    // Simply producing more block on fork C
    for _ in 0..10 {
        let (slot, opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        let tx = ferdie
            .construct_unsigned_extrinsic(pallet_domains::Call::submit_bundle { opaque_bundle })
            .into();
        // Produce consensus block that only contains the `submit_bundle` extrinsic instead of
        // any extrinsic in the tx pool, because the background worker `txpool-notifications` may
        // submit extrinsic from the retracted blocks of other fork to the tx pool and these tx
        // is invalid in the fork C
        ferdie
            .produce_block_with_slot_at(slot, ferdie.client.info().best_hash, Some(vec![tx]))
            .await
            .unwrap();
    }
    assert_eq!(alice.client.info().best_number, domain_block_number + 10);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_processing_empty_consensus_block() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    let domain_block_processor = DomainBlockProcessor {
        domain_id: alice.domain_id,
        domain_created_at: 1,
        client: alice.client.clone(),
        consensus_client: ferdie.client.clone(),
        backend: alice.backend.clone(),
        block_import: Arc::new(Box::new(alice.client.clone())),
        import_notification_sinks: Default::default(),
        domain_sync_oracle: ferdie.sync_service.clone(),
        domain_executor: alice.code_executor.clone(),
        challenge_period: 100u32,
    };

    let domain_genesis_hash = alice.client.info().best_hash;
    for _ in 0..10 {
        // Produce consensus block with no tx thus no bundle
        let slot = ferdie.produce_slot();
        ferdie
            .produce_block_with_slot_at(slot, ferdie.client.info().best_hash, Some(vec![]))
            .await
            .unwrap();

        let consensus_best_hash = ferdie.client.info().best_hash;
        let consensus_best_number = ferdie.client.info().best_number;
        let res = domain_block_processor
            .pending_imported_consensus_blocks(consensus_best_hash, consensus_best_number);
        match res {
            // The consensus block is processed in the above `produce_block_with_extrinsics` call,
            // thus calling `pending_imported_consensus_blocks` again will result in an `Ok(None)`
            Ok(None) => {
                // The `latest_consensus_block` that mapped to the genesis domain block must be updated
                let latest_consensus_block: Hash =
                    crate::aux_schema::latest_consensus_block_hash_for(
                        &*alice.backend,
                        &domain_genesis_hash,
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(latest_consensus_block, consensus_best_hash);
            }
            // For consensus block at `domain_created_at + 1` (namely block #2), `pending_imported_consensus_blocks`
            // will return `PendingConsensusBlocks` directly
            Ok(Some(PendingConsensusBlocks {
                initial_parent,
                consensus_imports,
            })) if consensus_best_number == 2 => {
                assert_eq!(initial_parent.0, domain_genesis_hash);
                assert_eq!(consensus_imports.len(), 1);
                assert_eq!(consensus_imports[0].hash, consensus_best_hash,);
            }
            _ => panic!("unexpected result: {res:?}"),
        }
    }
    // The domain chain is not progressed as all the consensus blocks are empty
    assert_eq!(ferdie.client.info().best_number, 10);
    assert_eq!(alice.client.info().best_number, 0);

    // To process non-empty consensus blocks and produce domain blocks
    produce_blocks!(ferdie, alice, 3).await.unwrap();
    assert_eq!(alice.client.info().best_number, 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_block_deriving_from_multiple_bundles() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let pre_eve_free_balance = alice.free_balance(Eve.to_account_id());
    for caller in [Alice, Bob, Charlie] {
        let tx = domain_test_service::construct_extrinsic_generic::<
            evm_domain_test_runtime::Runtime,
            _,
        >(
            &alice.client,
            pallet_balances::Call::transfer_allow_death {
                dest: Eve.to_account_id(),
                value: 1,
            },
            caller,
            false,
            0,
            0u128,
        );
        alice
            .send_extrinsic(tx)
            .await
            .expect("Failed to send extrinsic");

        // Produce a bundle and submit to the tx pool of the consensus node
        let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        assert_eq!(bundle.extrinsics().len(), 1);
    }

    let slot = ferdie.produce_slot();
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert_eq!(
        alice.free_balance(Eve.to_account_id()),
        pre_eve_free_balance + 3
    );
    let domain_block_number = alice.client.info().best_number;

    // Produce one more bundle to submit the receipt of the above 3 bundles
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // The receipt should be submitted successfully thus head receipt number
    // is updated
    let head_receipt_number = ferdie
        .client
        .runtime_api()
        .head_receipt_number(ferdie.client.info().best_hash, 0u32.into())
        .unwrap();
    assert_eq!(domain_block_number, head_receipt_number);
}

// This test is more unstable on macOS
// TODO: find and fix the source of the instability (#3385)
#[cfg(not(target_os = "macos"))]
#[tokio::test(flavor = "multi_thread")]
async fn collected_receipts_should_be_on_the_same_branch_with_current_best_block() {
    use sp_domains::bundle::Bundle;

    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut consensus_node = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut consensus_node)
    .await;

    produce_blocks!(consensus_node, alice, 3)
        .await
        .expect("3 consensus blocks produced successfully");

    let best_consensus_hash = consensus_node.client.info().best_hash;
    let best_consensus_number = consensus_node.client.info().best_number;
    assert_eq!(best_consensus_number, 3);

    assert_eq!(alice.client.info().best_number, 3);
    let domain_block_2_hash = *alice
        .client
        .header(alice.client.info().best_hash)
        .unwrap()
        .unwrap()
        .parent_hash();

    let best_header = consensus_node
        .client
        .header(best_consensus_hash)
        .unwrap()
        .unwrap();

    let parent_hash = *best_header.parent_hash();

    // Consensus chain forks:
    //      3
    //   /
    // 2 -- 3a
    //   \
    //      3b -- 4
    let slot = consensus_node.produce_slot();
    let fork_block_hash_3a = consensus_node
        .produce_block_with_slot_at(slot, parent_hash, Some(vec![]))
        .await
        .expect("Produced first consensus fork block 3a at height #3");
    // A fork block 3a at #3 produced.
    assert_eq!(number_of(&consensus_node, fork_block_hash_3a), 3);
    assert_ne!(fork_block_hash_3a, best_consensus_hash);
    // Best hash unchanged due to the longest chain fork choice.
    assert_eq!(consensus_node.client.info().best_hash, best_consensus_hash);
    // Hash of block number #3 unchanged.
    assert_eq!(
        consensus_node.client.hash(3).unwrap().unwrap(),
        best_consensus_hash
    );

    let consensus_block_info =
        |best_header: Header| -> (u32, Hash) { (*best_header.number(), best_header.hash()) };
    let receipts_consensus_info =
        |bundle: Bundle<OpaqueExtrinsic, u32, sp_core::H256, Header, Balance>| {
            (
                *bundle.receipt().to_owned_er().consensus_block_number(),
                *bundle.receipt().to_owned_er().consensus_block_hash(),
            )
        };

    // Produce a bundle after the fork block #3a has been produced.
    let signed_bundle = consensus_node
        .notify_new_slot_and_wait_for_bundle(slot)
        .await;

    let expected_receipts_consensus_info = consensus_block_info(best_header.clone());

    // TODO: make MaximumReceiptDrift configurable in order to submit all the pending receipts at
    // once, now the max drift is 2, the receipts is limitted to [2, 3]. Once configurable, we
    // can make the assertation straightforward:
    // assert_eq!(receipts_consensus_info, expected_receipts_consensus_info).
    //
    // Receipts are always collected against the current best block.
    assert_eq!(
        receipts_consensus_info(signed_bundle.unwrap()),
        expected_receipts_consensus_info
    );

    let slot = consensus_node.produce_slot();
    let fork_block_hash_3b = consensus_node
        .produce_block_with_slot_at(slot, parent_hash, Some(vec![]))
        .await
        .expect("Produced second consensus fork block 3b at height #3");
    // Another fork block 3b at #3 produced,
    assert_eq!(number_of(&consensus_node, fork_block_hash_3b), 3);
    assert_ne!(fork_block_hash_3b, best_consensus_hash);
    // Best hash unchanged due to the longest chain fork choice.
    assert_eq!(consensus_node.client.info().best_hash, best_consensus_hash);
    // Hash of block number #3 unchanged.
    assert_eq!(
        consensus_node.client.hash(3).unwrap().unwrap(),
        best_consensus_hash
    );

    // Produce a bundle after the fork block #3b has been produced.
    let signed_bundle = consensus_node
        .notify_new_slot_and_wait_for_bundle(slot)
        .await;
    // Receipts are always collected against the current best block.
    assert_eq!(
        receipts_consensus_info(signed_bundle.unwrap()),
        expected_receipts_consensus_info
    );

    // Produce a new tip at #4.
    let slot = consensus_node.produce_slot();
    produce_block_with!(
        consensus_node.produce_block_with_slot_at(slot, fork_block_hash_3b, Some(vec![])),
        alice
    )
    .await
    .expect("Produce a new block on top of the second fork block at height #3");
    let new_best_hash = consensus_node.client.info().best_hash;
    let new_best_number = consensus_node.client.info().best_number;
    assert_eq!(new_best_number, 4);

    // The domain best block should be reverted to #2 because the primary block #3b and #4 do
    // not contains any bundles
    assert_eq!(alice.client.info().best_number, 2);
    assert_eq!(alice.client.info().best_hash, domain_block_2_hash);

    // Hash of block number #3 is updated to the second fork block 3b.
    assert_eq!(
        consensus_node.client.hash(3).unwrap().unwrap(),
        fork_block_hash_3b
    );

    let new_best_header = consensus_node
        .client
        .header(new_best_hash)
        .unwrap()
        .unwrap();

    assert_eq!(*new_best_header.parent_hash(), fork_block_hash_3b);

    // Produce a bundle after the new block #4 has been produced.
    let (_slot, signed_bundle) = consensus_node
        .produce_slot_and_wait_for_bundle_submission()
        .await;

    // In the new best fork, the receipt header number is 1 thus it produce the receipt
    // of next block namely block 2
    let hash_2 = consensus_node.client.hash(2).unwrap().unwrap();
    let header_2 = consensus_node.client.header(hash_2).unwrap().unwrap();
    assert_eq!(
        receipts_consensus_info(signed_bundle),
        consensus_block_info(header_2)
    );
}

// This test hangs occasionally, but we don't know which step hangs.
// TODO: when the test is fixed, decide if we want to remove the timeouts.
#[tokio::test(flavor = "multi_thread")]
async fn test_domain_tx_propagate() -> Result<(), tokio::time::error::Elapsed> {
    let test = "test_domain_tx_propagate";
    info!("{test}: Setting up Ferdie and Alice nodes");
    let (directory, mut ferdie, alice) =
        setup_evm_test_nodes(Ferdie, false, None).timeout().await?;

    info!("{test}: Setting up Bob Full node, and connecting to Alice");
    // Run Bob (a evm domain full node)
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio::runtime::Handle::current(),
        BasePath::new(directory.path().join("bob")),
    )
    .connect_to_domain_node(alice.addr.clone())
    .build_evm_node(Role::Full, Bob, &mut ferdie)
    .timeout()
    .await?;

    info!("{test}: Producing 5 blocks");
    produce_blocks!(ferdie, alice, 5, bob)
        .timeout()
        .await?
        .unwrap();

    info!("{test}: Waiting for Alice and Bob to sync");
    async {
        while alice.sync_service.is_major_syncing() || bob.sync_service.is_major_syncing() {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            // TODO: Unfortunately, this test contains a race condition where Alice sometimes bans
            // Bob for making multiple requests for the same block. And in response to that ban's
            // reject message, Bob bans Alice.
            alice.unban_peer(bob.addr.clone());
            bob.unban_peer(alice.addr.clone());
        }
    }
    .timeout()
    .await?;

    info!("{test}: Transferring balance on Bob");
    let pre_bob_free_balance = alice.free_balance(bob.key.to_account_id());
    // Construct and send an extrinsic to bob, as bob is not a authority node, the extrinsic has
    // to propagate to alice to get executed
    bob.construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
        dest: Alice.to_account_id(),
        value: 123,
    })
    .timeout()
    .await?
    .expect("Failed to send extrinsic");

    info!("{test}: Waiting for transaction to propagate to Alice and be executed");
    produce_blocks_until!(
        ferdie,
        alice,
        {
            alice.unban_peer(bob.addr.clone());
            bob.unban_peer(alice.addr.clone());
            // ensure bob has reduced balance since alice might submit other transactions which cost
            // and so exact balance check is not feasible
            alice.free_balance(bob.key.to_account_id()) <= pre_bob_free_balance - 123
        },
        bob
    )
    .timeout()
    .await?
    .unwrap();

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_executor_full_node_catching_up() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );
    // Produce 5 consensus block to initialize genesis domain
    //
    // This also make the first consensus block being processed by the alice's domain
    // block processor be block #5, to ensure it can correctly handle the consensus
    // block even it is out of order.
    for _ in 0..5 {
        let slot = ferdie.produce_slot();
        ferdie.produce_block_with_slot(slot).await.unwrap();
    }

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run Bob (a evm domain full node)
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle,
        BasePath::new(directory.path().join("bob")),
    )
    .build_evm_node(Role::Full, Bob, &mut ferdie)
    .await;

    // Bob is able to sync blocks.
    produce_blocks!(ferdie, alice, 3, bob).await.unwrap();

    let alice_block_hash = alice
        .client
        .expect_block_hash_from_id(&BlockId::Number(2))
        .unwrap();
    let bob_block_hash = bob
        .client
        .expect_block_hash_from_id(&BlockId::Number(2))
        .unwrap();
    assert_eq!(
        alice_block_hash, bob_block_hash,
        "Domain authority node and full node must have the same state"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_executor_inherent_timestamp_is_set() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run Bob who runs the authority node for core domain
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("bob")),
    )
    .build_evm_node(Role::Authority, Bob, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 1, bob).await.unwrap();

    let consensus_timestamp = ferdie
        .client
        .runtime_api()
        .domain_timestamp(ferdie.client.info().best_hash)
        .unwrap();

    let domain_timestamp = bob
        .client
        .runtime_api()
        .domain_timestamp(bob.client.info().best_hash)
        .unwrap();

    assert_eq!(
        consensus_timestamp, domain_timestamp,
        "Timestamp should be preset on domain and must match Consensus runtime timestamp"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bad_invalid_bundle_fraud_proof_is_rejected() {
    let (_directory, mut ferdie, alice) = setup_evm_test_nodes(Ferdie, false, None).await;

    let fraud_proof_generator = FraudProofGenerator::new(
        alice.client.clone(),
        ferdie.client.clone(),
        alice.backend.clone(),
        alice.code_executor.clone(),
    );

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let mut bundles = vec![];
    let alice_nonce = alice.account_nonce();
    for (i, acc) in [Bob, Charlie, Dave].into_iter().enumerate() {
        let tx = alice.construct_extrinsic(
            alice_nonce + i as u32,
            pallet_balances::Call::transfer_allow_death {
                dest: acc.to_account_id(),
                value: 12334567890987654321,
            },
        );
        alice
            .send_extrinsic(tx)
            .await
            .expect("Failed to send extrinsic");
    }
    let (_, valid_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(valid_bundle.extrinsics().len(), 3);
    bundles.push(valid_bundle.clone());

    // UndecodableTx
    bundles.push({
        let (_, mut b) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        let undecodable_tx =
            OpaqueExtrinsic::from_bytes(&rand::random::<[u8; 5]>().to_vec().encode())
                .expect("raw byte encoding and decoding never fails; qed");
        let mut exts = b.extrinsics().to_vec();
        exts.push(undecodable_tx);
        exts.extend_from_slice(valid_bundle.extrinsics());
        b.set_extrinsics(exts);
        b
    });

    // IllegalTx
    bundles.push({
        let (_, mut b) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        let illegal_tx = alice
            .construct_extrinsic(
                alice_nonce, // stale nonce
                pallet_balances::Call::transfer_allow_death {
                    dest: Eve.to_account_id(),
                    value: 12334567890987654321,
                },
            )
            .into();
        let mut exts = b.extrinsics().to_vec();
        exts.extend_from_slice(valid_bundle.extrinsics());
        exts.push(illegal_tx);
        b.set_extrinsics(exts);
        b
    });

    // InvalidXDM
    bundles.push({
        let (_, mut b) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        let invalid_xdm = evm_domain_test_runtime::UncheckedExtrinsic::new_bare(
            pallet_messenger::Call::relay_message {
                msg: CrossDomainMessage {
                    src_chain_id: ChainId::Consensus,
                    dst_chain_id: ChainId::Domain(EVM_DOMAIN_ID),
                    channel_id: Default::default(),
                    nonce: Default::default(),
                    proof: Proof::Domain {
                        consensus_chain_mmr_proof: ConsensusChainMmrLeafProof {
                            consensus_block_number: 1,
                            consensus_block_hash: Default::default(),
                            opaque_mmr_leaf: EncodableOpaqueLeaf(vec![0, 1, 2]),
                            proof: MmrProof {
                                leaf_indices: vec![],
                                leaf_count: 0,
                                items: vec![],
                            },
                        },
                        domain_proof: StorageProof::empty(),
                        message_proof: StorageProof::empty(),
                    },
                    weight_tag: Default::default(),
                },
            }
            .into(),
        )
        .into();
        let mut exts = b.extrinsics().to_vec();
        exts.push(invalid_xdm);
        b.set_extrinsics(exts);
        b
    });

    // InherentTx
    bundles.push({
        let (_, mut b) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        let inherent_tx = subspace_test_runtime::UncheckedExtrinsic::new_bare(
            pallet_timestamp::Call::set { now: 12345 }.into(),
        )
        .into();
        let mut exts = b.extrinsics().to_vec();
        exts.extend_from_slice(valid_bundle.extrinsics());
        exts[1] = inherent_tx;
        b.set_extrinsics(exts);
        b
    });

    // InvalidBundleWeight
    bundles.push({
        let (_, mut b) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        b.set_estimated_bundle_weight(Weight::from_all(123456));
        b
    });

    let submit_bundle_txs: Vec<_> = bundles
        .into_iter()
        .map(|mut opaque_bundle| {
            let extrinsics = opaque_bundle
                .extrinsics()
                .iter()
                .map(|ext| ext.encode())
                .collect();
            opaque_bundle.set_bundle_extrinsics_root(BlakeTwo256::ordered_trie_root(
                extrinsics,
                StateVersion::V1,
            ));
            opaque_bundle.set_signature(
                Sr25519Keyring::Alice
                    .pair()
                    .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                    .into(),
            );
            ferdie
                .construct_unsigned_extrinsic(pallet_domains::Call::submit_bundle { opaque_bundle })
                .into()
        })
        .collect();

    assert_eq!(submit_bundle_txs.len(), 6);

    // Produce a block that contains all the bundle
    produce_block_with!(
        ferdie.produce_block_with_extrinsics(submit_bundle_txs),
        alice
    )
    .await
    .unwrap();

    // Get the receipt of that domain block and produce another bundle to submit the receipt
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    let valid_receipt = bundle.into_receipt();
    let valid_receipt_hash = valid_receipt.hash::<BlakeTwo256>();
    assert_eq!(valid_receipt.execution_traces().len(), 7);
    assert_eq!(valid_receipt.inboxed_bundles().len(), 6);

    // Produce all possible invalid fraud proof
    for bundle_index in 0..6 {
        for extrinsic_index in 0..4 {
            for is_good_invalid_fraud_proof in [true, false] {
                for invalid_type in 0..6 {
                    let invalid_bundle_type = match invalid_type {
                        0 => InvalidBundleType::UndecodableTx(extrinsic_index),
                        // TODO: We use `U256::MAX` as the tx range in the test to ensure all
                        // extrinsic will be included by the bundle but in production the fraud
                        // proof verification use `U256::MAX/3` thus the invalid OutOfRangeTx
                        // frauf proof may be accepted, need to workaround to add this test case
                        // 1 => InvalidBundleType::OutOfRangeTx(extrinsic_index),
                        2 => InvalidBundleType::IllegalTx(extrinsic_index),
                        3 => InvalidBundleType::InvalidXDM(extrinsic_index),
                        4 => InvalidBundleType::InherentExtrinsic(extrinsic_index),
                        5 if extrinsic_index == 0 => InvalidBundleType::InvalidBundleWeight,
                        _ => continue,
                    };
                    let mismatch_type = if is_good_invalid_fraud_proof {
                        BundleMismatchType::GoodInvalid(invalid_bundle_type)
                    } else {
                        BundleMismatchType::BadInvalid(invalid_bundle_type)
                    };
                    let res = fraud_proof_generator.generate_invalid_bundle_proof_for_test(
                        EVM_DOMAIN_ID,
                        &valid_receipt,
                        mismatch_type,
                        bundle_index,
                        valid_receipt_hash,
                        true,
                    );

                    let fp = match res {
                        Ok(fp) => fp,
                        Err(_) => {
                            // There are some invalid fraud proofs are impossible to construct
                            // e.g. the execution proof can't construct for the undecodable tx
                            continue;
                        }
                    };

                    let submit_fraud_proof_extrinsic = ferdie
                        .construct_unsigned_extrinsic(pallet_domains::Call::submit_fraud_proof {
                            fraud_proof: Box::new(fp),
                        })
                        .into();

                    let res = ferdie
                        .submit_transaction(submit_fraud_proof_extrinsic)
                        .await;

                    assert!(matches!(
                        res,
                        Err(TxPoolInvalidTransaction(
                            InvalidTransaction::Custom(tx_code)
                        )) if tx_code == InvalidTransactionCode::FraudProof as u8
                    ));
                }
            }
        }
    }

    ferdie.produce_blocks(1).await.unwrap();
    assert!(ferdie.does_receipt_exist(valid_receipt_hash).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bad_fraud_proof_is_rejected() {
    let (_directory, mut ferdie, alice) = setup_evm_test_nodes(Ferdie, true, Sr25519Alice).await;

    let fraud_proof_generator = FraudProofGenerator::new(
        alice.client.clone(),
        ferdie.client.clone(),
        alice.backend.clone(),
        alice.code_executor.clone(),
    );

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 12334567890987654321,
        })
        .await
        .expect("Failed to send extrinsic");

    ferdie
        .construct_and_send_extrinsic_with(
            pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
                domain_id: EVM_DOMAIN_ID,
                contract_creation_allowed_by: PermissionedActionAllowedBy::Anyone,
            },
        )
        .await
        .expect("Failed to send extrinsic");

    // Produce a domain block that contains the previously sent extrinsics
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // Get the receipt of that domain block and produce another bundle to submit the receipt
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    let valid_receipt = bundle.into_receipt();
    let valid_receipt_hash = valid_receipt.hash::<BlakeTwo256>();
    assert_eq!(valid_receipt.execution_traces().len(), 5);

    let mut fraud_proofs = vec![
        fraud_proof_generator
            .generate_valid_bundle_proof(EVM_DOMAIN_ID, &valid_receipt, 0, valid_receipt_hash)
            .unwrap(),
    ];

    fraud_proofs.push(
        fraud_proof_generator
            .generate_invalid_domain_extrinsics_root_proof(
                EVM_DOMAIN_ID,
                &valid_receipt,
                valid_receipt_hash,
            )
            .unwrap(),
    );

    fraud_proofs.push(
        fraud_proof_generator
            .generate_invalid_block_fees_proof(EVM_DOMAIN_ID, &valid_receipt, valid_receipt_hash)
            .unwrap(),
    );

    fraud_proofs.push(
        fraud_proof_generator
            .generate_invalid_transfers_proof(EVM_DOMAIN_ID, &valid_receipt, valid_receipt_hash)
            .unwrap(),
    );

    fraud_proofs.push(
        fraud_proof_generator
            .generate_invalid_domain_block_hash_proof(
                EVM_DOMAIN_ID,
                &valid_receipt,
                valid_receipt_hash,
            )
            .unwrap(),
    );

    for fp in fraud_proofs {
        let submit_fraud_proof_extrinsic = ferdie
            .construct_unsigned_extrinsic(pallet_domains::Call::submit_fraud_proof {
                fraud_proof: Box::new(fp),
            })
            .into();

        let res = ferdie
            .submit_transaction(submit_fraud_proof_extrinsic)
            .await;

        assert!(matches!(
            res,
            Err(TxPoolInvalidTransaction(
                InvalidTransaction::Custom(tx_code)
            )) if tx_code == InvalidTransactionCode::FraudProof as u8
        ));
    }

    ferdie.produce_blocks(1).await.unwrap();
    assert!(ferdie.does_receipt_exist(valid_receipt_hash).unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_bad_invalid_state_transition_proof_is_rejected() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    let fraud_proof_generator = FraudProofGenerator::new(
        alice.client.clone(),
        ferdie.client.clone(),
        alice.backend.clone(),
        alice.code_executor.clone(),
    );

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // We get the receipt of target bundle
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let valid_receipt = bundle.into_receipt();
    assert_eq!(valid_receipt.execution_traces().len(), 5);
    let valid_receipt_hash = valid_receipt.hash::<BlakeTwo256>();

    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // trace index 0 is the index of the state root after applying DomainCoreApi::initialize_block_with_post_state_root
    // trace index 1 is the index of the state root after applying inherent timestamp extrinsic
    // trace index 2 is the index of the state root after applying above balance transfer extrinsic
    // trace index 3 is the index of the state root after applying BlockBuilder::finalize_block
    for trace_diff_type in [
        TraceDiffType::Mismatch,
        TraceDiffType::Shorter,
        TraceDiffType::Longer,
    ] {
        for mismatch_index in 0..valid_receipt.execution_traces().len() {
            let dummy_execution_trace = match trace_diff_type {
                TraceDiffType::Shorter => valid_receipt
                    .execution_traces()
                    .to_vec()
                    .drain(..)
                    .take(mismatch_index + 1)
                    .collect(),
                TraceDiffType::Longer => {
                    let mut long_trace = valid_receipt.execution_traces().to_vec();
                    long_trace.push(H256::default());
                    long_trace
                }
                TraceDiffType::Mismatch => {
                    let mut modified_trace = valid_receipt.execution_traces().to_vec();
                    modified_trace[mismatch_index] = H256::default();
                    modified_trace
                }
            };

            // For some combination of (TraceDiffType, mismatch_trace_index) there is no difference in trace
            // In this case the fraud proof cannot be generated.
            if valid_receipt.execution_traces().to_vec() == dummy_execution_trace {
                continue;
            }

            // Abusing this method to generate every possible variant of ExecutionPhase
            let result_execution_phase = fraud_proof_generator.find_mismatched_execution_phase(
                *valid_receipt.domain_block_hash(),
                valid_receipt.execution_traces(),
                &dummy_execution_trace,
            );

            assert!(result_execution_phase.is_ok());
            assert!(
                result_execution_phase
                    .as_ref()
                    .is_ok_and(|maybe_execution_phase| maybe_execution_phase.is_some())
            );

            let execution_phase = result_execution_phase
                .expect("already checked for error above; qed")
                .expect("we already checked for  None above; qed");

            let mut fraud_proof = fraud_proof_generator
                .generate_invalid_state_transition_proof(
                    EVM_DOMAIN_ID,
                    execution_phase,
                    &valid_receipt,
                    dummy_execution_trace.len(),
                    valid_receipt_hash,
                )
                .expect(
                    "Fraud proof generation should succeed for every valid execution phase; qed",
                );

            let submit_fraud_proof_extrinsic = ferdie
                .construct_unsigned_extrinsic(pallet_domains::Call::submit_fraud_proof {
                    fraud_proof: Box::new(fraud_proof.clone()),
                })
                .into();

            let response = ferdie
                .submit_transaction(submit_fraud_proof_extrinsic)
                .await;

            assert!(matches!(
                response,
                Err(TxPoolInvalidTransaction(
                    InvalidTransaction::Custom(tx_code)
                )) if tx_code == InvalidTransactionCode::FraudProof as u8
            ));

            // To prevent receiving TemporarilyBanned error from the pool
            ferdie.clear_tx_pool().await.unwrap();

            // Modify fraud proof's mismatch index to a higher value and try to submit it.
            match &fraud_proof.proof {
                FraudProofVariant::InvalidStateTransition(invalid_state_transition_fraud_proof) => {
                    match &invalid_state_transition_fraud_proof.execution_phase {
                        ExecutionPhase::ApplyExtrinsic {
                            extrinsic_proof,
                            mismatch: ApplyExtrinsicMismatch::StateRoot(_),
                        } => {
                            let mut modified_invalid_state_transition_fraud_proof =
                                invalid_state_transition_fraud_proof.clone();
                            modified_invalid_state_transition_fraud_proof.execution_phase =
                                ExecutionPhase::ApplyExtrinsic {
                                    extrinsic_proof: extrinsic_proof.clone(),
                                    mismatch: ApplyExtrinsicMismatch::StateRoot(u32::MAX),
                                };
                            fraud_proof.proof = FraudProofVariant::InvalidStateTransition(
                                modified_invalid_state_transition_fraud_proof,
                            );
                        }
                        ExecutionPhase::FinalizeBlock {
                            mismatch: FinalizeBlockMismatch::Longer(_),
                        } => {
                            let mut modified_invalid_state_transition_fraud_proof =
                                invalid_state_transition_fraud_proof.clone();
                            modified_invalid_state_transition_fraud_proof.execution_phase =
                                ExecutionPhase::FinalizeBlock {
                                    mismatch: FinalizeBlockMismatch::Longer(u32::MAX),
                                };
                            fraud_proof.proof = FraudProofVariant::InvalidStateTransition(
                                modified_invalid_state_transition_fraud_proof,
                            );
                        }
                        _ => {}
                    }
                }
                _ => unreachable!(),
            }

            let submit_fraud_proof_with_invalid_mismatch_index_extrinsic = ferdie
                .construct_unsigned_extrinsic(pallet_domains::Call::submit_fraud_proof {
                    fraud_proof: Box::new(fraud_proof),
                })
                .into();

            let response = ferdie
                .submit_transaction(submit_fraud_proof_with_invalid_mismatch_index_extrinsic)
                .await;

            assert!(matches!(
                response,
                Err(TxPoolInvalidTransaction(
                    InvalidTransaction::Custom(tx_code)
                )) if tx_code == InvalidTransactionCode::FraudProof as u8
            ));

            // To prevent receiving TemporarilyBanned error from the pool
            ferdie.clear_tx_pool().await.unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_initialize_block_proof_creation_and_verification_should_work() {
    test_invalid_state_transition_proof_creation_and_verification(TraceDiffType::Mismatch, 0).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_apply_extrinsic_proof_inherent_ext_creation_and_verification_should_work() {
    test_invalid_state_transition_proof_creation_and_verification(TraceDiffType::Mismatch, 1).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_apply_extrinsic_proof_normal_ext_creation_and_verification_should_work() {
    test_invalid_state_transition_proof_creation_and_verification(TraceDiffType::Mismatch, 3).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_finalize_block_proof_creation_and_verification_should_work() {
    test_invalid_state_transition_proof_creation_and_verification(TraceDiffType::Mismatch, 4).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_short_trace_for_inherent_apply_extrinsic_proof_creation_and_verification_should_work()
{
    test_invalid_state_transition_proof_creation_and_verification(TraceDiffType::Shorter, 1).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_short_trace_for_normal_ext_apply_extrinsic_proof_creation_and_verification_should_work()
 {
    test_invalid_state_transition_proof_creation_and_verification(TraceDiffType::Shorter, 3).await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_long_trace_for_finalize_block_proof_creation_and_verification_should_work() {
    // In case of TraceDiffType::Longer the bad ER always has two more elements. So, no effect of
    // `mismatch_trace_index`
    test_invalid_state_transition_proof_creation_and_verification(TraceDiffType::Longer, 0).await
}

/// This test will create and verify a invalid state transition proof that targets the receipt of
/// a bundle that contains 2 extrinsic (including 1 inherent timestamp extrinsic), thus there are
/// 4 trace roots in total, passing the `mismatch_trace_index` as:
/// - 0 to test the `initialize_block` state transition
/// - 1 to test the `apply_extrinsic` state transition with the inherent timestamp extrinsic
/// - 2 to test the `apply_extrinsic` state transition with the inherent `set_consensus_chain_byte_fee` extrinsic
/// - 3 to test the `apply_extrinsic` state transition with regular domain extrinsic
/// - 4 to test the `finalize_block` state transition
///
/// TraceDiffType can be passed as `TraceDiffType::Shorter`, `TraceDiffType::Longer`
/// and `TraceDiffType::Mismatch`
async fn test_invalid_state_transition_proof_creation_and_verification(
    trace_diff_type: TraceDiffType,
    mismatch_trace_index: u32,
) {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let ExecutionReceiptRef::V0(receipt) = opaque_bundle.sealed_header().receipt();
    let original_length = receipt.execution_trace.len();
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(receipt) = opaque_bundle.execution_receipt_as_mut();
        assert_eq!(receipt.execution_trace.len(), 5);

        match trace_diff_type {
            TraceDiffType::Longer => {
                receipt.execution_trace.push(Default::default());
                receipt.execution_trace.push(Default::default());
            }
            TraceDiffType::Shorter => {
                receipt.execution_trace = receipt
                    .execution_trace
                    .clone()
                    .drain(..)
                    .take((mismatch_trace_index + 1) as usize)
                    .collect();
            }
            TraceDiffType::Mismatch => {
                receipt.execution_trace[mismatch_trace_index as usize] = Default::default();
            }
        }

        receipt.execution_trace_root = {
            let trace: Vec<_> = receipt
                .execution_trace
                .iter()
                .map(|t| t.encode().try_into().unwrap())
                .collect();
            MerkleTree::from_leaves(trace.as_slice())
                .root()
                .unwrap()
                .into()
        };
        receipt.final_state_root = *receipt.execution_trace.last().unwrap();
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidStateTransition(proof) = &fp.proof {
            match (trace_diff_type, mismatch_trace_index) {
                (TraceDiffType::Mismatch, mismatch_trace_index) => match mismatch_trace_index {
                    0 => assert!(matches!(
                        proof.execution_phase,
                        ExecutionPhase::InitializeBlock
                    )),
                    // 1 for the inherent timestamp extrinsic, 1 for the inherent `set_consensus_chain_byte_fee`
                    // extrinsic, 3 for the above `transfer_allow_death` extrinsic
                    1..=3 => assert!(matches!(
                        proof.execution_phase,
                        ExecutionPhase::ApplyExtrinsic {
                            mismatch: ApplyExtrinsicMismatch::StateRoot(trace_index),
                            ..
                        } if trace_index == mismatch_trace_index
                    )),
                    4 => assert!(matches!(
                        proof.execution_phase,
                        ExecutionPhase::FinalizeBlock {
                            mismatch: FinalizeBlockMismatch::StateRoot
                        }
                    )),
                    _ => unreachable!(),
                },
                (TraceDiffType::Shorter, _) => {
                    assert!(matches!(
                        proof.execution_phase,
                        ExecutionPhase::ApplyExtrinsic {
                            mismatch: ApplyExtrinsicMismatch::Shorter,
                            ..
                        }
                    ))
                }
                (TraceDiffType::Longer, _) => {
                    assert!(matches!(
                        proof.execution_phase,
                        ExecutionPhase::FinalizeBlock {
                            mismatch: FinalizeBlockMismatch::Longer(trace_index)
                        } if trace_index as usize == original_length - 1
                    ))
                }
            }
            true
        } else {
            false
        }
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    // When the system domain node process the primary block that contains `bad_submit_bundle_tx`,
    // it will generate and submit a fraud proof
    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_true_invalid_bundles_inherent_extrinsic_proof_creation_and_verification() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    let inherent_extrinsic = || {
        let now = 1234;
        subspace_test_runtime::UncheckedExtrinsic::new_bare(
            pallet_timestamp::Call::set { now }.into(),
        )
        .into()
    };

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let extrinsics: Vec<Vec<u8>>;
    let bundle_extrinsic_root;
    let bad_submit_bundle_tx = {
        let mut exts = opaque_bundle.extrinsics().to_vec();
        exts.push(inherent_extrinsic());
        opaque_bundle.set_extrinsics(exts);
        extrinsics = opaque_bundle
            .extrinsics()
            .iter()
            .map(|ext| ext.encode())
            .collect();
        bundle_extrinsic_root =
            BlakeTwo256::ordered_trie_root(extrinsics.clone(), StateVersion::V1);
        opaque_bundle.set_bundle_extrinsics_root(bundle_extrinsic_root);
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        bundle_to_tx(&ferdie, opaque_bundle)
    };

    // Produce a block that contains `bad_submit_bundle_tx`
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();

    // produce another bundle that marks the previous extrinsic as invalid.
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(bad_receipt) = opaque_bundle.execution_receipt_as_mut();
        // bad receipt marks this particular bundle as valid even though bundle contains inherent extrinsic
        bad_receipt.inboxed_bundles =
            vec![InboxedBundle::valid(H256::random(), bundle_extrinsic_root)];

        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidBundles(proof) = &fp.proof
            && let InvalidBundleType::InherentExtrinsic(_) = proof.invalid_bundle_type()
        {
            assert!(proof.is_good_invalid_fraud_proof());
            return true;
        }
        false
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_false_invalid_bundles_inherent_extrinsic_proof_creation_and_verification() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 1);
    let extrinsics: Vec<Vec<u8>> = target_bundle
        .extrinsics()
        .iter()
        .map(|ext| ext.encode())
        .collect();
    let bundle_extrinsic_root =
        BlakeTwo256::ordered_trie_root(extrinsics.clone(), StateVersion::V1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // produce another bundle that marks the previous valid extrinsic as invalid.
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(bad_receipt) = opaque_bundle.execution_receipt_as_mut();
        // bad receipt marks this particular bundle as invalid even though bundle does not contain
        // inherent extrinsic
        bad_receipt.inboxed_bundles = vec![InboxedBundle::invalid(
            InvalidBundleType::InherentExtrinsic(0),
            bundle_extrinsic_root,
        )];

        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidBundles(proof) = &fp.proof
            && let InvalidBundleType::InherentExtrinsic(_) = proof.invalid_bundle_type()
        {
            assert!(!proof.is_good_invalid_fraud_proof());
            return true;
        }
        false
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_true_invalid_bundles_undecodeable_tx_proof_creation_and_verification() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    let undecodable_tx = || {
        let undecodable_extrinsic = rand::random::<[u8; 5]>().to_vec();
        OpaqueExtrinsic::from_bytes(&undecodable_extrinsic.encode())
            .expect("raw byte encoding and decoding never fails; qed")
    };

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let extrinsics: Vec<Vec<u8>>;
    let bundle_extrinsic_root;
    let bad_submit_bundle_tx = {
        let mut exts = opaque_bundle.extrinsics().to_vec();
        exts.push(undecodable_tx());
        opaque_bundle.set_extrinsics(exts);
        extrinsics = opaque_bundle
            .extrinsics()
            .iter()
            .map(|ext| ext.encode())
            .collect();
        bundle_extrinsic_root =
            BlakeTwo256::ordered_trie_root(extrinsics.clone(), StateVersion::V1);
        opaque_bundle.set_bundle_extrinsics_root(bundle_extrinsic_root);
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        bundle_to_tx(&ferdie, opaque_bundle)
    };

    // Produce a block that contains `bad_submit_bundle_tx`
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();

    // produce another bundle that marks the previous extrinsic as invalid.
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(bad_receipt) = opaque_bundle.execution_receipt_as_mut();
        // bad receipt marks this particular bundle as valid even though bundle contains inherent extrinsic
        bad_receipt.inboxed_bundles =
            vec![InboxedBundle::valid(H256::random(), bundle_extrinsic_root)];

        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidBundles(proof) = &fp.proof
            && let InvalidBundleType::UndecodableTx(_) = proof.invalid_bundle_type()
        {
            assert!(proof.is_good_invalid_fraud_proof());
            return true;
        }
        false
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_false_invalid_bundles_undecodeable_tx_proof_creation_and_verification() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 1);
    let extrinsics: Vec<Vec<u8>> = target_bundle
        .extrinsics()
        .iter()
        .map(|ext| ext.encode())
        .collect();
    let bundle_extrinsic_root =
        BlakeTwo256::ordered_trie_root(extrinsics.clone(), StateVersion::V1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // produce another bundle that marks the previous valid extrinsic as invalid.
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(bad_receipt) = opaque_bundle.execution_receipt_as_mut();
        // bad receipt marks this particular bundle as invalid even though bundle does not contain
        // inherent extrinsic
        bad_receipt.inboxed_bundles = vec![InboxedBundle::invalid(
            InvalidBundleType::UndecodableTx(0),
            bundle_extrinsic_root,
        )];

        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidBundles(proof) = &fp.proof
            && let InvalidBundleType::UndecodableTx(_) = proof.invalid_bundle_type()
        {
            assert!(!proof.is_good_invalid_fraud_proof());
            return true;
        }
        false
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_true_invalid_bundles_illegal_xdm_proof_creation_and_verification() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 0);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

    let bundle_extrinsic_root;
    let bad_submit_bundle_tx = {
        let invalid_xdm = evm_domain_test_runtime::UncheckedExtrinsic::new_bare(
            pallet_messenger::Call::relay_message {
                msg: CrossDomainMessage {
                    src_chain_id: ChainId::Consensus,
                    dst_chain_id: ChainId::Domain(EVM_DOMAIN_ID),
                    channel_id: Default::default(),
                    nonce: Default::default(),
                    proof: Proof::Domain {
                        consensus_chain_mmr_proof: ConsensusChainMmrLeafProof {
                            consensus_block_number: 1,
                            consensus_block_hash: Default::default(),
                            opaque_mmr_leaf: EncodableOpaqueLeaf(vec![0, 1, 2]),
                            proof: MmrProof {
                                leaf_indices: vec![],
                                leaf_count: 0,
                                items: vec![],
                            },
                        },
                        domain_proof: StorageProof::empty(),
                        message_proof: StorageProof::empty(),
                    },
                    weight_tag: Default::default(),
                },
            }
            .into(),
        )
        .into();
        opaque_bundle.set_extrinsics(vec![invalid_xdm]);
        let extrinsics: Vec<Vec<u8>> = opaque_bundle
            .extrinsics()
            .iter()
            .map(|ext| ext.encode())
            .collect();
        bundle_extrinsic_root =
            BlakeTwo256::ordered_trie_root(extrinsics.clone(), StateVersion::V1);
        opaque_bundle.set_bundle_extrinsics_root(bundle_extrinsic_root);
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        bundle_to_tx(&ferdie, opaque_bundle)
    };

    // Produce a block that contains `bad_submit_bundle_tx`
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();

    // produce another bundle that marks the previous extrinsic as invalid.
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(bad_receipt) = opaque_bundle.execution_receipt_as_mut();
        // bad receipt marks this particular bundle as valid even though bundle contains illegal extrinsic
        bad_receipt.inboxed_bundles =
            vec![InboxedBundle::valid(H256::random(), bundle_extrinsic_root)];

        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidBundles(proof) = &fp.proof
            && let InvalidBundleType::InvalidXDM(extrinsic_index) = proof.invalid_bundle_type()
        {
            assert!(proof.is_good_invalid_fraud_proof());
            assert_eq!(extrinsic_index, 0);
            return true;
        }
        false
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    // Produce a block that contains `bad_submit_bundle_tx`
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_true_invalid_bundles_illegal_extrinsic_proof_creation_and_verification() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 0);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

    let alice_balance = alice.free_balance(Alice.to_account_id());
    let mut alice_nonce = alice.account_nonce();
    let transfer_to_charlie_with_big_tip_1 = alice.construct_extrinsic_with_tip(
        alice_nonce,
        alice_balance / 3,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 1,
        },
    );
    alice_nonce += 1;

    let transfer_to_charlie_with_big_tip_2 = alice.construct_extrinsic_with_tip(
        alice_nonce,
        alice_balance / 3,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 1,
        },
    );
    alice_nonce += 1;

    // This would be illegal
    let transfer_to_charlie_with_big_tip_3 = alice.construct_extrinsic_with_tip(
        alice_nonce,
        alice_balance / 3,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 1,
        },
    );

    let extrinsics: Vec<Vec<u8>>;
    let bundle_extrinsic_root;
    let bad_submit_bundle_tx = {
        opaque_bundle.set_extrinsics(vec![
            transfer_to_charlie_with_big_tip_1.into(),
            transfer_to_charlie_with_big_tip_2.into(),
            transfer_to_charlie_with_big_tip_3.into(),
        ]);
        extrinsics = opaque_bundle
            .extrinsics()
            .iter()
            .map(|ext| ext.encode())
            .collect();
        bundle_extrinsic_root =
            BlakeTwo256::ordered_trie_root(extrinsics.clone(), StateVersion::V1);
        opaque_bundle.set_bundle_extrinsics_root(bundle_extrinsic_root);
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        bundle_to_tx(&ferdie, opaque_bundle)
    };

    // Produce a block that contains `bad_submit_bundle_tx`
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();

    // produce another bundle that marks the previous extrinsic as invalid.
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(bad_receipt) = opaque_bundle.execution_receipt_as_mut();
        // bad receipt marks this particular bundle as valid even though bundle contains illegal extrinsic
        bad_receipt.inboxed_bundles =
            vec![InboxedBundle::valid(H256::random(), bundle_extrinsic_root)];

        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidBundles(proof) = &fp.proof
            && let InvalidBundleType::IllegalTx(extrinsic_index) = proof.invalid_bundle_type()
        {
            assert!(proof.is_good_invalid_fraud_proof());
            assert_eq!(extrinsic_index, 2);
            return true;
        }
        false
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_false_invalid_bundles_illegal_extrinsic_proof_creation_and_verification() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // transfer most of the alice's balance
    let alice_balance = alice.free_balance(Alice.to_account_id());

    let mut alice_nonce = alice.account_nonce();

    let transfer_to_charlie_with_big_tip_1 = alice.construct_extrinsic_with_tip(
        alice_nonce,
        alice_balance / 3,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 1,
        },
    );
    alice_nonce += 1;

    let transfer_to_charlie_with_big_tip_2 = alice.construct_extrinsic_with_tip(
        alice_nonce,
        alice_balance / 3,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 1,
        },
    );

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .send_extrinsic(transfer_to_charlie_with_big_tip_1.clone())
        .await
        .expect("Failed to send extrinsic");

    alice
        .send_extrinsic(transfer_to_charlie_with_big_tip_2.clone())
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 2);
    let bundle_extrinsic_root = target_bundle.extrinsics_root();
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // produce another bundle that marks the previous valid extrinsic as invalid.
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(bad_receipt) = opaque_bundle.execution_receipt_as_mut();
        // bad receipt marks this particular bundle as invalid even though bundle does not contain
        // illegal tx
        bad_receipt.inboxed_bundles = vec![InboxedBundle::invalid(
            InvalidBundleType::IllegalTx(1),
            bundle_extrinsic_root,
        )];

        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidBundles(proof) = &fp.proof
            && let InvalidBundleType::IllegalTx(extrinsic_index) = proof.invalid_bundle_type()
        {
            assert!(!proof.is_good_invalid_fraud_proof());
            assert_eq!(extrinsic_index, 1);
            return true;
        }
        false
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_true_invalid_bundle_weight_proof_creation_and_verification() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(opaque_bundle.extrinsics().len(), 1);
    let bundle_extrinsic_root = opaque_bundle.sealed_header().bundle_extrinsics_root();
    let bad_submit_bundle_tx = {
        opaque_bundle.set_estimated_bundle_weight(Weight::from_all(123456));
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        bundle_to_tx(&ferdie, opaque_bundle)
    };

    // Produce a block that contains `bad_submit_bundle_tx`
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();

    // produce another bundle that marks the bundle as valid.
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(bad_receipt) = opaque_bundle.execution_receipt_as_mut();
        // bad receipt marks this particular bundle as valid even though bundle contains invalid `estimated_bundle_weight`
        bad_receipt.inboxed_bundles =
            vec![InboxedBundle::valid(H256::random(), bundle_extrinsic_root)];

        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidBundles(proof) = &fp.proof
            && InvalidBundleType::InvalidBundleWeight == proof.invalid_bundle_type()
        {
            assert!(proof.is_good_invalid_fraud_proof());
            return true;
        }
        false
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_false_invalid_bundle_weight_proof_creation_and_verification() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 1);
    let extrinsics: Vec<Vec<u8>> = target_bundle
        .extrinsics()
        .iter()
        .map(|ext| ext.encode())
        .collect();
    let bundle_extrinsic_root = BlakeTwo256::ordered_trie_root(extrinsics, StateVersion::V1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // produce another bundle that marks the previous valid bundle as invalid.
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(bad_receipt) = opaque_bundle.execution_receipt_as_mut();
        // bad receipt marks this particular bundle as `InvalidBundleWeight`
        bad_receipt.inboxed_bundles = vec![InboxedBundle::invalid(
            InvalidBundleType::InvalidBundleWeight,
            bundle_extrinsic_root,
        )];

        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidBundles(proof) = &fp.proof
            && InvalidBundleType::InvalidBundleWeight == proof.invalid_bundle_type()
        {
            assert!(!proof.is_good_invalid_fraud_proof());
            return true;
        }
        false
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_false_invalid_bundles_non_exist_extrinsic_proof_creation_and_verification() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 1);
    let extrinsics: Vec<Vec<u8>> = target_bundle
        .extrinsics()
        .iter()
        .map(|ext| ext.encode())
        .collect();
    let bundle_extrinsic_root =
        BlakeTwo256::ordered_trie_root(extrinsics.clone(), StateVersion::V1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // produce another bundle that marks the previous valid extrinsic as invalid.
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(bad_receipt) = opaque_bundle.execution_receipt_as_mut();
        // bad receipt marks a non-exist extrinsic as invalid
        bad_receipt.inboxed_bundles = vec![InboxedBundle::invalid(
            InvalidBundleType::InherentExtrinsic(u32::MAX),
            bundle_extrinsic_root,
        )];

        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidBundles(proof) = &fp.proof
            && let InvalidBundlesProofData::Bundle(_) = proof.proof_data
        {
            assert_eq!(fp.targeted_bad_receipt_hash(), bad_receipt_hash);
            return true;
        }
        false
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_block_fees_proof_creation() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(receipt) = opaque_bundle.execution_receipt_as_mut();
        receipt.block_fees.consensus_storage_fee = 12345;
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        matches!(
            fp.proof,
            FraudProofVariant::InvalidBlockFees(InvalidBlockFeesProof { .. })
        )
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    // When the domain node operator processes the primary block that contains `bad_submit_bundle_tx`,
    // it will generate and submit a fraud proof
    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_transfers_fraud_proof() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(receipt) = opaque_bundle.execution_receipt_as_mut();
        receipt.transfers = Transfers {
            transfers_in: BTreeMap::from([(ChainId::Consensus, 10 * AI3)]),
            transfers_out: BTreeMap::from([(ChainId::Consensus, 10 * AI3)]),
            rejected_transfers_claimed: Default::default(),
            transfers_rejected: Default::default(),
        };
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        matches!(
            fp.proof,
            FraudProofVariant::InvalidTransfers(InvalidTransfersProof { .. })
        )
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    // When the domain node operator processes the primary block that contains `bad_submit_bundle_tx`,
    // it will generate and submit a fraud proof
    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_domain_block_hash_proof_creation() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(receipt) = opaque_bundle.execution_receipt_as_mut();
        receipt.domain_block_hash = Default::default();
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        matches!(
            fp.proof,
            FraudProofVariant::InvalidDomainBlockHash(InvalidDomainBlockHashProof { .. })
        )
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    // When the domain node operator processes the primary block that contains `bad_submit_bundle_tx`,
    // it will generate and submit a fraud proof
    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_domain_extrinsics_root_proof_creation() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1,
        })
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(target_bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(receipt) = opaque_bundle.execution_receipt_as_mut();
        receipt.domain_block_extrinsic_root = Default::default();
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        matches!(
            fp.proof,
            FraudProofVariant::InvalidExtrinsicsRoot(InvalidExtrinsicsRootProof { .. })
        )
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    // When the domain node operator processes the primary block that contains `bad_submit_bundle_tx`,
    // it will generate and submit a fraud proof
    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_block_builder_include_ext_with_failed_execution() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // produce a transfer from alice to bob
    // we send two transactions, first one must succeed, while second one will fail
    // second extrinsic fails due to not enough balance but should still be included in the domain
    // block body
    let pre_alice_free_balance = alice.free_balance(Alice.to_account_id());
    let alice_account_nonce = alice.account_nonce();

    // first ext that must succeed
    let tx = alice.construct_extrinsic(
        alice_account_nonce,
        pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            // we send half of alice balance to bob
            value: pre_alice_free_balance / 2,
        },
    );
    alice
        .send_extrinsic(tx)
        .await
        .expect("Failed to send extrinsic");

    // second ext that will fail due to balance restrictions.
    let tx = alice.construct_extrinsic(
        alice_account_nonce + 1,
        pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            // try to send value that is more than what alice has
            value: pre_alice_free_balance,
        },
    );
    alice
        .send_extrinsic(tx)
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle and submit to the tx pool of the consensus node
    let (_slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 2);

    // produce block and import domain block
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // domain block body should have 3 extrinsics
    // timestamp inherent, `consensus_chain_byte_fee` inherent, successful transfer, failed transfer
    let best_hash = alice.client.info().best_hash;
    let domain_block_extrinsics = alice.client.block_body(best_hash).unwrap();
    assert_eq!(domain_block_extrinsics.unwrap().len(), 4);

    // next bundle should have er which should a total of 5 trace roots
    // pre_timestamp_root + pre_consensus_chain_byte_fee_root + pre_success_ext_root + pre_failed_ext_root
    // + pre_finalize_block_root + post_finalize_block_root
    let (_slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let ExecutionReceiptRef::V0(er) = bundle.receipt();
    assert_eq!(er.execution_trace.len(), 6);
    assert_eq!(er.execution_trace[5], er.final_state_root);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_block_builder_include_ext_with_failed_predispatch() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // produce a transfer from alice to bob in one bundle, which should succeed
    let pre_alice_free_balance = alice.free_balance(Alice.to_account_id());
    let alice_account_nonce = alice.account_nonce();

    let tx = alice.construct_extrinsic(
        alice_account_nonce,
        pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            // we send half of alice balance to bob
            value: pre_alice_free_balance / 2,
        },
    );
    alice
        .send_extrinsic(tx)
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle and submit to the tx pool of the consensus node
    let (_slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);

    // we produce another bundle with similar transaction
    // second one will fail at pre dispatch since we use same nonce
    // we change the value to something else so that ext is different
    // send the tip so that previous ext is replaced with current in Domain tx pool
    let tip = 1000000;
    let tx = alice.construct_extrinsic_with_tip(
        // use the same nonce
        alice_account_nonce,
        tip,
        pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: pre_alice_free_balance / 3,
        },
    );
    alice
        .send_extrinsic(tx)
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle and submit to the tx pool of the consensus node
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);

    // produce block and import domain block
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // domain block body should have 3 extrinsics
    // timestamp inherent, successful transfer, failed transfer
    let best_hash = alice.client.info().best_hash;
    let domain_block_extrinsics = alice.client.block_body(best_hash).unwrap();
    assert_eq!(domain_block_extrinsics.clone().unwrap().len(), 4);

    // next bundle should have er which should a total of 5 trace roots
    // pre_timestamp_root + pre_consensus_chain_byte_fee_root + pre_success_ext_root + pre_failed_ext_root
    // + pre_finalize_block_root + post_finalize_block_root
    let (_slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let ExecutionReceiptRef::V0(er) = bundle.sealed_header().receipt();

    assert_eq!(er.execution_trace.len(), 6);
    assert_eq!(er.execution_trace[5], er.final_state_root);

    let header = alice.client.header(best_hash).unwrap().unwrap();
    assert_eq!(
        *header.extrinsics_root(),
        BlakeTwo256::ordered_trie_root(
            domain_block_extrinsics
                .unwrap()
                .iter()
                .map(Encode::encode)
                .collect(),
            sp_core::storage::StateVersion::V1,
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_valid_bundle_proof_generation_and_verification() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    for i in 0..3 {
        let tx = alice.construct_extrinsic(
            alice.account_nonce() + i,
            pallet_balances::Call::transfer_allow_death {
                dest: Bob.to_account_id(),
                value: 1,
            },
        );
        alice
            .send_extrinsic(tx)
            .await
            .expect("Failed to send extrinsic");

        // Produce a bundle and submit to the tx pool of the consensus node
        let (slot, _) = ferdie.produce_slot_and_wait_for_bundle_submission().await;

        // In the last iteration, produce a consensus block which will included all the previous bundles
        if i == 2 {
            produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
                .await
                .unwrap();
        }
    }

    // Produce a bundle that will include the reciept of the last 3 bundles and modified the receipt's
    // `inboxed_bundles` field to make it invalid
    let (slot, mut bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let bundle_index = 1;
    let (bad_receipt, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(receipt) = bundle.execution_receipt_as_mut();
        assert_eq!(receipt.inboxed_bundles.len(), 3);
        receipt.inboxed_bundles[bundle_index].bundle = BundleValidity::Valid(H256::random());
        bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );

        (
            bundle.receipt().to_owned_er(),
            bundle_to_tx(&ferdie, bundle),
        )
    };

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    let mut import_tx_stream = ferdie.transaction_pool.import_notification_stream();
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(
        ferdie
            .does_receipt_exist(bad_receipt.hash::<BlakeTwo256>())
            .unwrap()
    );

    // When the domain node operator processes the primary block that contains `bad_submit_bundle_tx`,
    // it will generate and submit a fraud proof
    while let Some(ready_tx_hash) = import_tx_stream.next().await {
        let ready_tx = ferdie
            .transaction_pool
            .ready_transaction(&ready_tx_hash)
            .unwrap();
        let ext = subspace_test_runtime::UncheckedExtrinsic::decode(
            &mut ready_tx.data.encode().as_slice(),
        )
        .unwrap();
        if let subspace_test_runtime::RuntimeCall::Domains(
            pallet_domains::Call::submit_fraud_proof { fraud_proof },
        ) = ext.function
            && let FraudProofVariant::ValidBundle(ref proof) = fraud_proof.proof
        {
            // The fraud proof is targetting the `bad_receipt`
            assert_eq!(
                fraud_proof.bad_receipt_hash,
                bad_receipt.hash::<HeaderHashingFor<Header>>()
            );

            // If the fraud proof target a non-exist receipt then it is invalid
            let mut bad_fraud_proof = fraud_proof.clone();
            bad_fraud_proof.bad_receipt_hash = H256::random();
            let ext = proof_to_tx(&ferdie, bad_fraud_proof);
            assert!(ferdie.submit_transaction(ext).await.is_err());

            // If the fraud proof point to non-exist bundle then it is invalid
            let (mut bad_fraud_proof, mut bad_proof) = (fraud_proof.clone(), proof.clone());
            bad_proof.set_bundle_index(u32::MAX);
            bad_fraud_proof.proof = FraudProofVariant::ValidBundle(bad_proof);
            let ext = proof_to_tx(&ferdie, bad_fraud_proof);
            assert!(ferdie.submit_transaction(ext).await.is_err());

            break;
        }
    }

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(
        !ferdie
            .does_receipt_exist(bad_receipt.hash::<BlakeTwo256>())
            .unwrap()
    );
}

// TODO: Add a new test which simulates a situation that an executor produces a fraud proof
// when an invalid receipt is received.

// TODO: construct a minimal consensus runtime code and use the `set_code` extrinsic to actually
// cover the case that the new domain runtime are updated accordingly upon the new consensus runtime.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn set_new_code_should_work() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 1).await.unwrap();

    let new_runtime_wasm_blob = b"new_runtime_wasm_blob".to_vec();

    let best_number = alice.client.info().best_number;
    let consensus_block_number = best_number + 1;
    // Although we're processing the bundle manually, the original bundle processor still works in
    // the meanwhile, it's possible the executor alice already processed this consensus block, expecting next
    // consensus block, in which case we use a dummy consensus hash instead.
    //
    // Nice to disable the built-in bundle processor and have a full control of the executor block
    // production manually.
    let consensus_block_hash = ferdie
        .client
        .hash(consensus_block_number)
        .unwrap()
        .unwrap_or_else(Hash::random);
    alice
        .operator
        .clone()
        .process_bundles((consensus_block_hash, consensus_block_number, true))
        .await;

    let best_hash = alice.client.info().best_hash;
    let state = alice.backend.state_at(best_hash).expect("Get state");
    let trie_backend = state.as_trie_backend();
    let state_runtime_code = sp_state_machine::backend::BackendRuntimeCode::new(trie_backend);
    let runtime_code = state_runtime_code.fetch_runtime_code().unwrap();
    let logs = alice.client.header(best_hash).unwrap().unwrap().digest.logs;
    if logs != vec![DigestItem::RuntimeEnvironmentUpdated] {
        let extrinsics = alice
            .client
            .block_body(best_hash)
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|encoded_extrinsic| {
                EvmUncheckedExtrinsic::decode(&mut encoded_extrinsic.encode().as_slice()).unwrap()
            })
            .collect::<Vec<_>>();
        panic!("`set_code` not executed, extrinsics in the block: {extrinsics:?}")
    }
    assert_eq!(runtime_code, new_runtime_wasm_blob);
}

#[tokio::test(flavor = "multi_thread")]
async fn pallet_domains_unsigned_extrinsics_should_work() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run Bob (a evm domain full node)
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle,
        BasePath::new(directory.path().join("bob")),
    )
    .build_evm_node(Role::Full, Bob, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // Get a bundle from alice's tx pool and used as bundle template.
    let (slot, _) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let _alice_key = alice.key;
    // Drop alice in order to control the execution chain by submitting the receipts manually later.
    drop(alice);

    produce_block_with!(ferdie.produce_block_with_slot(slot), bob)
        .await
        .unwrap();

    // let ferdie_client = ferdie.client.clone();
    // let create_submit_bundle = |consensus_block_number: BlockNumber| {
    // let consensus_block_hash = ferdie_client.hash(consensus_block_number).unwrap().unwrap();
    // let execution_receipt =
    // crate::aux_schema::load_execution_receipt(&*bob.backend, consensus_block_hash)
    // .expect("Failed to load execution receipt from the local aux_db")
    // .unwrap_or_else(|| {
    // panic!(
    // "The requested execution receipt for block {consensus_block_number} does not exist"
    // )
    // });

    // let mut opaque_bundle = bundle_template.clone();
    // opaque_bundle.sealed_header.header.consensus_block_number = consensus_block_number;
    // opaque_bundle.sealed_header.header.consensus_block_hash = consensus_block_hash;
    // opaque_bundle.sealed_header.signature = alice_key
    // .pair()
    // .sign(opaque_bundle.sealed_header.pre_hash().as_ref())
    // .into();
    // opaque_bundle.receipt = execution_receipt;

    //     subspace_test_runtime::UncheckedExtrinsic::new_bare(
    //         pallet_domains::Call::submit_bundle { opaque_bundle }.into(),
    //     )
    //     .into()
    // };

    // TODO: Unlock once `head_receipt_number` API is usable.
    // let ferdie_client = ferdie.client.clone();
    // let head_receipt_number = || {
    //     let best_hash = ferdie_client.info().best_hash;
    //     ferdie_client
    //         .runtime_api()
    //         .head_receipt_number(best_hash, DomainId::SYSTEM)
    //         .expect("Failed to get head receipt number")
    // };

    // ferdie
    //     .submit_transaction(create_submit_bundle(1))
    //     .await
    //     .unwrap();
    // produce_blocks!(ferdie, bob, 1).await.unwrap();
    // ferdie
    //     .submit_transaction(create_submit_bundle(2))
    //     .await
    //     .unwrap();
    // produce_blocks!(ferdie, bob, 1).await.unwrap();
    // assert_eq!(head_receipt_number(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_and_in_future_bundle_should_be_rejected() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 10).await.unwrap();
    let slot_info = |slot, proof_of_time| OperatorSlotInfo {
        slot,
        proof_of_time,
    };
    let operator_id = 0;
    let mut bundle_producer = {
        let domain_bundle_proposer = DomainBundleProposer::new(
            EVM_DOMAIN_ID,
            alice.client.clone(),
            ferdie.client.clone(),
            alice.operator.transaction_pool.clone(),
        );
        let (bundle_sender, _bundle_receiver) =
            sc_utils::mpsc::tracing_unbounded("domain_bundle_stream", 100);
        TestBundleProducer::new(
            EVM_DOMAIN_ID,
            ferdie.client.clone(),
            alice.client.clone(),
            domain_bundle_proposer,
            Arc::new(bundle_sender),
            alice.operator.keystore.clone(),
            false,
            false,
        )
    };

    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    ferdie.clear_tx_pool().await.unwrap();

    // Bundle is valid and can submit to tx pool for 5 consensus blocks
    for _ in 0..5 {
        let ext = bundle_to_tx(&ferdie, bundle.clone());
        ferdie.submit_transaction(ext).await.unwrap();

        ferdie.produce_block_with_extrinsics(vec![]).await.unwrap();
        ferdie.clear_tx_pool().await.unwrap();
    }

    // Bundle will be rejected because its PoT is stale now
    let ext = bundle_to_tx(&ferdie, bundle);
    match ferdie.submit_transaction(ext).await.unwrap_err() {
        TxPoolError::InvalidTransaction(invalid_tx) => {
            assert_eq!(invalid_tx, InvalidTransactionCode::Bundle.into())
        }
        e => panic!("Unexpected error: {e}"),
    }

    // Produce a bundle with slot newer than the consensus block slot but less its the future slot
    let slot = ferdie.produce_slot();
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let exts = vec![bundle_to_tx(&ferdie, bundle)];
    produce_block_with!(
        ferdie.produce_block_with_slot_at(slot, ferdie.client.info().best_hash, Some(exts)),
        alice
    )
    .await
    .unwrap();

    // Bundle with unknow PoT and in future slot will be rejected before entring the tx pool
    let (valid_slot, valid_pot) = ferdie.produce_slot();
    let slot_in_future = u64::MAX.into();
    let unknow_pot = PotOutput::from(
        <&[u8] as TryInto<[u8; 16]>>::try_into(
            &subspace_runtime_primitives::Hash::random().to_fixed_bytes()[..16],
        )
        .expect("slice with length of 16 must able convert into [u8; 16]; qed"),
    );

    let valid_bundle = bundle_producer
        .produce_bundle(operator_id, slot_info(valid_slot, valid_pot))
        .await
        .unwrap()
        .and_then(|res| res.into_opaque_bundle())
        .unwrap();
    let bundle_with_unknow_pot = bundle_producer
        .produce_bundle(operator_id, slot_info(valid_slot, unknow_pot))
        .await
        .unwrap()
        .and_then(|res| res.into_opaque_bundle())
        .unwrap();
    let bundle_with_slot_in_future = bundle_producer
        .produce_bundle(operator_id, slot_info(slot_in_future, valid_pot))
        .await
        .unwrap()
        .and_then(|res| res.into_opaque_bundle())
        .unwrap();
    for bundle in [
        bundle_with_unknow_pot.clone(),
        bundle_with_slot_in_future.clone(),
    ] {
        let ext = bundle_to_tx(&ferdie, bundle);
        match ferdie.submit_transaction(ext).await.unwrap_err() {
            TxPoolError::InvalidTransaction(invalid_tx) => {
                assert_eq!(invalid_tx, InvalidTransactionCode::Bundle.into())
            }
            e => panic!("Unexpected error: {e}"),
        }
    }
    let ext = bundle_to_tx(&ferdie, valid_bundle);
    ferdie.submit_transaction(ext).await.unwrap();
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // Even try building consensus block with these invalid bundles, they will fail to pass
    // the `pre_dispatch` check, and won't included in the consensus block
    let pre_ferdie_best_number = ferdie.client.info().best_number;
    let pre_alice_best_number = alice.client.info().best_number;

    let exts = vec![
        bundle_to_tx(&ferdie, bundle_with_unknow_pot),
        bundle_to_tx(&ferdie, bundle_with_slot_in_future),
    ];
    ferdie.produce_block_with_extrinsics(exts).await.unwrap();
    assert_eq!(ferdie.client.info().best_number, pre_ferdie_best_number + 1);
    assert_eq!(alice.client.info().best_number, pre_alice_best_number);
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_bundle_can_be_resubmitted_to_new_fork() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let pre_alice_best_number = alice.client.info().best_number;
    let mut parent_hash = ferdie.client.info().best_hash;

    let (slot, opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let submit_bundle_tx = ferdie
        .construct_unsigned_extrinsic(pallet_domains::Call::submit_bundle { opaque_bundle })
        .into();

    // Wait one block to ensure the bundle is stored on this fork
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();

    // Create fork that also contains the bundle and build one more blocks on it to make
    // it the new best fork
    parent_hash = ferdie
        .produce_block_with_slot_at(slot, parent_hash, Some(vec![submit_bundle_tx]))
        .await
        .unwrap();
    let slot = ferdie.produce_slot();
    ferdie
        .produce_block_with_slot_at(slot, parent_hash, Some(vec![]))
        .await
        .unwrap();

    assert_eq!(alice.client.info().best_number, pre_alice_best_number + 1);

    produce_blocks!(ferdie, alice, 1).await.unwrap();
    assert_eq!(alice.client.info().best_number, pre_alice_best_number + 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_sudo_calls() {
    let (_directory, mut ferdie, mut alice, account_infos) =
        setup_evm_test_accounts(Sr25519Alice, true, Sr25519Alice).await;

    // Run the cross domain gossip message worker
    ferdie.start_cross_domain_gossip_message_worker();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Open XDM channel between the consensus chain and the EVM domain
    open_xdm_channel(&mut ferdie, &mut alice).await;

    // check initial contract allow list
    assert_eq!(
        alice.evm_contract_creation_allowed_by(),
        PermissionedActionAllowedBy::Anyone,
        "initial contract allow list should be anyone"
    );

    // set EVM contract allow list on Domain using domain sudo.
    // Sudo on consensus chain will send a sudo call to domain
    // once the call is executed in the domain, list will be updated.

    // Start with a redundant set to make sure the test framework works.
    let mut allow_list = generate_evm_account_list(&account_infos, EvmAccountList::Anyone);
    ferdie.construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
        call: Box::new(subspace_test_runtime::RuntimeCall::Domains(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    }))})
    .await
    .expect("Failed to construct and send consensus chain sudo call to update EVM contract allow list");

    // Wait until list is updated
    produce_blocks_until!(ferdie, alice, {
        alice.evm_contract_creation_allowed_by() == allow_list
    })
    .timeout()
    .await
    .unwrap()
    .unwrap();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Then use actual settings
    allow_list = generate_evm_account_list(&account_infos, EvmAccountList::NoOne);
    ferdie.construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
        call: Box::new(subspace_test_runtime::RuntimeCall::Domains(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    }))})
    .await
    .expect("Failed to construct and send consensus chain sudo call to update EVM contract allow list");

    // Wait until list is updated
    produce_blocks_until!(ferdie, alice, {
        alice.evm_contract_creation_allowed_by() == allow_list
    })
    .timeout()
    .await
    .unwrap()
    .unwrap();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // 1 account in the allow list
    allow_list = generate_evm_account_list(&account_infos, EvmAccountList::One);
    ferdie.construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
        call: Box::new(subspace_test_runtime::RuntimeCall::Domains(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    }))})
    .await
    .expect("Failed to construct and send consensus chain sudo call to update EVM contract allow list");

    // Wait until list is updated
    produce_blocks_until!(ferdie, alice, {
        alice.evm_contract_creation_allowed_by() == allow_list
    })
    .timeout()
    .await
    .unwrap()
    .unwrap();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Multiple accounts in the allow list
    allow_list = generate_evm_account_list(&account_infos, EvmAccountList::Multiple);
    ferdie.construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
        call: Box::new(subspace_test_runtime::RuntimeCall::Domains(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    }))})
    .await
    .expect("Failed to construct and send consensus chain sudo call to update EVM contract allow list");

    // Wait until list is updated
    produce_blocks_until!(ferdie, alice, {
        alice.evm_contract_creation_allowed_by() == allow_list
    })
    .timeout()
    .await
    .unwrap()
    .unwrap();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // close channel on Domain using domain sudo.
    // Sudo on consensus chain will send a sudo call to domain
    // once the call is executed in the domain,
    // closing channel flow should happen and channel on both domain
    // consensus chain should be closed.
    let channel_id = alice
        .get_open_channel_for_chain(ChainId::Consensus)
        .unwrap();
    let sudo_unsigned_extrinsic = alice
        .construct_unsigned_extrinsic(evm_domain_test_runtime::RuntimeCall::Messenger(
            pallet_messenger::Call::close_channel {
                chain_id: ChainId::Consensus,
                channel_id,
            },
        ))
        .encode();
    ferdie
        .construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
            call: Box::new(subspace_test_runtime::RuntimeCall::Domains(
                pallet_domains::Call::send_domain_sudo_call {
                    domain_id: EVM_DOMAIN_ID,
                    call: sudo_unsigned_extrinsic,
                },
            )),
        })
        .await
        .expect("Failed to construct and send consensus chain to close channel");

    // Wait until channel closes
    produce_blocks_until!(ferdie, alice, {
        alice
            .get_open_channel_for_chain(ChainId::Consensus)
            .is_none()
    })
    .timeout()
    .await
    .unwrap()
    .unwrap();

    // produce 30 more blocks to ensure nothing went wrong
    produce_blocks!(ferdie, alice, 30).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_owner_calls() {
    let (_directory, mut ferdie, alice, account_infos) =
        setup_evm_test_accounts(Ferdie, true, Ferdie).await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // TODO: other domain owner calls

    // check initial contract allow list
    assert_eq!(
        alice.evm_contract_creation_allowed_by(),
        PermissionedActionAllowedBy::Anyone,
        "initial contract allow list should be anyone"
    );

    // set EVM contract allow list on Domain using domain owner.
    // Consensus chain will send the call to domain as an inherent.
    // Once the call is executed in the domain, list will be updated.

    // Start with a redundant set to make sure the test framework works.
    let mut allow_list = generate_evm_account_list(&account_infos, EvmAccountList::Anyone);
    ferdie.construct_and_send_extrinsic_with(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    })
    .await
    .expect("Failed to construct and send consensus chain owner call to update EVM contract allow list");

    // Wait until list is updated
    produce_blocks_until!(ferdie, alice, {
        alice.evm_contract_creation_allowed_by() == allow_list
    })
    .await
    .unwrap();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Then use actual settings
    allow_list = generate_evm_account_list(&account_infos, EvmAccountList::NoOne);
    ferdie.construct_and_send_extrinsic_with(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    })
    .await
    .expect("Failed to construct and send consensus chain owner call to update EVM contract allow list");

    // Wait until list is updated
    produce_blocks_until!(ferdie, alice, {
        alice.evm_contract_creation_allowed_by() == allow_list
    })
    .await
    .unwrap();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // 1 account in the allow list
    allow_list = generate_evm_account_list(&account_infos, EvmAccountList::One);
    ferdie.construct_and_send_extrinsic_with(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    })
    .await
    .expect("Failed to construct and send consensus chain owner call to update EVM contract allow list");

    // Wait until list is updated
    produce_blocks_until!(ferdie, alice, {
        alice.evm_contract_creation_allowed_by() == allow_list
    })
    .await
    .unwrap();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Multiple accounts in the allow list
    allow_list = generate_evm_account_list(&account_infos, EvmAccountList::Multiple);
    ferdie.construct_and_send_extrinsic_with(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    })
    .await
    .expect("Failed to construct and send consensus chain owner call to update EVM contract allow list");

    // Wait until list is updated
    produce_blocks_until!(ferdie, alice, {
        alice.evm_contract_creation_allowed_by() == allow_list
    })
    .await
    .unwrap();

    // produce 30 more blocks to ensure nothing went wrong
    produce_blocks!(ferdie, alice, 30).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_public_evm_rejects_allow_list_domain_sudo_calls() {
    let (_directory, mut ferdie, alice, account_infos) =
        setup_evm_test_accounts(Sr25519Alice, false, Sr25519Alice).await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // check initial contract allow list
    assert_eq!(
        alice.evm_contract_creation_allowed_by(),
        PermissionedActionAllowedBy::Anyone,
        "initial contract allow list should be anyone"
    );

    // try to set EVM contract allow list on Domain using domain sudo.
    // pallet-domains should reject these calls on a public EVM instance.

    // A redundant set should still fail
    let mut allow_list = generate_evm_account_list(&account_infos, EvmAccountList::Anyone);
    ferdie.construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
        call: Box::new(subspace_test_runtime::RuntimeCall::Domains(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    }))})
    .await
    .expect("Failed to construct and send consensus chain sudo call to update EVM contract allow list");

    // Produce a bundle that contains just the sent extrinsics (and not the failed ones)
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 0);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Then use actual settings
    allow_list = generate_evm_account_list(&account_infos, EvmAccountList::NoOne);
    ferdie.construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
        call: Box::new(subspace_test_runtime::RuntimeCall::Domains(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    }))})
    .await
    .expect("Failed to construct and send consensus chain sudo call to update EVM contract allow list");

    // Produce a bundle that contains just the sent extrinsics (and not the failed ones)
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 0);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Multiple accounts in the allow list
    allow_list = generate_evm_account_list(&account_infos, EvmAccountList::Multiple);
    ferdie.construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
        call: Box::new(subspace_test_runtime::RuntimeCall::Domains(pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
        domain_id: EVM_DOMAIN_ID,
        contract_creation_allowed_by: allow_list.clone(),
    }))})
    .await
    .expect("Failed to construct and send consensus chain sudo call to update EVM contract allow list");

    // Produce a bundle that contains just the sent extrinsics (and not the failed ones)
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 0);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    // produce 30 more blocks to ensure nothing went wrong
    produce_blocks!(ferdie, alice, 30).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_public_evm_rejects_allow_list_domain_owner_calls() {
    let (_directory, mut ferdie, alice, account_infos) =
        setup_evm_test_accounts(Ferdie, false, Ferdie).await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // check initial contract allow list
    assert_eq!(
        alice.evm_contract_creation_allowed_by(),
        PermissionedActionAllowedBy::Anyone,
        "initial contract allow list should be anyone"
    );

    // Try to set EVM contract allow list on Domain using domain owner.
    // pallet-domains should reject these calls on a public EVM instance.

    // A redundant set should still fail.
    let mut allow_list = generate_evm_account_list(&account_infos, EvmAccountList::Anyone);
    ferdie
        .construct_and_send_extrinsic_with(
            pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
                domain_id: EVM_DOMAIN_ID,
                contract_creation_allowed_by: allow_list.clone(),
            },
        )
        .await
        .expect(
            "Owner update to public EVM contract allow list shouldn't have failed at this stage",
        );

    // Produce a bundle that contains just the sent extrinsics (and not the failed ones)
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 0);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Then use actual settings
    // 1 account in the allow list
    allow_list = generate_evm_account_list(&account_infos, EvmAccountList::One);
    ferdie
        .construct_and_send_extrinsic_with(
            pallet_domains::Call::send_evm_domain_set_contract_creation_allowed_by_call {
                domain_id: EVM_DOMAIN_ID,
                contract_creation_allowed_by: allow_list.clone(),
            },
        )
        .await
        .expect(
            "Owner update to public EVM contract allow list shouldn't have failed at this stage",
        );

    // Produce a bundle that contains just the sent extrinsics (and not the failed ones)
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 0);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    // produce 30 more blocks to ensure nothing went wrong
    produce_blocks!(ferdie, alice, 30).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_xdm_between_consensus_and_domain_should_work() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie with Alice Key since that is the sudo key
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Sr25519Alice,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (an evm domain)
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run the cross domain gossip message worker
    ferdie.start_cross_domain_gossip_message_worker();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Open XDM channel between the consensus chain and the EVM domain
    open_xdm_channel(&mut ferdie, &mut alice).await;

    // there should be channel updates on both consensus and domain chain

    // consensus channel update
    let channel_update = get_channel_state(
        &*ferdie.client,
        ChainId::Consensus,
        EVM_DOMAIN_ID.into(),
        ChannelId::zero(),
    )
    .unwrap()
    .unwrap();

    // next channel inbox nonce on consensus from domain should be 1
    assert_eq!(channel_update.next_inbox_nonce, 1.into());

    // domain channel update
    let channel_update = get_channel_state(
        &*ferdie.client,
        EVM_DOMAIN_ID.into(),
        ChainId::Consensus,
        ChannelId::zero(),
    )
    .unwrap()
    .unwrap();

    // next channel outbox nonce on domain to consensus should be 1
    assert_eq!(channel_update.next_outbox_nonce, 1.into());
    // received outbox response nonce on domain from consensus chain should be 0
    assert_eq!(
        channel_update.latest_response_received_message_nonce,
        Some(0.into())
    );

    // Transfer balance from
    let pre_alice_free_balance = alice.free_balance(alice.key.to_account_id());
    let pre_ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());
    let transfer_amount = 10;
    alice
        .construct_and_send_extrinsic(pallet_transporter::Call::transfer {
            dst_location: pallet_transporter::Location {
                chain_id: ChainId::Consensus,
                account_id: AccountIdConverter::convert(Sr25519Alice.into()),
            },
            amount: transfer_amount,
        })
        .await
        .expect("Failed to construct and send extrinsic");
    // Wait until transfer succeed
    produce_blocks_until!(ferdie, alice, {
        let post_alice_free_balance = alice.free_balance(alice.key.to_account_id());
        let post_ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());

        post_alice_free_balance < pre_alice_free_balance - transfer_amount
            && post_ferdie_free_balance == pre_ferdie_free_balance + transfer_amount
    })
    .await
    .unwrap();

    produce_blocks!(ferdie, alice, 20).await.unwrap();

    // there should be channel updates on both consensus and domain chain

    // consensus channel update
    let channel_update = get_channel_state(
        &*ferdie.client,
        ChainId::Consensus,
        EVM_DOMAIN_ID.into(),
        ChannelId::zero(),
    )
    .unwrap()
    .unwrap();

    // next channel inbox nonce on consensus from domain should be 2
    assert_eq!(channel_update.next_inbox_nonce, 2.into());

    // close channel on consensus chain using sudo since
    // channel is opened on domain
    let channel_id = alice
        .get_open_channel_for_chain(ChainId::Consensus)
        .unwrap();
    ferdie
        .construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
            call: Box::new(subspace_test_runtime::RuntimeCall::Messenger(
                pallet_messenger::Call::close_channel {
                    chain_id: ChainId::Domain(EVM_DOMAIN_ID),
                    channel_id,
                },
            )),
        })
        .await
        .expect("Failed to construct and send consensus chain to close channel");
    // Wait until channel close
    produce_blocks_until!(ferdie, alice, {
        alice
            .get_open_channel_for_chain(ChainId::Consensus)
            .is_none()
    })
    .await
    .unwrap();

    produce_blocks!(ferdie, alice, 20).await.unwrap();

    // there should be channel updates on both consensus and domain chain

    // domain channel update
    let channel_update = get_channel_state(
        &*ferdie.client,
        EVM_DOMAIN_ID.into(),
        ChainId::Consensus,
        ChannelId::zero(),
    )
    .unwrap()
    .unwrap();

    // next channel outbox nonce on domain to consensus should be 2
    assert_eq!(channel_update.next_outbox_nonce, 2.into());
    // next channel inbox nonce on domain should be 1
    assert_eq!(channel_update.next_inbox_nonce, 1.into());
    // received outbox response nonce on domain from consensus chain should be 1
    assert_eq!(
        channel_update.latest_response_received_message_nonce,
        Some(1.into())
    );
}

// This test is more unstable on Windows and macOS
// TODO: find and fix the source of the instability (#3562)
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[tokio::test(flavor = "multi_thread")]
async fn test_xdm_between_domains_should_work() {
    use domain_test_service::AUTO_ID_DOMAIN_ID;

    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Sr25519Alice,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a system domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run Bob (a auto-id domain authority node)
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("bob")),
    )
    .build_auto_id_node(Role::Authority, Sr25519Keyring::Bob, &mut ferdie)
    .await;

    // Run the cross domain gossip message worker
    ferdie.start_cross_domain_gossip_message_worker();

    produce_blocks!(ferdie, alice, 3, bob).await.unwrap();

    // add consensus chain to domain chain allow list
    ferdie
        .construct_and_send_extrinsic_with(subspace_test_runtime::RuntimeCall::Messenger(
            pallet_messenger::Call::initiate_domain_update_chain_allowlist {
                domain_id: EVM_DOMAIN_ID,
                update: ChainAllowlistUpdate::Add(ChainId::Domain(AUTO_ID_DOMAIN_ID)),
            },
        ))
        .await
        .expect("Failed to construct and send domain chain allowlist update");

    // produce another block so allowlist on  domain are updated
    produce_blocks!(ferdie, alice, 1, bob).await.unwrap();

    // add consensus chain to domain chain allow list
    ferdie
        .construct_and_send_extrinsic_with(subspace_test_runtime::RuntimeCall::Messenger(
            pallet_messenger::Call::initiate_domain_update_chain_allowlist {
                domain_id: AUTO_ID_DOMAIN_ID,
                update: ChainAllowlistUpdate::Add(ChainId::Domain(EVM_DOMAIN_ID)),
            },
        ))
        .await
        .expect("Failed to construct and send domain chain allowlist update");

    // produce another block so allowlist on  domain are updated
    produce_blocks!(ferdie, alice, 1, bob).await.unwrap();

    // Open channel between the evm domain and the auto-id domain
    bob.construct_and_send_extrinsic(auto_id_domain_test_runtime::RuntimeCall::Messenger(
        pallet_messenger::Call::initiate_channel {
            dst_chain_id: ChainId::Domain(EVM_DOMAIN_ID),
        },
    ))
    .await
    .expect("Failed to construct and send extrinsic");

    // Wait until channel open
    produce_blocks_until!(
        ferdie,
        alice,
        {
            alice
                .get_open_channel_for_chain(ChainId::Domain(AUTO_ID_DOMAIN_ID))
                .is_some()
                && bob
                    .get_open_channel_for_chain(ChainId::Domain(EVM_DOMAIN_ID))
                    .is_some()
        },
        bob
    )
    .await
    .unwrap();

    // Transfer balance cross the system domain and the core payments domain
    let pre_alice_free_balance = alice.free_balance(alice.key.to_account_id());
    let pre_bob_free_balance = bob.free_balance(bob.key.to_account_id());
    let transfer_amount = 10;
    alice
        .construct_and_send_extrinsic(pallet_transporter::Call::transfer {
            dst_location: pallet_transporter::Location {
                chain_id: ChainId::Domain(AUTO_ID_DOMAIN_ID),
                account_id: AccountIdConverter::convert(Sr25519Keyring::Bob.into()),
            },
            amount: transfer_amount,
        })
        .await
        .expect("Failed to construct and send extrinsic");
    // Wait until transfer succeed
    produce_blocks_until!(
        ferdie,
        alice,
        {
            let post_alice_free_balance = alice.free_balance(alice.key.to_account_id());
            let post_bob_free_balance = bob.free_balance(bob.key.to_account_id());

            post_alice_free_balance <= pre_alice_free_balance - transfer_amount
                && post_bob_free_balance == pre_bob_free_balance + transfer_amount
        },
        bob
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_unordered_cross_domains_message_should_work() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Sr25519Alice,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a system domain authority node)
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    let evm_domain_tx_pool_sink = ferdie
        .xdm_gossip_worker_builder()
        .remove_chain_sink(&ChainId::Domain(EVM_DOMAIN_ID))
        .unwrap();
    let (reorder_xdm_sink, mut reorder_xdm_receiver) = tracing_unbounded("reorder_xdm", 100);
    ferdie
        .xdm_gossip_worker_builder()
        .push_chain_sink(ChainId::Domain(EVM_DOMAIN_ID), reorder_xdm_sink);

    alice
        .task_manager
        .spawn_essential_handle()
        .spawn_essential_blocking(
            "reordering-xdm",
            None,
            Box::pin(async move {
                let mut i = 0;
                let mut msg_buffer = VecDeque::new();
                while let Some(xdm) = reorder_xdm_receiver.next().await {
                    if i % 3 == 0 {
                        msg_buffer.push_back(xdm);
                        if let Some(xdm) = msg_buffer.pop_front()
                            && i % 2 == 0
                        {
                            evm_domain_tx_pool_sink.unbounded_send(xdm).unwrap();
                        }
                    } else {
                        evm_domain_tx_pool_sink.unbounded_send(xdm).unwrap();
                    }
                    i += 1;
                }
            }),
        );

    // Run the cross domain gossip message worker
    ferdie.start_cross_domain_gossip_message_worker();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Open XDM channel between the consensus chain and the EVM domain
    open_xdm_channel(&mut ferdie, &mut alice).await;

    // Transfer balance cross the system domain and the core payments domain
    let pre_alice_free_balance = alice.free_balance(alice.key.to_account_id());
    let pre_ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());
    let transfer_amount = 10;
    for _ in 0..20 {
        ferdie
            .construct_and_send_extrinsic_with(pallet_transporter::Call::transfer {
                dst_location: pallet_transporter::Location {
                    chain_id: ChainId::Domain(EVM_DOMAIN_ID),
                    account_id: AccountId20Converter::convert(Alice.to_account_id()),
                },
                amount: transfer_amount,
            })
            .await
            .expect("Failed to construct and send extrinsic");
        produce_blocks!(ferdie, alice, 1).await.unwrap();
    }
    // Wait until transfer succeed
    produce_blocks_until!(ferdie, alice, {
        let post_alice_free_balance = alice.free_balance(alice.key.to_account_id());
        let post_ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());

        post_alice_free_balance == pre_alice_free_balance + transfer_amount * 20
            && post_ferdie_free_balance <= pre_ferdie_free_balance - transfer_amount * 20
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_restart_domain_operator() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();
    let next_slot = ferdie.next_slot();

    // Stop Ferdie and Alice and delete their database lock files
    ferdie.stop().await.unwrap();
    alice.stop().await.unwrap();

    // Restart Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );
    ferdie.set_next_slot(next_slot);

    // Restart Alice
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    // Chain should progress base on previous run
    assert_eq!(ferdie.client.info().best_number, 10);
    assert_eq!(alice.client.info().best_number, 10);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_transaction_fee_and_operator_reward() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Construct and submit an extrinsic with tip
    let pre_alice_free_balance = alice.free_balance(Alice.to_account_id());
    let tip = 123456;
    let tx = alice.construct_extrinsic_with_tip(
        alice.account_nonce(),
        tip,
        frame_system::Call::remark {
            remark: vec![1; 10 * 1024],
        },
    );
    alice
        .send_extrinsic(tx)
        .await
        .expect("Failed to send extrinsic");

    // Produce a bundle that contains the just sent extrinsic
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    let consensus_block_hash = ferdie.client.info().best_hash;

    // Produce one more bundle, this bundle should contain the ER of the previous bundle
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(*receipt.consensus_block_hash(), consensus_block_hash);

    // Transaction fee (including the tip) is deducted from alice's account
    let alice_free_balance_changes =
        pre_alice_free_balance - alice.free_balance(Alice.to_account_id());
    assert!(alice_free_balance_changes >= tip);

    let domain_block_fees = alice
        .client
        .runtime_api()
        .block_fees(*receipt.domain_block_hash())
        .unwrap();

    // All the transaction fee is collected as operator reward
    assert_eq!(
        alice_free_balance_changes,
        domain_block_fees.domain_execution_fee + domain_block_fees.consensus_storage_fee
    );
    assert_eq!(domain_block_fees, receipt.block_fees().clone());
    assert!(!domain_block_fees.consensus_storage_fee.is_zero());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_consensus_blocks_derive_similar_domain_block() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();
    let common_block_hash = ferdie.client.info().best_hash;

    // submit a remark from alice
    let alice_account_nonce = alice.account_nonce();
    let tx = alice.construct_extrinsic(
        alice_account_nonce,
        frame_system::Call::remark {
            remark: vec![0u8; 8],
        },
    );
    alice
        .send_extrinsic(tx)
        .await
        .expect("Failed to send extrinsic");

    // Fork A with bundle that contains above transaction
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let exts = vec![bundle_to_tx(&ferdie, opaque_bundle.clone())];
    let consensus_block_hash_fork_a = ferdie
        .produce_block_with_slot_at(slot, common_block_hash, Some(exts))
        .await
        .unwrap();

    // Fork B
    let bundle = {
        opaque_bundle.set_extrinsics(vec![]);
        // zero bundle weight since there are not extrinsics
        opaque_bundle.set_estimated_bundle_weight(Weight::zero());
        opaque_bundle.set_bundle_extrinsics_root(sp_domains::EMPTY_EXTRINSIC_ROOT);
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        opaque_bundle
    };

    let exts = vec![bundle_to_tx(&ferdie, bundle)];
    let consensus_block_hash_fork_b = ferdie
        .produce_block_with_slot_at(slot, common_block_hash, Some(exts))
        .await
        .unwrap();
    // Produce one more consensus block to make fork B the best fork and trigger processing
    // on fork B
    let slot = ferdie.produce_slot();
    ferdie
        .produce_block_with_slot_at(slot, consensus_block_hash_fork_b, Some(vec![]))
        .await
        .unwrap();

    assert_ne!(consensus_block_hash_fork_a, consensus_block_hash_fork_b);

    // Both consensus block from fork A and B should derive a corresponding domain block
    let domain_block_hash_fork_a =
        crate::aux_schema::best_domain_hash_for(&*alice.client, &consensus_block_hash_fork_a)
            .unwrap()
            .unwrap();
    let domain_block_hash_fork_b =
        crate::aux_schema::best_domain_hash_for(&*alice.client, &consensus_block_hash_fork_b)
            .unwrap()
            .unwrap();
    assert_ne!(domain_block_hash_fork_a, domain_block_hash_fork_b);

    // The domain block header should contain a digest that points to the consensus block, which
    // derives the domain block
    let get_header = |hash| alice.client.header(hash).unwrap().unwrap();
    let get_digest_consensus_block_hash = |header: &Header| -> BlockHashFor<CBlock> {
        header
            .digest()
            .convert_first(DigestItem::as_consensus_block_info)
            .unwrap()
    };
    let domain_block_header_fork_a = get_header(domain_block_hash_fork_a);
    let domain_block_header_fork_b = get_header(domain_block_hash_fork_b);
    let digest_consensus_block_hash_fork_a =
        get_digest_consensus_block_hash(&domain_block_header_fork_a);
    assert_eq!(
        digest_consensus_block_hash_fork_a,
        consensus_block_hash_fork_a
    );
    let digest_consensus_block_hash_fork_b =
        get_digest_consensus_block_hash(&domain_block_header_fork_b);
    assert_eq!(
        digest_consensus_block_hash_fork_b,
        consensus_block_hash_fork_b
    );

    // The domain block headers should have the same `parent_hash`
    // but different digest and `state_root` (because digest is stored on chain)
    assert_eq!(
        domain_block_header_fork_a.parent_hash(),
        domain_block_header_fork_b.parent_hash()
    );
    assert_ne!(
        domain_block_header_fork_a.digest(),
        domain_block_header_fork_b.digest()
    );
    assert_ne!(
        domain_block_header_fork_a.state_root(),
        domain_block_header_fork_b.state_root()
    );

    // Simply produce more block
    produce_blocks!(ferdie, alice, 3).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_skip_empty_bundle_production() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node) with `skip_empty_bundle_production` set to `true`
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .skip_empty_bundle()
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Wait for `BlockTreePruningDepth + 1` blocks which is 10 + 1 in test
    // to enure the genesis ER is confirmed
    produce_blocks!(ferdie, alice, 11).await.unwrap();
    let consensus_block_number = ferdie.client.info().best_number;
    let domain_block_number = alice.client.info().best_number;

    let slot = ferdie.produce_slot();
    let bundle = ferdie.notify_new_slot_and_wait_for_bundle(slot).await;
    ferdie.produce_block_with_slot(slot).await.unwrap();

    // Alice will skip producing bundle since there is no domain extrinsic
    assert!(bundle.is_none());
    assert_eq!(ferdie.client.info().best_number, consensus_block_number + 1);
    assert_eq!(alice.client.info().best_number, domain_block_number);

    // Send a domain extrinsic, Alice will start producing bundle
    alice.send_system_remark().await;
    let (slot, _) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert_eq!(ferdie.client.info().best_number, consensus_block_number + 2);
    assert_eq!(alice.client.info().best_number, domain_block_number + 1);
}

// This test is more unstable on macOS
// TODO: find and fix the source of the instability (#3385)
#[cfg(not(target_os = "macos"))]
#[tokio::test(flavor = "multi_thread")]
async fn test_bad_receipt_chain() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Sr25519Alice,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Start another operator node
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("bob")),
    )
    .operator_id(2)
    .build_evm_node(Role::Authority, Charlie, &mut ferdie)
    .await;

    let mut bundle_producer = {
        let domain_bundle_proposer = DomainBundleProposer::new(
            EVM_DOMAIN_ID,
            alice.client.clone(),
            ferdie.client.clone(),
            alice.operator.transaction_pool.clone(),
        );
        let (bundle_sender, _bundle_receiver) =
            sc_utils::mpsc::tracing_unbounded("domain_bundle_stream", 100);
        TestBundleProducer::new(
            EVM_DOMAIN_ID,
            ferdie.client.clone(),
            alice.client.clone(),
            domain_bundle_proposer,
            Arc::new(bundle_sender),
            alice.operator.keystore.clone(),
            false,
            false,
        )
    };

    produce_blocks!(ferdie, alice, 15).await.unwrap();

    // Stop `Bob` so it won't generate fraud proof for the incoming bad ER
    bob.stop().await.unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to an invalid one
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let stale_bundle = opaque_bundle.clone();
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(receipt) = opaque_bundle.execution_receipt_as_mut();
        receipt.domain_block_hash = Default::default();
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    // Remove the fraud proof from tx pool
    ferdie.clear_tx_pool().await.unwrap();

    // Wait for a fraud proof that target the first bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        matches!(
            fp.proof,
            FraudProofVariant::InvalidDomainBlockHash(InvalidDomainBlockHashProof { .. })
        ) && fp.targeted_bad_receipt_hash() == bad_receipt_hash
    });

    // Produce more bundles with bad ERs that use the previous bad ER as an ancestor
    let mut parent_bad_receipt_hash = bad_receipt_hash;
    let mut bad_receipt_descendants = vec![];
    for _ in 0..7 {
        let slot = ferdie.produce_slot();
        let bundle = bundle_producer
            .produce_bundle(
                0,
                OperatorSlotInfo {
                    slot: slot.0,
                    proof_of_time: slot.1,
                },
            )
            .await
            .expect("produce bundle must success")
            .and_then(|res| res.into_opaque_bundle())
            .expect("must win the challenge");
        let (receipt_hash, bad_submit_bundle_tx) = {
            let mut opaque_bundle = bundle;
            let ExecutionReceiptMutRef::V0(receipt) = opaque_bundle.execution_receipt_as_mut();
            receipt.parent_domain_block_receipt_hash = parent_bad_receipt_hash;
            receipt.domain_block_hash = Default::default();
            opaque_bundle.set_signature(
                Sr25519Keyring::Alice
                    .pair()
                    .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                    .into(),
            );
            (
                opaque_bundle.receipt().hash::<BlakeTwo256>(),
                bundle_to_tx(&ferdie, opaque_bundle),
            )
        };
        parent_bad_receipt_hash = receipt_hash;
        bad_receipt_descendants.push(receipt_hash);
        ferdie
            .produce_block_with_slot_at(
                slot,
                ferdie.client.info().best_hash,
                Some(vec![bad_submit_bundle_tx]),
            )
            .await
            .unwrap();
    }

    // All bad ERs should be added to the consensus chain block tree
    for receipt_hash in bad_receipt_descendants.iter().chain(&[bad_receipt_hash]) {
        assert!(ferdie.does_receipt_exist(*receipt_hash).unwrap());
    }

    // The fraud proof should be submitted
    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // The first bad ER should be pruned, and its descendants marked as pending to prune
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let ferdie_best_hash = ferdie.client.info().best_hash;
    let runtime_api = ferdie.client.runtime_api();
    for receipt_hash in &bad_receipt_descendants {
        assert!(ferdie.does_receipt_exist(*receipt_hash).unwrap());
        assert!(
            runtime_api
                .is_bad_er_pending_to_prune(ferdie_best_hash, EVM_DOMAIN_ID, *receipt_hash)
                .unwrap()
        );
    }

    // There should be a receipt gap
    let head_domain_number = ferdie
        .client
        .runtime_api()
        .domain_best_number(ferdie_best_hash, EVM_DOMAIN_ID)
        .unwrap()
        .unwrap();
    let head_receipt_number = ferdie
        .client
        .runtime_api()
        .head_receipt_number(ferdie_best_hash, EVM_DOMAIN_ID)
        .unwrap();
    assert_eq!(head_domain_number - head_receipt_number, 9);
    // The previous bundle will be rejected as there is a receipt gap
    let ext = bundle_to_tx(&ferdie, stale_bundle);
    match ferdie.submit_transaction(ext).await.unwrap_err() {
        TxPoolError::InvalidTransaction(invalid_tx) => {
            assert_eq!(invalid_tx, InvalidTransactionCode::Bundle.into())
        }
        e => panic!("Unexpected error: {e}"),
    }

    // Register another operator as Alice is slashed
    ferdie
        .construct_and_send_extrinsic_with(pallet_domains::Call::register_operator {
            domain_id: EVM_DOMAIN_ID,
            amount: 1000 * AI3,
            config: OperatorConfig {
                signing_key: Sr25519Keyring::Charlie.public().into(),
                minimum_nominator_stake: Balance::MAX,
                nomination_tax: Default::default(),
            },
        })
        .await
        .unwrap();
    ferdie.produce_blocks(1).await.unwrap();

    ferdie
        .construct_and_send_extrinsic_with(pallet_sudo::Call::sudo {
            call: Box::new(subspace_test_runtime::RuntimeCall::Domains(
                pallet_domains::Call::force_staking_epoch_transition {
                    domain_id: EVM_DOMAIN_ID,
                },
            )),
        })
        .await
        .unwrap();
    ferdie.produce_blocks(1).await.unwrap();

    let alice_best_number = alice.client.info().best_number;
    drop(alice);

    // Restart `Bob`
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("bob")),
    )
    .operator_id(2)
    .build_evm_node(Role::Authority, Charlie, &mut ferdie)
    .await;
    ferdie.produce_blocks(1).await.unwrap();

    let bob_best_number = bob.client.info().best_number;
    assert_eq!(alice_best_number, bob_best_number);

    // The bad receipt and its descendants should be pruned immediately
    for receipt_hash in vec![bad_receipt_hash]
        .into_iter()
        .chain(bad_receipt_descendants)
    {
        let slot = ferdie.produce_slot();
        ferdie.notify_new_slot_and_wait_for_bundle(slot).await;
        ferdie.produce_block_with_slot(slot).await.unwrap();
        assert!(!ferdie.does_receipt_exist(receipt_hash).unwrap());
    }

    // The receipt gap should be filled up
    let ferdie_best_hash = ferdie.client.info().best_hash;
    let head_domain_number = ferdie
        .client
        .runtime_api()
        .domain_best_number(ferdie_best_hash, EVM_DOMAIN_ID)
        .unwrap()
        .unwrap();
    let head_receipt_number = ferdie
        .client
        .runtime_api()
        .head_receipt_number(ferdie_best_hash, EVM_DOMAIN_ID)
        .unwrap();
    assert_eq!(head_domain_number - head_receipt_number, 1);
    assert_eq!(bob_best_number, bob.client.info().best_number);

    produce_blocks!(ferdie, bob, 15).await.unwrap();
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_chain_storage_price_should_be_aligned_with_the_consensus_chain() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // The domain transaction byte is non-zero on the consensus chain genesis but
    // it is zero in the domain chain genesis
    let consensus_chain_byte_fee = ferdie
        .client
        .runtime_api()
        .consensus_transaction_byte_fee(ferdie.client.info().best_hash)
        .unwrap();
    let operator_consensus_chain_byte_fee = alice
        .client
        .runtime_api()
        .consensus_transaction_byte_fee(alice.client.info().best_hash)
        .unwrap();
    assert!(operator_consensus_chain_byte_fee.is_zero());
    assert!(!consensus_chain_byte_fee.is_zero());

    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // The domain transaction byte of the domain chain should be updated to the consensus chain's
    // through the inherent extrinsic of domain block #1
    let consensus_chain_byte_fee = ferdie
        .client
        .runtime_api()
        .consensus_transaction_byte_fee(ferdie.client.info().best_hash)
        .unwrap();
    let operator_consensus_chain_byte_fee = alice
        .client
        .runtime_api()
        .consensus_transaction_byte_fee(alice.client.info().best_hash)
        .unwrap();
    assert_eq!(consensus_chain_byte_fee, operator_consensus_chain_byte_fee);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_skip_duplicated_tx_in_previous_bundle() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    let bob_pre_balance = alice.free_balance(Bob.to_account_id());
    let call = pallet_balances::Call::transfer_allow_death {
        dest: Bob.to_account_id(),
        value: 1,
    };

    // Send a tx and produce a bundle, it will include the tx
    alice
        .construct_and_send_extrinsic_with(alice.account_nonce(), 0u32.into(), call.clone())
        .await
        .expect("Failed to send extrinsic");
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);

    // Produce a few more bundles, all of them will be empty since the only tx in the tx pool is already pick
    // up by the previous bundle
    for _ in 0..3 {
        let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        assert!(bundle.extrinsics().is_empty());
    }

    // Produce a domain that include all the bundles
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert_eq!(alice.free_balance(Bob.to_account_id()), bob_pre_balance + 1);

    // Produce a bundle with a tx but not include it in the next consensus block
    alice
        .construct_and_send_extrinsic_with(alice.account_nonce(), 0u32.into(), call.clone())
        .await
        .expect("Failed to send extrinsic");
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);
    ferdie
        .produce_block_with_slot_at(slot, ferdie.client.info().best_hash, Some(vec![]))
        .await
        .unwrap();

    // Even the tx is inclued in a previous bundle, after the consensus chain's tip changed, the operator
    // will resubmit the tx in the next bundle as retry
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);

    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert_eq!(alice.free_balance(Bob.to_account_id()), bob_pre_balance + 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_handle_duplicated_tx_with_diff_nonce_in_previous_bundle() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    let nonce = alice.account_nonce();
    let bob_pre_balance = alice.free_balance(Bob.to_account_id());
    let call = pallet_balances::Call::transfer_allow_death {
        dest: Bob.to_account_id(),
        value: 1,
    };

    // Send a tx and produce a bundle, it will include the tx
    alice
        .construct_and_send_extrinsic_with(nonce, 0u32.into(), call.clone())
        .await
        .expect("Failed to send extrinsic");
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);

    // Send a new tx with the same `nonce` and a tip then produce a bundle, this tx will replace
    // the previous tx in the tx pool and included in the bundle
    alice
        .construct_and_send_extrinsic_with(nonce, 1u32.into(), call.clone())
        .await
        .expect("Failed to send extrinsic");
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 1);

    // Send a tx with `nonce + 1` and produce a bundle, it won't include this tx because the tx
    // with `nonce` is included in previous bundle and is not submitted to the consensus chain yet
    alice
        .construct_and_send_extrinsic_with(nonce + 1, 0u32.into(), call.clone())
        .await
        .expect("Failed to send extrinsic");
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert!(bundle.extrinsics().is_empty());

    // Produce a domain that include all the bundles
    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert_eq!(alice.free_balance(Bob.to_account_id()), bob_pre_balance + 1);

    // Send a tx with `nonce + 2` and produce a bundle, it will include both the previous `nonce + 1`
    // tx and the `nonce + 2` tx
    alice
        .construct_and_send_extrinsic_with(nonce + 2, 0u32.into(), call.clone())
        .await
        .expect("Failed to send extrinsic");
    let (slot, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    assert_eq!(bundle.extrinsics().len(), 2);

    produce_block_with!(ferdie.produce_block_with_slot(slot), alice)
        .await
        .unwrap();
    assert_eq!(alice.free_balance(Bob.to_account_id()), bob_pre_balance + 3);
    assert_eq!(alice.account_nonce(), nonce + 3);
}

// TODO: add test to ensure MMR proof from diff fork wil be rejected
#[tokio::test(flavor = "multi_thread")]
async fn test_verify_mmr_proof_stateless() {
    use subspace_test_primitives::OnchainStateApi as _;
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie with Alice Key since that is the sudo key
    let mut ferdie = MockConsensusNode::run_with_finalization_depth(
        tokio_handle.clone(),
        Sr25519Alice,
        BasePath::new(directory.path().join("ferdie")),
        // finalization depth
        Some(10),
        false,
        None,
    );

    // Run Alice (an evm domain)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let to_prove = ferdie.client.info().best_number;
    let expected_state_root = *ferdie
        .client
        .header(ferdie.client.info().best_hash)
        .unwrap()
        .unwrap()
        .state_root();

    // Can't generate MMR proof for the current best block
    assert!(generate_mmr_proof(&ferdie.client, to_prove).is_err());

    produce_blocks!(ferdie, alice, 1).await.unwrap();

    let proof = generate_mmr_proof(&ferdie.client, to_prove).unwrap();
    for i in 0..20 {
        let res = ferdie
            .client
            .runtime_api()
            .verify_proof_and_extract_leaf(ferdie.client.info().best_hash, proof.clone())
            .unwrap()
            .map(|leaf| leaf.state_root());

        produce_blocks!(ferdie, alice, 1).await.unwrap();

        // The MMR is proof is valid for the first `MmrRootHashCount` (i.e. 15) blocks but then expired
        if i < 15 {
            assert_eq!(res, Some(expected_state_root));
        } else {
            assert_eq!(res, None);
        }
    }

    // Re-generate MMR proof for the same block, it will be valid for the next `MmrRootHashCount` blocks
    let proof = generate_mmr_proof(&ferdie.client, to_prove).unwrap();
    for _ in 0..15 {
        let res = ferdie
            .client
            .runtime_api()
            .verify_proof_and_extract_leaf(ferdie.client.info().best_hash, proof.clone())
            .unwrap()
            .map(|leaf| leaf.state_root());

        assert_eq!(res, Some(expected_state_root));
        produce_blocks!(ferdie, alice, 1).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_equivocated_bundle_check() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie with Alice Key since that is the sudo key
    let mut ferdie = MockConsensusNode::run_with_finalization_depth(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
        // finalization depth
        Some(10),
        false,
        None,
    );

    // Run Alice (an evm domain)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Get a bundle from the txn pool
    let (_, opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let proof_of_election = opaque_bundle.sealed_header().proof_of_election().clone();

    // Construct an equivocated bundle that with the same slot but different content
    let submit_equivocated_bundle_tx = {
        let mut equivocated_bundle = opaque_bundle.clone();
        equivocated_bundle.set_estimated_bundle_weight(Weight::from_all(123));
        equivocated_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(equivocated_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        bundle_to_tx(&ferdie, equivocated_bundle)
    };

    // Submit equivocated bundle to tx pool will failed because the equivocated bundle has
    // the same `provides` tag as the original bundle
    match ferdie
        .submit_transaction(submit_equivocated_bundle_tx.clone())
        .await
        .unwrap_err()
    {
        TxPoolError::TooLowPriority { .. } => {}
        e => panic!("Unexpected error: {e}"),
    }

    // Produce consensus block with equivocated bundle which will fail to include in block,
    // in production the whole block will be discard by the honest farmer
    let extrinsics = vec![
        bundle_to_tx(&ferdie, opaque_bundle.clone()),
        submit_equivocated_bundle_tx,
    ];
    ferdie
        .produce_block_with_extrinsics(extrinsics)
        .await
        .unwrap();
    let block_hash = ferdie.client.info().best_hash;
    let block_body = ferdie.client.block_body(block_hash).unwrap().unwrap();
    let bundles = ferdie
        .client
        .runtime_api()
        .extract_successful_bundles(block_hash, EVM_DOMAIN_ID, block_body)
        .unwrap();
    assert_eq!(bundles, vec![opaque_bundle]);

    // Produce consensus block with duplicated bundle which will fail to include in block,
    // in production the whole block will be discard by the honest farmer
    let (_, opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let extrinsics = vec![
        bundle_to_tx(&ferdie, opaque_bundle.clone()),
        bundle_to_tx(&ferdie, opaque_bundle.clone()),
    ];
    ferdie
        .produce_block_with_extrinsics(extrinsics)
        .await
        .unwrap();
    let block_hash = ferdie.client.info().best_hash;
    let block_body = ferdie.client.block_body(block_hash).unwrap().unwrap();
    let bundles = ferdie
        .client
        .runtime_api()
        .extract_successful_bundles(block_hash, EVM_DOMAIN_ID, block_body)
        .unwrap();
    assert_eq!(bundles, vec![opaque_bundle]);

    // Construct an equivocated bundle that reuse an old `proof_of_election`
    let (_, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let submit_equivocated_bundle_tx = {
        opaque_bundle.set_proof_of_election(proof_of_election);
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        bundle_to_tx(&ferdie, opaque_bundle)
    };
    // It will fail to submit to the tx pool
    match ferdie
        .submit_transaction(submit_equivocated_bundle_tx.clone())
        .await
        .unwrap_err()
    {
        TxPoolError::InvalidTransaction(invalid_tx) => {
            assert_eq!(invalid_tx, InvalidTransactionCode::Bundle.into())
        }
        e => panic!("Unexpected error: {e}"),
    }
    // Also fail to include in block
    let pre_ferdie_best_number = ferdie.client.info().best_number;
    let pre_alice_best_number = alice.client.info().best_number;
    ferdie
        .produce_block_with_extrinsics(vec![submit_equivocated_bundle_tx])
        .await
        .unwrap();
    assert_eq!(ferdie.client.info().best_number, pre_ferdie_best_number + 1);
    assert_eq!(alice.client.info().best_number, pre_alice_best_number);
}

// This test is more unstable on Windows and macOS
// TODO: find and fix the source of the instability (#3562)
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[tokio::test(flavor = "multi_thread")]
async fn test_xdm_false_invalid_fraud_proof() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie with Alice Key since that is the sudo key
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Sr25519Alice,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (an evm domain)
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run the cross domain gossip message worker
    ferdie.start_cross_domain_gossip_message_worker();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Open XDM channel between the consensus chain and the EVM domain
    open_xdm_channel(&mut ferdie, &mut alice).await;

    // Transfer balance through XDM
    ferdie
        .construct_and_send_extrinsic_with(pallet_transporter::Call::transfer {
            dst_location: pallet_transporter::Location {
                chain_id: ChainId::Domain(EVM_DOMAIN_ID),
                account_id: AccountId20Converter::convert(Alice.to_account_id()),
            },
            amount: 10,
        })
        .await
        .expect("Failed to construct and send extrinsic");

    // Wait until a bundle that cantains the XDM
    let mut maybe_opaque_bundle = None;
    produce_blocks_until!(ferdie, alice, {
        let alice_best_hash = alice.client.info().best_hash;
        let (_, opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        for tx in opaque_bundle.extrinsics().iter() {
            if alice
                .client
                .runtime_api()
                .extract_xdm_mmr_proof(alice_best_hash, tx)
                .unwrap()
                .is_some()
            {
                maybe_opaque_bundle.replace(opaque_bundle);
                break;
            }
        }
        maybe_opaque_bundle.is_some()
    })
    .await
    .unwrap();

    // Produce a block that contains the XDM
    let opaque_bundle = maybe_opaque_bundle.unwrap();
    let bundle_extrinsic_root = opaque_bundle.extrinsics_root();
    let slot = ferdie.produce_slot();
    let exts = vec![bundle_to_tx(&ferdie, opaque_bundle)];
    produce_block_with!(
        ferdie.produce_block_with_slot_at(slot, ferdie.client.info().best_hash, Some(exts)),
        alice
    )
    .await
    .unwrap();

    // produce another bundle that marks the XDM as invalid.
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(bad_receipt) = opaque_bundle.execution_receipt_as_mut();
        bad_receipt.inboxed_bundles = vec![InboxedBundle::invalid(
            InvalidBundleType::InvalidXDM(0),
            bundle_extrinsic_root,
        )];

        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidBundles(proof) = &fp.proof
            && let InvalidBundleType::InvalidXDM(extrinsic_index) = proof.invalid_bundle_type()
        {
            assert!(!proof.is_good_invalid_fraud_proof());
            assert_eq!(extrinsic_index, 0);
            return true;
        }
        false
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    // Produce a block that contains `bad_submit_bundle_tx`
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

// TODO: this test is flaky and sometime hang forever in CI thus disable it temporary,
// do investigate and fix it
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_stale_fork_xdm_true_invalid_fraud_proof() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie with Alice Key since that is the sudo key
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Sr25519Alice,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (an evm domain)
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run the cross domain gossip message worker
    ferdie.start_cross_domain_gossip_message_worker();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Open XDM channel between the consensus chain and the EVM domain
    open_xdm_channel(&mut ferdie, &mut alice).await;

    // Transfer balance through XDM
    ferdie
        .construct_and_send_extrinsic_with(pallet_transporter::Call::transfer {
            dst_location: pallet_transporter::Location {
                chain_id: ChainId::Domain(EVM_DOMAIN_ID),
                account_id: AccountId20Converter::convert(Alice.to_account_id()),
            },
            amount: 10,
        })
        .await
        .expect("Failed to construct and send extrinsic");

    // Wait until a bundle that cantains the XDM
    let mut maybe_opaque_bundle = None;
    produce_blocks_until!(ferdie, alice, {
        let alice_best_hash = alice.client.info().best_hash;
        let (_, opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        for tx in opaque_bundle.extrinsics().iter() {
            if alice
                .client
                .runtime_api()
                .extract_xdm_mmr_proof(alice_best_hash, tx)
                .unwrap()
                .is_some()
            {
                maybe_opaque_bundle.replace(opaque_bundle);
                break;
            }
        }
        maybe_opaque_bundle.is_some()
    })
    .await
    .unwrap();

    let xdm = maybe_opaque_bundle.unwrap().extrinsics()[0].clone();
    let mmr_proof_constructed_at_number = alice
        .client
        .runtime_api()
        .extract_xdm_mmr_proof(alice.client.info().best_hash, &xdm)
        .unwrap()
        .unwrap()
        .consensus_block_number;

    // Construct a fork and make it the best fork so the XDM mmr proof is in the stale fork
    let best_number = ferdie.client.info().best_number;
    let mut fork_block_hash = ferdie
        .client
        .hash(mmr_proof_constructed_at_number - 2)
        .unwrap()
        .unwrap();
    for _ in 0..(best_number - mmr_proof_constructed_at_number) + 5 {
        let slot = ferdie.produce_slot();
        fork_block_hash = ferdie
            .produce_block_with_slot_at(slot, fork_block_hash, Some(vec![]))
            .await
            .unwrap();
    }
    // The XDM should be rejected as its mmr proof is in the stale fork
    let alice_best_hash = alice.client.info().best_hash;
    let res = alice
        .client
        .runtime_api()
        .validate_transaction(
            alice_best_hash,
            TransactionSource::External,
            xdm.clone(),
            alice_best_hash,
        )
        .unwrap();
    assert_eq!(
        res,
        Err(TransactionValidityError::Invalid(
            InvalidTransaction::BadProof
        ))
    );

    // Construct an bundle that contain the invalid xdm and submit the bundle
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let (bundle_extrinsic_root, bad_submit_bundle_tx) = {
        let mut exts = opaque_bundle.extrinsics().to_vec();
        exts.push(xdm);
        opaque_bundle.set_extrinsics(exts);
        let extrinsics = opaque_bundle
            .extrinsics()
            .iter()
            .map(|ext| ext.encode())
            .collect();
        opaque_bundle.set_bundle_extrinsics_root(BlakeTwo256::ordered_trie_root(
            extrinsics,
            StateVersion::V1,
        ));
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.extrinsics_root(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();

    // produce another bundle that marks the invalid xdm as valid.
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(bad_receipt) = opaque_bundle.execution_receipt_as_mut();
        assert!(bad_receipt.inboxed_bundles[0].is_invalid());
        bad_receipt.inboxed_bundles =
            vec![InboxedBundle::valid(H256::random(), bundle_extrinsic_root)];
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidBundles(proof) = &fp.proof
            && let InvalidBundleType::InvalidXDM(extrinsic_index) = proof.invalid_bundle_type()
        {
            assert!(proof.is_good_invalid_fraud_proof());
            assert_eq!(extrinsic_index, 0);
            return true;
        }
        false
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    // Produce a block that contains `bad_submit_bundle_tx`
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_custom_api_storage_root_match_upstream_root() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    let domain_parent_number = alice.client.info().best_number;
    let domain_parent_hash = alice.client.info().best_hash;
    let alice_account_nonce = alice.account_nonce();
    let alice_total_balance = alice.free_balance(Alice.to_account_id());
    // Success tx
    let tx1 = alice.construct_extrinsic(
        alice_account_nonce,
        pallet_balances::Call::transfer_allow_death {
            dest: Bob.to_account_id(),
            value: 1234567890987654321,
        },
    );
    // Tx fail during execution due to insufficient fund
    let tx2 = alice.construct_extrinsic(
        alice_account_nonce + 1,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: alice_total_balance + 1,
        },
    );
    // Tx transfer all of Alice's fund
    let tx3 = alice.construct_extrinsic(
        alice_account_nonce + 2,
        pallet_balances::Call::transfer_all {
            dest: Dave.to_account_id(),
            keep_alive: false,
        },
    );
    // Tx fail during pre-dispatch due to unable to pay tx fee
    let tx4 = alice.construct_extrinsic(
        alice_account_nonce + 3,
        pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: 1,
        },
    );
    for tx in [tx1, tx2, tx3, tx4] {
        alice
            .send_extrinsic(tx)
            .await
            .expect("Failed to send extrinsic");
    }

    // Produce a domain block that contains the previously sent extrinsic
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // Get the receipt of that block, its execution trace is generated by the custom API instance
    let (_, bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let receipt = bundle.into_receipt();
    assert_eq!(receipt.execution_traces().len(), 8);

    let mut roots = vec![];
    let runtime_api_instance = alice.client.runtime_api();

    let init_header = <HeaderFor<DomainBlock> as HeaderT>::new(
        domain_parent_number + 1u32,
        Default::default(),
        Default::default(),
        domain_parent_hash,
        Digest {
            logs: vec![DigestItem::consensus_block_info(
                *receipt.consensus_block_hash(),
            )],
        },
    );
    runtime_api_instance
        .initialize_block(domain_parent_hash, &init_header)
        .unwrap();
    roots.push(
        runtime_api_instance
            .storage_root(domain_parent_hash)
            .unwrap(),
    );

    let domain_block_body = {
        let best_hash = alice.client.info().best_hash;
        alice.client.block_body(best_hash).unwrap().unwrap()
    };
    for xt in domain_block_body {
        let _ = runtime_api_instance.execute_in_transaction(|api| {
            match api.apply_extrinsic(domain_parent_hash, xt) {
                Ok(Ok(_)) => TransactionOutcome::Commit(Ok(())),
                Ok(Err(tx_validity)) => TransactionOutcome::Rollback(Err(
                    ApplyExtrinsicFailed::Validity(tx_validity).into(),
                )),
                Err(e) => TransactionOutcome::Rollback(Err(sp_blockchain::Error::from(e))),
            }
        });
        roots.push(
            runtime_api_instance
                .storage_root(domain_parent_hash)
                .unwrap(),
        );
    }

    let finalized_header = runtime_api_instance
        .finalize_block(domain_parent_hash)
        .unwrap();
    roots.push((*finalized_header.state_root()).into());

    let roots: Vec<BlockHashFor<DomainBlock>> = roots
        .into_iter()
        .map(|r| BlockHashFor::<DomainBlock>::decode(&mut r.as_slice()).unwrap())
        .collect();

    assert_eq!(receipt.execution_traces().to_vec(), roots);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_xdm_channel_allowlist_removed_after_xdm_initiated() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Sr25519Alice,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a system domain authority node)
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run the cross domain gossip message worker
    ferdie.start_cross_domain_gossip_message_worker();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Open XDM channel between the consensus chain and the EVM domain
    open_xdm_channel(&mut ferdie, &mut alice).await;

    // Transfer balance through XDM
    let transfer_amount = 1234567890987654321;
    let pre_alice_free_balance = alice.free_balance(alice.key.to_account_id());
    ferdie
        .construct_and_send_extrinsic_with(pallet_transporter::Call::transfer {
            dst_location: pallet_transporter::Location {
                chain_id: ChainId::Domain(EVM_DOMAIN_ID),
                account_id: AccountId20Converter::convert(Alice.to_account_id()),
            },
            amount: transfer_amount,
        })
        .await
        .expect("Failed to construct and send extrinsic");
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // Remove the consensus chain from EVM domain's channel allowlist
    let tx = ferdie.construct_extrinsic(
        ferdie.account_nonce(),
        subspace_test_runtime::RuntimeCall::Messenger(
            pallet_messenger::Call::initiate_domain_update_chain_allowlist {
                domain_id: EVM_DOMAIN_ID,
                update: ChainAllowlistUpdate::Remove(ChainId::Consensus),
            },
        ),
    );
    ferdie
        .produce_block_with_extrinsics(vec![tx.into()])
        .await
        .unwrap();

    // The XDM should be failed to executed and the XDM response should return the fund
    // to the sender (after XDM fees deducted) while the receiver's balance unchanged
    let ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());
    produce_blocks_until!(ferdie, alice, {
        let post_alice_free_balance = alice.free_balance(alice.key.to_account_id());
        let post_ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());

        post_alice_free_balance == pre_alice_free_balance
            && post_ferdie_free_balance == ferdie_free_balance + transfer_amount
    })
    .await
    .unwrap();
}

// This test is more unstable on Windows and macOS
// TODO: find and fix the source of the instability (#3562)
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[tokio::test(flavor = "multi_thread")]
async fn test_xdm_channel_allowlist_removed_after_xdm_req_relaying() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Sr25519Alice,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a system domain authority node)
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run the cross domain gossip message worker
    ferdie.start_cross_domain_gossip_message_worker();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Open XDM channel between the consensus chain and the EVM domain
    open_xdm_channel(&mut ferdie, &mut alice).await;

    // Transfer balance through XDM
    let transfer_amount = 1234567890987654321;
    let pre_alice_free_balance = alice.free_balance(alice.key.to_account_id());
    ferdie
        .construct_and_send_extrinsic_with(pallet_transporter::Call::transfer {
            dst_location: pallet_transporter::Location {
                chain_id: ChainId::Domain(EVM_DOMAIN_ID),
                account_id: AccountId20Converter::convert(Alice.to_account_id()),
            },
            amount: transfer_amount,
        })
        .await
        .expect("Failed to construct and send extrinsic");
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // Wait until a bundle that cantains the XDM
    let mut maybe_opaque_bundle = None;
    produce_blocks_until!(ferdie, alice, {
        let alice_best_hash = alice.client.info().best_hash;
        let (_, opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        for tx in opaque_bundle.extrinsics().iter() {
            if alice
                .client
                .runtime_api()
                .extract_xdm_mmr_proof(alice_best_hash, tx)
                .unwrap()
                .is_some()
            {
                maybe_opaque_bundle.replace(opaque_bundle);
                break;
            }
        }
        maybe_opaque_bundle.is_some()
    })
    .await
    .unwrap();
    let opaque_bundle = maybe_opaque_bundle.unwrap();

    // Remove the consensus chain from EVM domain's channel allowlist
    let tx = ferdie.construct_extrinsic(
        ferdie.account_nonce(),
        subspace_test_runtime::RuntimeCall::Messenger(
            pallet_messenger::Call::initiate_domain_update_chain_allowlist {
                domain_id: EVM_DOMAIN_ID,
                update: ChainAllowlistUpdate::Remove(ChainId::Consensus),
            },
        ),
    );
    ferdie
        .produce_block_with_extrinsics(vec![tx.into()])
        .await
        .unwrap();

    // Submit the XDM after the consensus chain is removed from the allowlist
    let exts = vec![bundle_to_tx(&ferdie, opaque_bundle)];
    produce_block_with!(ferdie.produce_block_with_extrinsics(exts), alice)
        .await
        .unwrap();

    // The XDM should be failed to executed and the XDM response should return the fund
    // to the sender (after XDM fees deducted) while the receiver's balance unchanged
    let ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());
    produce_blocks_until!(ferdie, alice, {
        let post_alice_free_balance = alice.free_balance(alice.key.to_account_id());
        let post_ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());

        post_alice_free_balance == pre_alice_free_balance
            && post_ferdie_free_balance == ferdie_free_balance + transfer_amount
    })
    .await
    .unwrap();
}

// This test is more unstable on Windows and macOS
// TODO: find and fix the source of the instability (#3562)
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[tokio::test(flavor = "multi_thread")]
async fn test_xdm_channel_allowlist_removed_after_xdm_resp_relaying() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Sr25519Alice,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a system domain authority node)
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run the cross domain gossip message worker
    ferdie.start_cross_domain_gossip_message_worker();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Open XDM channel between the consensus chain and the EVM domain
    open_xdm_channel(&mut ferdie, &mut alice).await;

    // Transfer balance through XDM
    let transfer_amount = 1234567890987654321;
    let pre_alice_free_balance = alice.free_balance(alice.key.to_account_id());
    let pre_bob_free_balance = ferdie.free_balance(Sr25519Keyring::Bob.to_account_id());
    alice
        .construct_and_send_extrinsic(pallet_transporter::Call::transfer {
            dst_location: pallet_transporter::Location {
                chain_id: ChainId::Consensus,
                account_id: AccountIdConverter::convert(Sr25519Keyring::Bob.to_account_id()),
            },
            amount: transfer_amount,
        })
        .await
        .expect("Failed to construct and send extrinsic");

    // XDM is send from domain to consensus, so wait for a bundle that cantains the XDM response
    let mut maybe_opaque_bundle = None;
    produce_blocks_until!(ferdie, alice, {
        let alice_best_hash = alice.client.info().best_hash;
        let (_, opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
        for tx in opaque_bundle.extrinsics().iter() {
            if alice
                .client
                .runtime_api()
                .extract_xdm_mmr_proof(alice_best_hash, tx)
                .unwrap()
                .is_some()
            {
                maybe_opaque_bundle.replace(opaque_bundle);
                break;
            }
        }
        maybe_opaque_bundle.is_some()
    })
    .await
    .unwrap();
    let opaque_bundle = maybe_opaque_bundle.unwrap();

    // Remove the consensus chain from EVM domain's channel allowlist
    let tx = ferdie.construct_extrinsic(
        ferdie.account_nonce(),
        subspace_test_runtime::RuntimeCall::Messenger(
            pallet_messenger::Call::initiate_domain_update_chain_allowlist {
                domain_id: EVM_DOMAIN_ID,
                update: ChainAllowlistUpdate::Remove(ChainId::Consensus),
            },
        ),
    );
    ferdie
        .produce_block_with_extrinsics(vec![tx.into()])
        .await
        .unwrap();

    // Submit the XDM response after the consensus chain is removed from the allowlist
    let extrinsics = vec![bundle_to_tx(&ferdie, opaque_bundle)];
    produce_block_with!(ferdie.produce_block_with_extrinsics(extrinsics), alice)
        .await
        .unwrap();

    // The XDM should be success
    produce_blocks_until!(ferdie, alice, {
        let post_alice_free_balance = alice.free_balance(alice.key.to_account_id());
        let post_bob_free_balance = ferdie.free_balance(Sr25519Keyring::Bob.to_account_id());

        post_alice_free_balance < pre_alice_free_balance - transfer_amount
            && post_bob_free_balance == pre_bob_free_balance + transfer_amount
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_xdm_transfer_below_existential_deposit() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Sr25519Alice,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a system domain authority node)
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run the cross domain gossip message worker
    ferdie.start_cross_domain_gossip_message_worker();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Open XDM channel between the consensus chain and the EVM domain
    open_xdm_channel(&mut ferdie, &mut alice).await;

    // Transfer fund that below `ExistentialDeposit` to an non-exist account in the EVM domain
    ferdie
        .construct_and_send_extrinsic_with(pallet_transporter::Call::transfer {
            dst_location: pallet_transporter::Location {
                chain_id: ChainId::Domain(EVM_DOMAIN_ID),
                account_id: AccountId20Converter::convert(EcdsaKeyring::One.to_account_id()),
            },
            amount: 1,
        })
        .await
        .expect("Failed to construct and send extrinsic");
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // The XDM should success but the receiver's balance is still 0 since the fund is below `ExistentialDeposit`
    // the receiver account can't be created
    let pre_ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());
    produce_blocks_until!(ferdie, alice, {
        let channel_nonce = ferdie
            .client
            .runtime_api()
            .channel_nonce(
                ferdie.client.info().best_hash,
                ChainId::Domain(EVM_DOMAIN_ID),
                ChannelId::zero(),
            )
            .unwrap()
            .unwrap();
        if channel_nonce.relay_response_msg_nonce == Some(U256::from(0)) {
            let post_ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());
            assert!(
                alice
                    .free_balance(EcdsaKeyring::One.to_account_id())
                    .is_zero()
            );
            assert_eq!(post_ferdie_free_balance, pre_ferdie_free_balance);
            true
        } else {
            false
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_xdm_transfer_to_wrong_format_address() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Sr25519Alice,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a system domain authority node)
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run the cross domain gossip message worker
    ferdie.start_cross_domain_gossip_message_worker();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Open XDM channel between the consensus chain and the EVM domain
    open_xdm_channel(&mut ferdie, &mut alice).await;

    // Transfer funds to a substrate address in the EVM domain
    let transfer_amount = 1234567890987654321;
    let pre_alice_free_balance = alice.free_balance(alice.key.to_account_id());
    ferdie
        .construct_and_send_extrinsic_with(pallet_transporter::Call::transfer {
            dst_location: pallet_transporter::Location {
                chain_id: ChainId::Domain(EVM_DOMAIN_ID),
                // A substrate address
                account_id: AccountIdConverter::convert(Sr25519Alice.into()),
            },
            amount: transfer_amount,
        })
        .await
        .expect("Failed to construct and send extrinsic");
    produce_blocks!(ferdie, alice, 1).await.unwrap();

    // The XDM should be failed to executed and the XDM response should return the fund
    // to the sender (after XDM fees deducted) while the receiver's balance unchanged
    let ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());
    produce_blocks_until!(ferdie, alice, {
        let post_alice_free_balance = alice.free_balance(alice.key.to_account_id());
        let post_ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());

        post_alice_free_balance == pre_alice_free_balance
            && post_ferdie_free_balance == ferdie_free_balance + transfer_amount
    })
    .await
    .unwrap();
}

// TODO: ignore test until we bring back the best block number as starting nonce instead of 0.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_current_block_number_used_as_new_account_nonce() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run Bob (a auto-id domain authority node)
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("bob")),
    )
    .build_auto_id_node(Role::Authority, Sr25519Keyring::Bob, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 3, bob).await.unwrap();

    let tx = subspace_test_service::construct_extrinsic_generic::<_>(
        &ferdie.client,
        pallet_balances::Call::transfer_all {
            dest: MultiAddress::Id(Sr25519Keyring::Eve.to_account_id()),
            keep_alive: false,
        },
        Sr25519Keyring::Charlie,
        false,
        0,
        0u128,
    );
    ferdie.send_extrinsic(tx).await.unwrap();

    let tx = domain_test_service::construct_extrinsic_generic::<evm_domain_test_runtime::Runtime, _>(
        &alice.client,
        pallet_balances::Call::transfer_all {
            dest: Eve.to_account_id(),
            keep_alive: false,
        },
        Charlie,
        false,
        0,
        0u128,
    );
    alice.send_extrinsic(tx).await.unwrap();

    let tx = domain_test_service::construct_extrinsic_generic::<
        auto_id_domain_test_runtime::Runtime,
        _,
    >(
        &bob.client,
        pallet_balances::Call::transfer_all {
            dest: MultiAddress::Id(Sr25519Keyring::Eve.to_account_id()),
            keep_alive: false,
        },
        Sr25519Keyring::Charlie,
        false,
        0,
        0u128,
    );
    bob.send_extrinsic(tx).await.unwrap();

    produce_blocks!(ferdie, alice, 5, bob).await.unwrap();

    // Charlie now has 0 balance and is reaped
    assert_eq!(
        ferdie.free_balance(Sr25519Keyring::Charlie.to_account_id()),
        0u128
    );
    assert_eq!(alice.free_balance(Charlie.to_account_id()), 0u128);
    assert_eq!(
        bob.free_balance(Sr25519Keyring::Charlie.to_account_id()),
        0u128
    );

    // Transfer fund back to Charlie
    let transfer_amount = 1234567890987654321;
    ferdie
        .construct_and_send_extrinsic_with(pallet_balances::Call::transfer_allow_death {
            dest: MultiAddress::Id(Sr25519Keyring::Charlie.to_account_id()),
            value: transfer_amount,
        })
        .await
        .unwrap();
    alice
        .construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
            dest: Charlie.to_account_id(),
            value: transfer_amount,
        })
        .await
        .unwrap();
    bob.construct_and_send_extrinsic(pallet_balances::Call::transfer_allow_death {
        dest: MultiAddress::Id(Sr25519Keyring::Charlie.to_account_id()),
        value: transfer_amount,
    })
    .await
    .unwrap();

    produce_blocks!(ferdie, alice, 1, bob).await.unwrap();

    // Charlie account is recreated with current block number as nonce
    assert_eq!(
        ferdie.account_nonce_of(Sr25519Keyring::Charlie.to_account_id()),
        ferdie.client.info().best_number
    );
    assert_eq!(
        alice.account_nonce_of(Charlie.to_account_id()),
        alice.client.info().best_number
    );
    assert_eq!(
        bob.account_nonce_of(Sr25519Keyring::Charlie.to_account_id()),
        bob.client.info().best_number
    );
}

// This test is unstable on Windows, it likely contains a filesystem race condition between stopping
// the node `bob`, and restarting that node with the same data directory.
#[tokio::test(flavor = "multi_thread")]
async fn test_domain_node_starting_check() {
    use futures::FutureExt;
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Produce 5 consensus block without bundle
    for _ in 0..5 {
        ferdie.produce_block_with_extrinsics(vec![]).await.unwrap();
    }
    assert_eq!(ferdie.client.info().best_number, 5);
    assert_eq!(alice.client.info().best_number, 0);

    // Start one more domain node `Bob` on the same consensus node shoule be fine
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("bob")),
    )
    .operator_id(1)
    .build_evm_node(Role::Authority, Bob, &mut ferdie)
    .await;

    // Produce 3 domain blocks
    produce_blocks!(ferdie, alice, 3, bob).await.unwrap();
    assert_eq!(alice.client.info().best_number, 3);
    assert_eq!(bob.client.info().best_number, 3);

    // Stop `Bob`, produce more domain blocks, then restart `Bob` with the same
    // consensus node should be fine
    bob.stop().await.unwrap();

    produce_blocks!(ferdie, alice, 3).await.unwrap();
    assert_eq!(alice.client.info().best_number, 6);

    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("bob")),
    )
    .operator_id(1)
    .build_evm_node(Role::Authority, Bob, &mut ferdie)
    .await;
    assert_eq!(bob.client.info().best_number, 3);

    // It should be able catch up the missed domain block as more consensus block
    // produced
    ferdie.produce_block_with_extrinsics(vec![]).await.unwrap();
    assert_eq!(bob.client.info().best_number, 6);

    // Starting another domain node with the same consensus node should fail now.
    // Because there are already domain blocks produced, the domain node has to start
    // with a fresh consensus node
    let tokio_handle_clone = tokio_handle.clone();
    let charlie_base_path = BasePath::new(directory.path().join("charlie"));
    let result = async move {
        std::panic::AssertUnwindSafe(
            domain_test_service::DomainNodeBuilder::new(tokio_handle_clone, charlie_base_path)
                .operator_id(2)
                .build_evm_node(Role::Authority, Charlie, &mut ferdie),
        )
        .catch_unwind()
        .await
    }
    .await;
    assert!(result.is_err());

    // Restart a domain node with a fresh consensus node should fail
    let mut eve = MockConsensusNode::run(
        tokio_handle.clone(),
        Sr25519Keyring::Eve,
        BasePath::new(directory.path().join("eve")),
    );
    let alice_base_path = alice.base_path.clone();
    alice.stop().await.unwrap();
    let result = async move {
        std::panic::AssertUnwindSafe(
            domain_test_service::DomainNodeBuilder::new(tokio_handle, alice_base_path)
                // Build with another domain id `3`, which is not instantiated in the
                // consensus chain, to simulate the domain node `alice` is running ahead
                // of the consensus node `eve`.
                .build_evm_node_with(Role::Authority, Alice, &mut eve, 3.into()),
        )
        .catch_unwind()
        .await
    }
    .await;
    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_chain_reward_receipt() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    let mut bundle_producer = {
        let domain_bundle_proposer = DomainBundleProposer::new(
            EVM_DOMAIN_ID,
            alice.client.clone(),
            ferdie.client.clone(),
            alice.operator.transaction_pool.clone(),
        );
        let (bundle_sender, _bundle_receiver) =
            sc_utils::mpsc::tracing_unbounded("domain_bundle_stream", 100);
        TestBundleProducer::new(
            EVM_DOMAIN_ID,
            ferdie.client.clone(),
            alice.client.clone(),
            domain_bundle_proposer,
            Arc::new(bundle_sender),
            alice.operator.keystore.clone(),
            false,
            false,
        )
    };

    produce_blocks!(ferdie, alice, 5).await.unwrap();

    // Get a bundle from the txn pool and modify the receipt of the target bundle to has an invalid `chain_rewards`
    let (slot, mut opaque_bundle) = ferdie.produce_slot_and_wait_for_bundle_submission().await;
    let (first_bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(receipt) = opaque_bundle.execution_receipt_as_mut();
        // Set an invalid `chain_rewards` that exceeds the domain's total balance
        receipt
            .block_fees
            .chain_rewards
            .insert(ChainId::Consensus, Balance::MAX / 2);
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(first_bad_receipt_hash).unwrap());

    // Produce more bundles with bad ERs that use the previous bad ER as an ancestor,
    // also not include the FP in the consensus block to try confirm the bad ER
    let mut parent_bad_receipt_hash = first_bad_receipt_hash;
    for i in 0..DOMAINS_BLOCK_PRUNING_DEPTH + 5 {
        let slot = ferdie.produce_slot();
        let bundle = bundle_producer
            .produce_bundle(
                0,
                OperatorSlotInfo {
                    slot: slot.0,
                    proof_of_time: slot.1,
                },
            )
            .await
            .expect("produce bundle must success")
            .and_then(|res| res.into_opaque_bundle())
            .expect("must win the challenge");
        let bad_submit_bundle_tx = {
            let mut opaque_bundle = bundle;
            let ExecutionReceiptMutRef::V0(receipt) = opaque_bundle.execution_receipt_as_mut();
            receipt.parent_domain_block_receipt_hash = parent_bad_receipt_hash;
            opaque_bundle.set_signature(
                Sr25519Keyring::Alice
                    .pair()
                    .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                    .into(),
            );
            parent_bad_receipt_hash = opaque_bundle.receipt().hash::<BlakeTwo256>();

            bundle_to_tx(&ferdie, opaque_bundle)
        };

        let pre_consensus_best_number = ferdie.client.info().best_number;
        let pre_domain_best_number = alice.client.info().best_number;
        ferdie
            .produce_block_with_slot_at(
                slot,
                ferdie.client.info().best_hash,
                Some(vec![bad_submit_bundle_tx]),
            )
            .await
            .unwrap();

        assert_eq!(
            ferdie.client.info().best_number,
            pre_consensus_best_number + 1
        );

        // The first bad ER supposed to be confirmed at `DOMAINS_BLOCK_PRUNING_DEPTH - 1` since
        // there is no FP included by the consensus chain to prune it. But the domain balance
        // bookkeeping check will reject to confirm the first bad ER because the invalid `chain_rewards`
        // exceeds the domain's total balance thus the bundle will fail and derive no domain block
        // so the domain chain will stop progressing and the first bad ER is not confirmed.
        let post_domain_best_number = if i < DOMAINS_BLOCK_PRUNING_DEPTH - 1 {
            pre_domain_best_number + 1
        } else {
            pre_domain_best_number
        };
        assert_eq!(alice.client.info().best_number, post_domain_best_number);

        assert!(ferdie.does_receipt_exist(first_bad_receipt_hash).unwrap());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_domain_total_issuance_match_consensus_chain_bookkeeping_with_xdm() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Sr25519Alice,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a system domain authority node)
    let mut alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run the cross domain gossip message worker
    ferdie.start_cross_domain_gossip_message_worker();

    produce_blocks!(ferdie, alice, 3).await.unwrap();

    // Open XDM channel between the consensus chain and the EVM domain
    open_xdm_channel(&mut ferdie, &mut alice).await;

    for i in 0..10 {
        let transfer_amount = 123456789987654321 * i;
        let domain_to_consensus = i % 2 == 0;

        // Transfer balance from
        let pre_alice_free_balance = alice.free_balance(alice.key.to_account_id());
        let pre_ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());

        if domain_to_consensus {
            alice
                .construct_and_send_extrinsic(pallet_transporter::Call::transfer {
                    dst_location: pallet_transporter::Location {
                        chain_id: ChainId::Consensus,
                        account_id: AccountIdConverter::convert(Sr25519Alice.into()),
                    },
                    amount: transfer_amount,
                })
                .await
                .expect("Failed to construct and send extrinsic");
        } else {
            ferdie
                .construct_and_send_extrinsic_with(pallet_transporter::Call::transfer {
                    dst_location: pallet_transporter::Location {
                        chain_id: ChainId::Domain(EVM_DOMAIN_ID),
                        account_id: AccountId20Converter::convert(Alice.to_account_id()),
                    },
                    amount: transfer_amount,
                })
                .await
                .expect("Failed to construct and send extrinsic");
        }

        // Wait until transfer succeed
        produce_blocks_until!(ferdie, alice, {
            let post_alice_free_balance = alice.free_balance(alice.key.to_account_id());
            let post_ferdie_free_balance = ferdie.free_balance(ferdie.key.to_account_id());

            if domain_to_consensus {
                post_alice_free_balance <= pre_alice_free_balance - transfer_amount
                    && post_ferdie_free_balance == pre_ferdie_free_balance + transfer_amount
            } else {
                post_ferdie_free_balance <= pre_ferdie_free_balance - transfer_amount
                    && post_alice_free_balance == pre_alice_free_balance + transfer_amount
            }
        })
        .await
        .unwrap();

        let ferdie_best_hash = ferdie.client.info().best_hash;
        let (_, confirmed_domain_hash) = ferdie
            .client
            .runtime_api()
            .latest_confirmed_domain_block(ferdie_best_hash, EVM_DOMAIN_ID)
            .unwrap()
            .unwrap();
        let domain_total_balance = ferdie
            .client
            .runtime_api()
            .domain_balance(ferdie_best_hash, EVM_DOMAIN_ID)
            .unwrap();
        let domain_total_issuance = alice
            .client
            .runtime_api()
            .total_issuance(confirmed_domain_hash)
            .unwrap();
        assert_eq!(domain_total_balance, domain_total_issuance);

        ferdie.clear_tx_pool().await.unwrap();
        alice.clear_tx_pool().await;
        produce_blocks!(ferdie, alice, 5).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_false_bundle_author() {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

    let mut builder = sc_cli::LoggerBuilder::new("");
    builder.with_colors(false);
    let _ = builder.init();

    let tokio_handle = tokio::runtime::Handle::current();

    // Start Ferdie
    let mut ferdie = MockConsensusNode::run(
        tokio_handle.clone(),
        Ferdie,
        BasePath::new(directory.path().join("ferdie")),
    );

    // Run Alice (a evm domain authority node)
    let alice = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("alice")),
    )
    .build_evm_node(Role::Authority, Alice, &mut ferdie)
    .await;

    // Run Bob as another authority node
    let bob_operator_id = 2;
    let bob = domain_test_service::DomainNodeBuilder::new(
        tokio_handle.clone(),
        BasePath::new(directory.path().join("bob")),
    )
    .operator_id(bob_operator_id)
    .build_evm_node(Role::Authority, Bob, &mut ferdie)
    .await;

    produce_blocks!(ferdie, alice, 1, bob).await.unwrap();

    let tx = subspace_test_service::construct_extrinsic_generic::<_>(
        &ferdie.client,
        pallet_domains::Call::register_operator {
            domain_id: EVM_DOMAIN_ID,
            amount: 100 * AI3,
            config: OperatorConfig {
                signing_key: get_from_seed::<OperatorPublicKey>("Bob"),
                minimum_nominator_stake: 100 * AI3,
                nomination_tax: Percent::from_percent(5),
            },
        },
        Sr25519Keyring::Bob,
        false,
        0,
        0u128,
    );
    ferdie.send_extrinsic(tx).await.unwrap();
    produce_blocks!(ferdie, alice, 1, bob).await.unwrap();

    let staking_summary = ferdie
        .get_domain_staking_summary(EVM_DOMAIN_ID)
        .unwrap()
        .unwrap();
    assert!(staking_summary.next_operators.contains(&bob_operator_id));

    let tx = subspace_test_service::construct_extrinsic_generic::<_>(
        &ferdie.client,
        pallet_sudo::Call::sudo {
            call: Box::new(
                pallet_domains::Call::force_staking_epoch_transition {
                    domain_id: EVM_DOMAIN_ID,
                }
                .into(),
            ),
        },
        Sr25519Keyring::Alice,
        false,
        0,
        0u128,
    );
    ferdie.send_extrinsic(tx).await.unwrap();

    produce_blocks!(ferdie, alice, 1, bob).await.unwrap();

    let staking_summary = ferdie
        .get_domain_staking_summary(EVM_DOMAIN_ID)
        .unwrap()
        .unwrap();
    assert!(
        staking_summary
            .current_operators
            .contains_key(&bob_operator_id)
    );
    assert!(staking_summary.next_operators.contains(&bob_operator_id));

    // Produce a bundle that contains the previously sent extrinsic and record that bundle for later use
    let (slot, target_bundle) = ferdie
        .produce_slot_and_wait_for_bundle_submission_from_operator(bob_operator_id)
        .await;
    let extrinsics: Vec<Vec<u8>> = target_bundle
        .extrinsics()
        .iter()
        .map(|ext| ext.encode())
        .collect();
    let bundle_extrinsic_root = BlakeTwo256::ordered_trie_root(extrinsics, StateVersion::V1);
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bundle_to_tx(&ferdie, target_bundle)])
        ),
        alice,
        bob
    )
    .await
    .unwrap();

    // produce bundle from alice who marks the bob's previous invalid
    let alice_operator_id = 0;
    let (slot, mut opaque_bundle) = ferdie
        .produce_slot_and_wait_for_bundle_submission_from_operator(alice_operator_id)
        .await;

    let (bad_receipt_hash, bad_submit_bundle_tx) = {
        let ExecutionReceiptMutRef::V0(bad_receipt) = opaque_bundle.execution_receipt_as_mut();
        // bad receipt marks this particular bundle as `InvalidBundleWeight`
        bad_receipt.inboxed_bundles = vec![InboxedBundle::invalid(
            InvalidBundleType::InvalidBundleWeight,
            bundle_extrinsic_root,
        )];

        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );
        (
            opaque_bundle.receipt().hash::<BlakeTwo256>(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |fp| {
        if let FraudProofVariant::InvalidBundles(proof) = &fp.proof
            && InvalidBundleType::InvalidBundleWeight == proof.invalid_bundle_type()
        {
            assert!(!proof.is_good_invalid_fraud_proof());
            return true;
        }
        false
    });

    // Produce a consensus block that contains `bad_submit_bundle_tx` and the bad receipt should
    // be added to the consensus chain block tree
    produce_block_with!(
        ferdie.produce_block_with_slot_at(
            slot,
            ferdie.client.info().best_hash,
            Some(vec![bad_submit_bundle_tx])
        ),
        alice,
        bob
    )
    .await
    .unwrap();
    assert!(ferdie.does_receipt_exist(bad_receipt_hash).unwrap());

    // bob should not be in the current and next operator set
    let staking_summary = ferdie
        .get_domain_staking_summary(EVM_DOMAIN_ID)
        .unwrap()
        .unwrap();
    assert!(
        !staking_summary
            .current_operators
            .contains_key(&bob_operator_id)
    );
    assert!(!staking_summary.next_operators.contains(&bob_operator_id));

    let timed_out = tokio::time::timeout(TIMEOUT, wait_for_fraud_proof_fut)
        .await
        .inspect_err(|_| error!("fraud proof was not created before the timeout"))
        .is_err();

    // Produce a consensus block that contains the fraud proof, the fraud proof wil be verified
    // and executed, and prune the bad receipt from the block tree
    ferdie.produce_blocks(1).await.unwrap();
    assert!(!ferdie.does_receipt_exist(bad_receipt_hash).unwrap());
    // We check for timeouts last, because they are the least useful test failure message.
    assert!(!timed_out);

    // since er is pruned through fraud proof, bob should be back in next operator set.
    let staking_summary = ferdie
        .get_domain_staking_summary(EVM_DOMAIN_ID)
        .unwrap()
        .unwrap();
    assert!(
        !staking_summary
            .current_operators
            .contains_key(&bob_operator_id)
    );
    assert!(staking_summary.next_operators.contains(&bob_operator_id));

    let tx = subspace_test_service::construct_extrinsic_generic::<_>(
        &ferdie.client,
        pallet_sudo::Call::sudo {
            call: Box::new(
                pallet_domains::Call::force_staking_epoch_transition {
                    domain_id: EVM_DOMAIN_ID,
                }
                .into(),
            ),
        },
        Sr25519Keyring::Alice,
        false,
        1,
        0u128,
    );
    ferdie.send_extrinsic(tx).await.unwrap();

    ferdie.produce_blocks(1).await.unwrap();
    let staking_summary = ferdie
        .get_domain_staking_summary(EVM_DOMAIN_ID)
        .unwrap()
        .unwrap();
    assert!(
        staking_summary
            .current_operators
            .contains_key(&bob_operator_id)
    );
    assert!(staking_summary.next_operators.contains(&bob_operator_id));
}

fn bundle_to_tx(
    ferdie: &MockConsensusNode,
    opaque_bundle: OpaqueBundleOf<Runtime>,
) -> OpaqueExtrinsic {
    ferdie
        .construct_unsigned_extrinsic(pallet_domains::Call::submit_bundle { opaque_bundle })
        .into()
}

fn proof_to_tx(
    ferdie: &MockConsensusNode,
    fraud_proof: Box<FraudProofFor<Runtime>>,
) -> OpaqueExtrinsic {
    ferdie
        .construct_unsigned_extrinsic(pallet_domains::Call::submit_fraud_proof { fraud_proof })
        .into()
}

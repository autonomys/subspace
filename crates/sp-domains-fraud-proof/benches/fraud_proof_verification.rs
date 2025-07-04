use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use domain_runtime_primitives::opaque::Block as DomainBlock;
use domain_test_service::EcdsaKeyring::{Alice, Bob};
use domain_test_service::Sr25519Keyring::{self, Ferdie};
use domain_test_service::{EVM_DOMAIN_ID, EvmDomainNode};
use pallet_domains::VersionedOpaqueBundleOf;
use parity_scale_codec::{Decode, Encode};
use sc_client_api::execution_extensions::ExtensionsFactory;
use sc_client_api::{Backend, HeaderBackend};
use sc_domains::{ExtensionsFactory as DomainsExtensionFactory, FPStorageKeyProvider};
use sc_service::{BasePath, Role};
use sp_api::ProvideRuntimeApi;
use sp_core::{H256, Pair as _};
use sp_domains::bundle::{BundleValidity, InvalidBundleType};
use sp_domains::merkle_tree::MerkleTree;
use sp_domains::{ChainId, DomainsApi, ExecutionReceiptFor, Transfers};
use sp_domains_fraud_proof::fraud_proof::DomainRuntimeCodeAt;
use sp_domains_fraud_proof::fraud_proof::fraud_proof_v1::{FraudProofV1, FraudProofVariantV1};
use sp_domains_fraud_proof::storage_proof::{BasicStorageProof, DomainRuntimeCodeProof};
use sp_domains_fraud_proof::verification::*;
use sp_domains_fraud_proof::{FraudProofExtension, FraudProofHostFunctionsImpl};
use sp_runtime::OpaqueExtrinsic;
use sp_runtime::traits::{BlakeTwo256, NumberFor};
use sp_state_machine::{Ext, OverlayedChanges};
use sp_subspace_mmr::{ConsensusChainMmrLeafProof, MmrProofVerifier as _};
use std::collections::BTreeMap;
use std::sync::Arc;
use subspace_runtime_primitives::opaque::Block;
use subspace_runtime_primitives::{AI3, Balance, BlockHashFor, BlockHashingFor, HeaderFor};
use subspace_test_runtime::{MmrProofVerifier, Runtime, StorageKeyProvider, mmr};
use subspace_test_service::{MockConsensusNode, produce_block_with, produce_blocks};
use tempfile::TempDir;
use tokio::runtime::{Handle, Runtime as TokioRuntime};

type TestExternalities = sp_state_machine::TestExternalities<sp_runtime::traits::BlakeTwo256>;

type FraudProofFor<Block, DomainBlock> =
    FraudProofV1<NumberFor<Block>, BlockHashFor<Block>, HeaderFor<DomainBlock>, H256>;

fn bundle_to_tx(
    ferdie: &MockConsensusNode,
    opaque_bundle: VersionedOpaqueBundleOf<Runtime>,
) -> OpaqueExtrinsic {
    ferdie
        .construct_unsigned_extrinsic(pallet_domains::Call::submit_bundle { opaque_bundle })
        .into()
}

enum Error {
    BadMmrProof,
    UnexpectedMmrProof,
    BadStoragePoof,
}

// Helper function port from `pallet-domains`
fn verify_mmr_proof_and_extract_state_root(
    mmr_leaf_proof: ConsensusChainMmrLeafProof<NumberFor<Block>, BlockHashFor<Block>, mmr::Hash>,
    expected_block_number: NumberFor<Block>,
) -> Result<BlockHashFor<Block>, Error> {
    let leaf_data = MmrProofVerifier::verify_proof_and_extract_leaf(mmr_leaf_proof)
        .ok_or(Error::BadMmrProof)?;

    // Ensure it is a proof of the exact block that we expected
    if expected_block_number != leaf_data.block_number() {
        return Err(Error::UnexpectedMmrProof);
    }

    Ok(leaf_data.state_root())
}

async fn prepare_mmr_proof_and_runtime_code_proof(
    tokio_handle: Handle,
) -> (
    (TempDir, MockConsensusNode, EvmDomainNode),
    NumberFor<Block>,
    NumberFor<Block>,
    ConsensusChainMmrLeafProof<NumberFor<Block>, BlockHashFor<Block>, mmr::Hash>,
    DomainRuntimeCodeAt<NumberFor<Block>, BlockHashFor<Block>, mmr::Hash>,
) {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

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

    let consensus_block_number = ferdie.client.info().best_number;
    let (parent_consensus_number, parent_consensus_hash) = {
        let best_hash = ferdie.client.info().best_hash;
        let header = ferdie.client.header(best_hash).unwrap().unwrap();
        (consensus_block_number - 1, header.parent_hash)
    };

    produce_blocks!(ferdie, alice, 1).await.unwrap();

    let consensus_state_root_mmr_proof =
        sc_domains::generate_mmr_proof(&ferdie.client, consensus_block_number).unwrap();

    let domain_runtime_code_at_proof = {
        let mmr_proof =
            sc_domains::generate_mmr_proof(&ferdie.client, parent_consensus_number).unwrap();
        let domain_runtime_code_proof = DomainRuntimeCodeProof::generate(
            ferdie.client.as_ref(),
            parent_consensus_hash,
            0, // runtime_id
            &FPStorageKeyProvider::new(ferdie.client.clone()),
        )
        .unwrap();
        DomainRuntimeCodeAt {
            mmr_proof,
            domain_runtime_code_proof,
        }
    };

    (
        (directory, ferdie, alice),
        consensus_block_number,
        parent_consensus_number,
        consensus_state_root_mmr_proof,
        domain_runtime_code_at_proof,
    )
}

fn mmr_proof_and_runtime_code_proof_verification(c: &mut Criterion) {
    let rt = TokioRuntime::new().unwrap();
    let tokio_handle = rt.handle();

    let (
        (_dir, ferdie, _alice),
        consensus_block_number,
        parent_consensus_block_number,
        consensus_state_root_mmr_proof,
        domain_runtime_code_proof,
    ) = tokio_handle.block_on(prepare_mmr_proof_and_runtime_code_proof(
        tokio_handle.clone(),
    ));
    let runtime_id = 0;
    let mut overlay = OverlayedChanges::default();
    let state = ferdie
        .backend
        .state_at(ferdie.client.info().best_hash)
        .unwrap();
    let mut ext = Ext::new(&mut overlay, &state, None);

    c.bench_function("Consensus state root MMR proof verification", |b| {
        b.iter_batched(
            || consensus_state_root_mmr_proof.clone(),
            |consensus_state_root_mmr_proof| {
                assert!(
                    sp_externalities::set_and_run_with_externalities(&mut ext, || {
                        verify_mmr_proof_and_extract_state_root(
                            consensus_state_root_mmr_proof,
                            consensus_block_number,
                        )
                    })
                    .is_ok()
                );
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("Domain runtime code proof verification", |b| {
        b.iter_batched(
            || domain_runtime_code_proof.clone(),
            |domain_runtime_code_proof| {
                assert!(
                    sp_externalities::set_and_run_with_externalities(&mut ext, || {
                        let DomainRuntimeCodeAt {
                            mmr_proof,
                            domain_runtime_code_proof,
                        } = domain_runtime_code_proof;

                        let state_root = verify_mmr_proof_and_extract_state_root(
                            mmr_proof,
                            parent_consensus_block_number,
                        )?;

                        <DomainRuntimeCodeProof as BasicStorageProof<Block>>::verify::<
                            StorageKeyProvider,
                        >(domain_runtime_code_proof, runtime_id, &state_root)
                        .map_err(|_| Error::BadStoragePoof)
                    })
                    .is_ok()
                );
            },
            BatchSize::SmallInput,
        )
    });
}

async fn prepare_fraud_proof(
    tokio_handle: Handle,
    bad_receipt_maker: impl Fn(&mut ExecutionReceiptFor<HeaderFor<DomainBlock>, Block, Balance>)
    + Send
    + 'static,
) -> (
    (TempDir, MockConsensusNode, EvmDomainNode),
    TestExternalities,
    BlockHashFor<Block>,
    ExecutionReceiptFor<HeaderFor<DomainBlock>, Block, Balance>,
    ExecutionReceiptFor<HeaderFor<DomainBlock>, Block, Balance>,
    Vec<u8>,
    FraudProofFor<Block, DomainBlock>,
) {
    let directory = TempDir::new().expect("Must be able to create temporary directory");

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
    let (bad_receipt, bad_submit_bundle_tx) = {
        // Make a bad receipt
        bad_receipt_maker(opaque_bundle.execution_receipt_as_mut());

        // Re-seal bundle
        opaque_bundle.set_signature(
            Sr25519Keyring::Alice
                .pair()
                .sign(opaque_bundle.sealed_header().pre_hash().as_ref())
                .into(),
        );

        (
            opaque_bundle.receipt().clone(),
            bundle_to_tx(&ferdie, opaque_bundle),
        )
    };

    // Wait for the fraud proof that targets the bad ER
    let wait_for_fraud_proof_fut = ferdie.wait_for_fraud_proof(move |_| true);

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
    assert!(
        ferdie
            .does_receipt_exist(bad_receipt.hash::<BlakeTwo256>())
            .unwrap()
    );

    let fp: FraudProofFor<Block, DomainBlock> = {
        let fp = wait_for_fraud_proof_fut.await;
        Decode::decode(&mut fp.encode().as_slice()).unwrap()
    };
    let bad_receipt_parent = ferdie
        .client
        .runtime_api()
        .execution_receipt(
            ferdie.client.info().best_hash,
            bad_receipt.parent_domain_block_receipt_hash,
        )
        .unwrap()
        .unwrap();
    let domain_runtime_code = ferdie
        .client
        .runtime_api()
        .domain_runtime_code(ferdie.client.info().best_hash, EVM_DOMAIN_ID)
        .unwrap()
        .unwrap();

    let consensus_state_root = ferdie
        .client
        .header(bad_receipt.consensus_block_hash)
        .unwrap()
        .unwrap()
        .state_root;

    let mut ext = TestExternalities::new_empty();
    ext.extensions.register(FraudProofExtension::new(Arc::new(
        FraudProofHostFunctionsImpl::<_, _, DomainBlock, _, _>::new(
            ferdie.client.clone(),
            alice.code_executor.clone(),
            move |client, executor| {
                let extension_factory = DomainsExtensionFactory::<_, Block, DomainBlock, _>::new(
                    client, executor, 100, //confirmation_depth_k
                );
                Box::new(extension_factory) as Box<dyn ExtensionsFactory<DomainBlock>>
            },
        ),
    )));

    (
        (directory, ferdie, alice),
        ext,
        consensus_state_root,
        bad_receipt,
        bad_receipt_parent,
        domain_runtime_code,
        fp,
    )
}

fn invalid_state_transition_proof_verification(c: &mut Criterion) {
    let rt = TokioRuntime::new().unwrap();
    let tokio_handle = rt.handle();

    let (_placeholder, mut ext, _, bad_receipt, bad_receipt_parent, domain_runtime_code, fp) =
        tokio_handle.block_on(prepare_fraud_proof(tokio_handle.clone(), |receipt| {
            let mismatch_trace_index = 3;
            assert_eq!(receipt.execution_trace.len(), 5);
            receipt.execution_trace[mismatch_trace_index as usize] = Default::default();
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
        }));

    if let FraudProofVariantV1::InvalidStateTransition(invalid_state_transition_proof) = fp.proof {
        c.bench_function("Invalid state transition FP verification", |b| {
            b.iter_batched(
                || {
                    (
                        bad_receipt.clone(),
                        bad_receipt_parent.clone(),
                        domain_runtime_code.clone(),
                    )
                },
                |(bad_receipt, bad_receipt_parent, domain_runtime_code)| {
                    assert!(
                        ext.execute_with(|| verify_invalid_state_transition_fraud_proof::<
                            Block,
                            HeaderFor<DomainBlock>,
                            _,
                        >(
                            bad_receipt,
                            bad_receipt_parent,
                            &invalid_state_transition_proof,
                            domain_runtime_code,
                        ))
                        .is_ok()
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn valid_bundle_proof_verification(c: &mut Criterion) {
    let rt = TokioRuntime::new().unwrap();
    let tokio_handle = rt.handle();

    // Prepare fraud proof
    let (_placeholder, mut ext, consensus_state_root, bad_receipt, _, domain_runtime_code, fp) =
        tokio_handle.block_on(prepare_fraud_proof(tokio_handle.clone(), |receipt| {
            assert_eq!(receipt.inboxed_bundles.len(), 1);
            receipt.inboxed_bundles[0].bundle = BundleValidity::Valid(H256::random());
        }));

    if let FraudProofVariantV1::ValidBundle(valid_bundle_proof) = fp.proof {
        c.bench_function("Valid bundle FP verification", |b| {
            b.iter_batched(
                || (bad_receipt.clone(), domain_runtime_code.clone()),
                |(bad_receipt, domain_runtime_code)| {
                    assert!(
                        ext.execute_with(|| verify_valid_bundle_fraud_proof::<
                            Block,
                            HeaderFor<DomainBlock>,
                            Balance,
                            StorageKeyProvider,
                        >(
                            bad_receipt,
                            &valid_bundle_proof,
                            EVM_DOMAIN_ID,
                            consensus_state_root,
                            domain_runtime_code,
                        ))
                        .is_ok()
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn invalid_domain_extrinsics_root_fraud_proof(c: &mut Criterion) {
    let rt = TokioRuntime::new().unwrap();
    let tokio_handle = rt.handle();

    let (_placeholder, mut ext, consensus_state_root, bad_receipt, _, domain_runtime_code, fp) =
        tokio_handle.block_on(prepare_fraud_proof(tokio_handle.clone(), |receipt| {
            receipt.domain_block_extrinsic_root = Default::default();
        }));

    if let FraudProofVariantV1::InvalidExtrinsicsRoot(invalid_domain_extrinsics_root_fraud_proof) =
        fp.proof
    {
        c.bench_function("Invalid extrinsic root FP verification", |b| {
            b.iter_batched(
                || (bad_receipt.clone(), domain_runtime_code.clone()),
                |(bad_receipt, domain_runtime_code)| {
                    assert!(
                        ext.execute_with(|| verify_invalid_domain_extrinsics_root_fraud_proof::<
                            Block,
                            Balance,
                            HeaderFor<DomainBlock>,
                            BlockHashingFor<Block>,
                            StorageKeyProvider,
                        >(
                            bad_receipt,
                            &invalid_domain_extrinsics_root_fraud_proof,
                            EVM_DOMAIN_ID,
                            0, // RuntimeId
                            consensus_state_root,
                            domain_runtime_code,
                        ))
                        .is_ok()
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn invalid_domain_block_hash_fraud_proof_verification(c: &mut Criterion) {
    let rt = TokioRuntime::new().unwrap();
    let tokio_handle = rt.handle();

    let (_placeholder, mut ext, _, bad_receipt, bad_receipt_parent, _, fp) =
        tokio_handle.block_on(prepare_fraud_proof(tokio_handle.clone(), |receipt| {
            receipt.domain_block_hash = Default::default();
        }));

    if let FraudProofVariantV1::InvalidDomainBlockHash(invalid_domain_block_hash_fraud_proof) =
        fp.proof
    {
        c.bench_function("Invalid domain block hash FP verification", |b| {
            b.iter_batched(
                || {
                    (
                        bad_receipt.clone(),
                        bad_receipt_parent.clone(),
                        invalid_domain_block_hash_fraud_proof.clone(),
                    )
                },
                |(bad_receipt, bad_receipt_parent, invalid_domain_block_hash_fraud_proof)| {
                    assert!(
                        ext.execute_with(|| verify_invalid_domain_block_hash_fraud_proof::<
                            Block,
                            Balance,
                            HeaderFor<DomainBlock>,
                        >(
                            bad_receipt,
                            invalid_domain_block_hash_fraud_proof
                                .digest_storage_proof
                                .clone(),
                            bad_receipt_parent.domain_block_hash
                        ))
                        .is_ok()
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn invalid_block_fees_fraud_proof_verification(c: &mut Criterion) {
    let rt = TokioRuntime::new().unwrap();
    let tokio_handle = rt.handle();

    let (_placeholder, mut ext, _, bad_receipt, _, domain_runtime_code, fp) = tokio_handle
        .block_on(prepare_fraud_proof(tokio_handle.clone(), |receipt| {
            receipt.block_fees.consensus_storage_fee = 12345;
        }));

    if let FraudProofVariantV1::InvalidBlockFees(invalid_block_fees_fraud_proof) = fp.proof {
        c.bench_function("Invalid block fees FP verification", |b| {
            b.iter_batched(
                || (bad_receipt.clone(), domain_runtime_code.clone()),
                |(bad_receipt, domain_runtime_code)| {
                    assert!(
                        ext.execute_with(|| verify_invalid_block_fees_fraud_proof::<
                            Block,
                            NumberFor<DomainBlock>,
                            BlockHashFor<DomainBlock>,
                            Balance,
                            BlockHashingFor<DomainBlock>,
                        >(
                            bad_receipt,
                            &invalid_block_fees_fraud_proof.storage_proof.clone(),
                            domain_runtime_code,
                        ))
                        .is_ok()
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn invalid_transfers_fraud_proof_verification(c: &mut Criterion) {
    let rt = TokioRuntime::new().unwrap();
    let tokio_handle = rt.handle();

    let (_placeholder, mut ext, _, bad_receipt, _, domain_runtime_code, fp) = tokio_handle
        .block_on(prepare_fraud_proof(tokio_handle.clone(), |receipt| {
            receipt.transfers = Transfers {
                transfers_in: BTreeMap::from([(ChainId::Consensus, 10 * AI3)]),
                transfers_out: BTreeMap::from([(ChainId::Consensus, 10 * AI3)]),
                rejected_transfers_claimed: Default::default(),
                transfers_rejected: Default::default(),
            }
        }));

    if let FraudProofVariantV1::InvalidTransfers(invalid_transfers_fraud_proof) = fp.proof {
        c.bench_function("Invalid transfers FP verification", |b| {
            b.iter_batched(
                || (bad_receipt.clone(), domain_runtime_code.clone()),
                |(bad_receipt, domain_runtime_code)| {
                    assert!(
                        ext.execute_with(|| verify_invalid_transfers_fraud_proof::<
                            Block,
                            NumberFor<DomainBlock>,
                            BlockHashFor<DomainBlock>,
                            Balance,
                            BlockHashingFor<DomainBlock>,
                        >(
                            bad_receipt,
                            &invalid_transfers_fraud_proof.storage_proof.clone(),
                            domain_runtime_code,
                        ))
                        .is_ok()
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn invalid_bundle_undecodable_tx_fraud_proof_verification(c: &mut Criterion) {
    let rt = TokioRuntime::new().unwrap();
    let tokio_handle = rt.handle();

    let (
        _placeholder,
        mut ext,
        consensus_state_root,
        bad_receipt,
        bad_receipt_parent,
        domain_runtime_code,
        fp,
    ) = tokio_handle.block_on(prepare_fraud_proof(tokio_handle.clone(), |receipt| {
        receipt.inboxed_bundles[0].bundle =
            BundleValidity::Invalid(InvalidBundleType::UndecodableTx(0));
    }));

    if let FraudProofVariantV1::InvalidBundles(invalid_bundle_fraud_proof) = fp.proof {
        c.bench_function("Invalid bundle UndecodableTx FP verification", |b| {
            assert!(matches!(
                invalid_bundle_fraud_proof.invalid_bundle_type(),
                InvalidBundleType::UndecodableTx(0)
            ));
            b.iter_batched(
                || {
                    (
                        bad_receipt.clone(),
                        bad_receipt_parent.clone(),
                        domain_runtime_code.clone(),
                    )
                },
                |(bad_receipt, bad_receipt_parent, domain_runtime_code)| {
                    assert!(
                        ext.execute_with(|| verify_invalid_bundles_fraud_proof::<
                            Block,
                            HeaderFor<DomainBlock>,
                            mmr::Hash,
                            Balance,
                            StorageKeyProvider,
                            MmrProofVerifier,
                        >(
                            bad_receipt,
                            bad_receipt_parent,
                            &invalid_bundle_fraud_proof,
                            EVM_DOMAIN_ID,
                            consensus_state_root,
                            domain_runtime_code,
                        ))
                        .is_ok()
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn invalid_bundle_out_of_range_tx_fraud_proof_verification(c: &mut Criterion) {
    let rt = TokioRuntime::new().unwrap();
    let tokio_handle = rt.handle();

    let (
        _placeholder,
        mut ext,
        consensus_state_root,
        bad_receipt,
        bad_receipt_parent,
        domain_runtime_code,
        fp,
    ) = tokio_handle.block_on(prepare_fraud_proof(tokio_handle.clone(), |receipt| {
        receipt.inboxed_bundles[0].bundle =
            BundleValidity::Invalid(InvalidBundleType::OutOfRangeTx(0));
    }));

    if let FraudProofVariantV1::InvalidBundles(invalid_bundle_fraud_proof) = fp.proof {
        assert!(matches!(
            invalid_bundle_fraud_proof.invalid_bundle_type(),
            InvalidBundleType::OutOfRangeTx(0)
        ));
        c.bench_function("Invalid bundle OutOfRangeTx FP verification", |b| {
            b.iter_batched(
                || {
                    (
                        bad_receipt.clone(),
                        bad_receipt_parent.clone(),
                        domain_runtime_code.clone(),
                    )
                },
                |(bad_receipt, bad_receipt_parent, domain_runtime_code)| {
                    assert!(
                        ext.execute_with(|| verify_invalid_bundles_fraud_proof::<
                            Block,
                            HeaderFor<DomainBlock>,
                            mmr::Hash,
                            Balance,
                            StorageKeyProvider,
                            MmrProofVerifier,
                        >(
                            bad_receipt,
                            bad_receipt_parent,
                            &invalid_bundle_fraud_proof,
                            EVM_DOMAIN_ID,
                            consensus_state_root,
                            domain_runtime_code,
                        ))
                        .is_ok()
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn invalid_bundle_illegal_tx_fraud_proof_verification(c: &mut Criterion) {
    let rt = TokioRuntime::new().unwrap();
    let tokio_handle = rt.handle();

    let (
        _placeholder,
        mut ext,
        consensus_state_root,
        bad_receipt,
        bad_receipt_parent,
        domain_runtime_code,
        fp,
    ) = tokio_handle.block_on(prepare_fraud_proof(tokio_handle.clone(), |receipt| {
        receipt.inboxed_bundles[0].bundle =
            BundleValidity::Invalid(InvalidBundleType::IllegalTx(0));
    }));

    if let FraudProofVariantV1::InvalidBundles(invalid_bundle_fraud_proof) = fp.proof {
        assert!(matches!(
            invalid_bundle_fraud_proof.invalid_bundle_type(),
            InvalidBundleType::IllegalTx(0)
        ));
        c.bench_function("Invalid bundle IllegalTx FP verification", |b| {
            b.iter_batched(
                || {
                    (
                        bad_receipt.clone(),
                        bad_receipt_parent.clone(),
                        domain_runtime_code.clone(),
                    )
                },
                |(bad_receipt, bad_receipt_parent, domain_runtime_code)| {
                    assert!(
                        ext.execute_with(|| verify_invalid_bundles_fraud_proof::<
                            Block,
                            HeaderFor<DomainBlock>,
                            mmr::Hash,
                            Balance,
                            StorageKeyProvider,
                            MmrProofVerifier,
                        >(
                            bad_receipt,
                            bad_receipt_parent,
                            &invalid_bundle_fraud_proof,
                            EVM_DOMAIN_ID,
                            consensus_state_root,
                            domain_runtime_code,
                        ))
                        .is_ok()
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn invalid_bundle_invalid_xdm_fraud_proof_verification(c: &mut Criterion) {
    let rt = TokioRuntime::new().unwrap();
    let tokio_handle = rt.handle();

    let (
        _placeholder,
        mut ext,
        consensus_state_root,
        bad_receipt,
        bad_receipt_parent,
        domain_runtime_code,
        fp,
    ) = tokio_handle.block_on(prepare_fraud_proof(tokio_handle.clone(), |receipt| {
        receipt.inboxed_bundles[0].bundle =
            BundleValidity::Invalid(InvalidBundleType::InvalidXDM(0));
    }));

    if let FraudProofVariantV1::InvalidBundles(invalid_bundle_fraud_proof) = fp.proof {
        assert!(matches!(
            invalid_bundle_fraud_proof.invalid_bundle_type(),
            InvalidBundleType::InvalidXDM(0)
        ));
        c.bench_function("Invalid bundle InvalidXDM FP verification", |b| {
            b.iter_batched(
                || {
                    (
                        bad_receipt.clone(),
                        bad_receipt_parent.clone(),
                        domain_runtime_code.clone(),
                    )
                },
                |(bad_receipt, bad_receipt_parent, domain_runtime_code)| {
                    assert!(
                        ext.execute_with(|| verify_invalid_bundles_fraud_proof::<
                            Block,
                            HeaderFor<DomainBlock>,
                            mmr::Hash,
                            Balance,
                            StorageKeyProvider,
                            MmrProofVerifier,
                        >(
                            bad_receipt,
                            bad_receipt_parent,
                            &invalid_bundle_fraud_proof,
                            EVM_DOMAIN_ID,
                            consensus_state_root,
                            domain_runtime_code,
                        ))
                        .is_ok()
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn invalid_bundle_inherent_extrinsic_fraud_proof_verification(c: &mut Criterion) {
    let rt = TokioRuntime::new().unwrap();
    let tokio_handle = rt.handle();

    let (
        _placeholder,
        mut ext,
        consensus_state_root,
        bad_receipt,
        bad_receipt_parent,
        domain_runtime_code,
        fp,
    ) = tokio_handle.block_on(prepare_fraud_proof(tokio_handle.clone(), |receipt| {
        receipt.inboxed_bundles[0].bundle =
            BundleValidity::Invalid(InvalidBundleType::InherentExtrinsic(0));
    }));

    if let FraudProofVariantV1::InvalidBundles(invalid_bundle_fraud_proof) = fp.proof {
        assert!(matches!(
            invalid_bundle_fraud_proof.invalid_bundle_type(),
            InvalidBundleType::InherentExtrinsic(0)
        ));
        c.bench_function("Invalid bundle InherentExtrinsic FP verification", |b| {
            b.iter_batched(
                || {
                    (
                        bad_receipt.clone(),
                        bad_receipt_parent.clone(),
                        domain_runtime_code.clone(),
                    )
                },
                |(bad_receipt, bad_receipt_parent, domain_runtime_code)| {
                    assert!(
                        ext.execute_with(|| verify_invalid_bundles_fraud_proof::<
                            Block,
                            HeaderFor<DomainBlock>,
                            mmr::Hash,
                            Balance,
                            StorageKeyProvider,
                            MmrProofVerifier,
                        >(
                            bad_receipt,
                            bad_receipt_parent,
                            &invalid_bundle_fraud_proof,
                            EVM_DOMAIN_ID,
                            consensus_state_root,
                            domain_runtime_code,
                        ))
                        .is_ok()
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn invalid_bundle_weight_fraud_proof_verification(c: &mut Criterion) {
    let rt = TokioRuntime::new().unwrap();
    let tokio_handle = rt.handle();

    let (
        _placeholder,
        mut ext,
        consensus_state_root,
        bad_receipt,
        bad_receipt_parent,
        domain_runtime_code,
        fp,
    ) = tokio_handle.block_on(prepare_fraud_proof(tokio_handle.clone(), |receipt| {
        receipt.inboxed_bundles[0].bundle =
            BundleValidity::Invalid(InvalidBundleType::InvalidBundleWeight);
    }));

    if let FraudProofVariantV1::InvalidBundles(invalid_bundle_fraud_proof) = fp.proof {
        assert!(matches!(
            invalid_bundle_fraud_proof.invalid_bundle_type(),
            InvalidBundleType::InvalidBundleWeight
        ));
        c.bench_function("Invalid bundle InvalidBundleWeight FP verification", |b| {
            b.iter_batched(
                || {
                    (
                        bad_receipt.clone(),
                        bad_receipt_parent.clone(),
                        domain_runtime_code.clone(),
                    )
                },
                |(bad_receipt, bad_receipt_parent, domain_runtime_code)| {
                    assert!(
                        ext.execute_with(|| verify_invalid_bundles_fraud_proof::<
                            Block,
                            HeaderFor<DomainBlock>,
                            mmr::Hash,
                            Balance,
                            StorageKeyProvider,
                            MmrProofVerifier,
                        >(
                            bad_receipt,
                            bad_receipt_parent,
                            &invalid_bundle_fraud_proof,
                            EVM_DOMAIN_ID,
                            consensus_state_root,
                            domain_runtime_code,
                        ))
                        .is_ok()
                    );
                },
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(
    benches,
    mmr_proof_and_runtime_code_proof_verification,
    invalid_state_transition_proof_verification,
    valid_bundle_proof_verification,
    invalid_domain_extrinsics_root_fraud_proof,
    invalid_domain_block_hash_fraud_proof_verification,
    invalid_block_fees_fraud_proof_verification,
    invalid_transfers_fraud_proof_verification,
    invalid_bundle_undecodable_tx_fraud_proof_verification,
    // NOTE: `invalid_bundle_out_of_range_tx_fraud_proof_verification` is unstable because the test
    // consensus runtime use `U256::MAX` as tx range to ensure every tx can be included by bundle while
    // the fraud proof verification use the production tx range `U256::MAX / 3`.
    invalid_bundle_out_of_range_tx_fraud_proof_verification,
    invalid_bundle_illegal_tx_fraud_proof_verification,
    invalid_bundle_invalid_xdm_fraud_proof_verification,
    invalid_bundle_inherent_extrinsic_fraud_proof_verification,
    invalid_bundle_weight_fraud_proof_verification,
);
criterion_main!(benches);

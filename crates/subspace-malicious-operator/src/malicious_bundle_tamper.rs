use domain_client_operator::{ExecutionReceiptFor, OpaqueBundleFor};
use parity_scale_codec::{Decode, Encode};
use sc_client_api::HeaderBackend;
use sp_api::ProvideRuntimeApi;
use sp_domain_digests::AsPredigest;
use sp_domains::core_api::DomainCoreApi;
use sp_domains::merkle_tree::MerkleTree;
use sp_domains::{
    BlockFees, BundleValidity, ChainId, HeaderHashingFor, InvalidBundleType, OperatorPublicKey,
    OperatorSignature,
};
use sp_keystore::KeystorePtr;
use sp_runtime::traits::{Block as BlockT, Hash as HashT, Header as HeaderT, NumberFor, One, Zero};
use sp_runtime::{DigestItem, OpaqueExtrinsic, RuntimeAppPublic};
use sp_weights::Weight;
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::sync::Arc;

const MAX_BAD_RECEIPT_CACHE: u32 = 128;

// TODO: remove dead_code once the `InboxedBundle` variant is used
// currently blocked due to https://github.com/autonomys/subspace/issues/2287
#[allow(dead_code)]
#[derive(Debug)]
enum BadReceiptType {
    InboxedBundle,
    ExtrinsicsRoot,
    ExecutionTrace,
    BlockFees,
    Transfers,
    DomainBlockHash,
    ParentReceipt,
}

struct Random;

impl Random {
    fn seed() -> u32 {
        rand::random::<u32>()
    }

    // Return `true` based on the given probability
    fn probability(p: f64) -> bool {
        assert!(p <= 1f64);
        Self::seed() < ((u32::MAX as f64) * p) as u32
    }
}

#[allow(clippy::type_complexity)]
pub struct MaliciousBundleTamper<Block, CBlock, Client>
where
    Block: BlockT,
    CBlock: BlockT,
{
    domain_client: Arc<Client>,
    keystore: KeystorePtr,
    // A cache for recently produced bad receipts
    bad_receipts_cache:
        BTreeMap<NumberFor<Block>, HashMap<CBlock::Hash, ExecutionReceiptFor<Block, CBlock>>>,
}

impl<Block, CBlock, Client> MaliciousBundleTamper<Block, CBlock, Client>
where
    Block: BlockT,
    CBlock: BlockT,
    CBlock::Hash: Decode,
    Client: HeaderBackend<Block> + ProvideRuntimeApi<Block> + 'static,
    Client::Api: DomainCoreApi<Block>,
{
    pub fn new(domain_client: Arc<Client>, keystore: KeystorePtr) -> Self {
        MaliciousBundleTamper {
            domain_client,
            keystore,
            bad_receipts_cache: BTreeMap::new(),
        }
    }

    pub fn maybe_tamper_bundle(
        &mut self,
        opaque_bundle: &mut OpaqueBundleFor<Block, CBlock>,
        operator_signing_key: &OperatorPublicKey,
    ) -> Result<(), Box<dyn Error>> {
        if Random::probability(0.2) {
            self.make_receipt_fraudulent(&mut opaque_bundle.sealed_header.header.receipt)?;
            self.reseal_bundle(opaque_bundle, operator_signing_key)?;
        }
        if Random::probability(0.1) {
            self.make_bundle_invalid(opaque_bundle)?;
            self.reseal_bundle(opaque_bundle, operator_signing_key)?;
        }
        Ok(())
    }

    fn make_receipt_fraudulent(
        &mut self,
        receipt: &mut ExecutionReceiptFor<Block, CBlock>,
    ) -> Result<(), Box<dyn Error>> {
        // We can't make the genesis receipt into a bad ER
        if receipt.domain_block_number.is_zero() {
            return Ok(());
        }
        // If a bad receipt is already made for the same domain block, reuse it
        if let Some(bad_receipts_at) = self.bad_receipts_cache.get(&receipt.domain_block_number)
            && let Some(previous_bad_receipt) = bad_receipts_at.get(&receipt.consensus_block_hash)
        {
            *receipt = previous_bad_receipt.clone();
            return Ok(());
        }

        let random_seed = Random::seed();
        let bad_receipt_type = match random_seed % 7 {
            0 => BadReceiptType::InboxedBundle,
            1 => BadReceiptType::ExtrinsicsRoot,
            2 => BadReceiptType::ExecutionTrace,
            3 => BadReceiptType::BlockFees,
            4 => BadReceiptType::Transfers,
            5 => BadReceiptType::DomainBlockHash,
            6 => BadReceiptType::ParentReceipt,
            _ => return Ok(()),
        };

        tracing::info!(
            ?bad_receipt_type,
            "Generate bad ER of domain block {}#{}",
            receipt.domain_block_number,
            receipt.domain_block_hash,
        );

        match bad_receipt_type {
            BadReceiptType::BlockFees => {
                receipt.block_fees = BlockFees::new(
                    random_seed.into(),
                    random_seed.into(),
                    random_seed.into(),
                    BTreeMap::default(),
                );
            }
            BadReceiptType::Transfers => {
                receipt.transfers.transfers_in =
                    BTreeMap::from_iter([(ChainId::consensus_chain_id(), random_seed.into())]);
                receipt.transfers.transfers_out =
                    BTreeMap::from_iter([(0.into(), random_seed.into())]);
                receipt.transfers.rejected_transfers_claimed =
                    BTreeMap::from_iter([(random_seed.into(), random_seed.into())]);
                receipt.transfers.transfers_rejected =
                    BTreeMap::from_iter([(1.into(), random_seed.into())]);
            }
            BadReceiptType::ExecutionTrace => {
                let mismatch_index = random_seed as usize % receipt.execution_trace.len();
                match random_seed as usize % 3 {
                    0 => receipt.execution_trace.push(Default::default()),
                    1 => {
                        receipt.execution_trace = receipt
                            .execution_trace
                            .clone()
                            .drain(..)
                            .take(mismatch_index + 1)
                            .collect();
                    }
                    2 => receipt.execution_trace[mismatch_index] = Default::default(),
                    _ => unreachable!(),
                };
                receipt.final_state_root = *receipt.execution_trace.last().unwrap();
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
            }
            BadReceiptType::ExtrinsicsRoot => {
                receipt.domain_block_extrinsic_root = Default::default();
            }
            BadReceiptType::DomainBlockHash => {
                receipt.domain_block_hash = Default::default();
            }
            BadReceiptType::ParentReceipt => {
                let parent_domain_number = receipt.domain_block_number - One::one();
                let parent_block_consensus_hash: CBlock::Hash = {
                    let parent_domain_hash = *self
                        .domain_client
                        .header(receipt.domain_block_hash)?
                        .ok_or_else(|| {
                            sp_blockchain::Error::Backend(format!(
                                "Domain block header for #{:?} not found",
                                receipt.domain_block_hash
                            ))
                        })?
                        .parent_hash();
                    let parent_domain_header = self
                        .domain_client
                        .header(parent_domain_hash)?
                        .ok_or_else(|| {
                            sp_blockchain::Error::Backend(format!(
                                "Domain block header for #{parent_domain_hash:?} not found",
                            ))
                        })?;
                    parent_domain_header
                        .digest()
                        .convert_first(DigestItem::as_consensus_block_info)
                        .expect("Domain block header must have the consensus block info digest")
                };
                let maybe_parent_bad_receipt = self
                    .bad_receipts_cache
                    .get(&parent_domain_number)
                    .and_then(|bad_receipts_at| bad_receipts_at.get(&parent_block_consensus_hash));
                match maybe_parent_bad_receipt {
                    Some(parent_bad_receipt) => {
                        receipt.parent_domain_block_receipt_hash =
                            parent_bad_receipt.hash::<HeaderHashingFor<Block::Header>>();
                    }
                    // The parent receipt is not a bad receipt so even we modify this field to a random
                    // value, the receipt will be rejected by the consensus node directly thus just skip
                    None => return Ok(()),
                }
            }
            // NOTE: Not need to modify the bundle `extrinsics_root` or the lenght of `inboxed_bundles`
            // since the consensus runtime will perform the these checks and reject the bundle directly
            BadReceiptType::InboxedBundle => {
                let mismatch_index = random_seed as usize % receipt.inboxed_bundles.len();
                receipt.inboxed_bundles[mismatch_index].bundle = if random_seed % 2 == 0 {
                    BundleValidity::Valid(Default::default())
                } else {
                    let extrincis_index = random_seed % 2;
                    let invalid_bundle_type = match random_seed as usize % 5 {
                        0 => InvalidBundleType::UndecodableTx(extrincis_index),
                        1 => InvalidBundleType::OutOfRangeTx(extrincis_index),
                        2 => InvalidBundleType::IllegalTx(extrincis_index),
                        3 => InvalidBundleType::InherentExtrinsic(extrincis_index),
                        4 => InvalidBundleType::InvalidBundleWeight,
                        _ => unreachable!(),
                    };
                    BundleValidity::Invalid(invalid_bundle_type)
                }
            }
        }

        // Add the bad receipt to cache and remove the oldest receipt from cache
        self.bad_receipts_cache
            .entry(receipt.domain_block_number)
            .or_default()
            .insert(receipt.consensus_block_hash, receipt.clone());
        if self.bad_receipts_cache.len() as u32 > MAX_BAD_RECEIPT_CACHE {
            self.bad_receipts_cache.pop_first();
        }

        Ok(())
    }

    #[allow(clippy::modulo_one)]
    fn make_bundle_invalid(
        &self,
        opaque_bundle: &mut OpaqueBundleFor<Block, CBlock>,
    ) -> Result<(), Box<dyn Error>> {
        let random_seed = Random::seed();
        let invalid_bundle_type = match random_seed % 4 {
            0 => InvalidBundleType::UndecodableTx(0),
            1 => InvalidBundleType::IllegalTx(0),
            2 => InvalidBundleType::InherentExtrinsic(0),
            3 => InvalidBundleType::InvalidBundleWeight,
            // TODO: `OutOfRangeTx` invalid bundle is tricky to simulate because the
            // tx range is dynamically change based on the `proof_of_election.vrf_hash`
            // 1 => InvalidBundleType::OutOfRangeTx(0),
            _ => unreachable!(),
        };
        tracing::info!(
            ?invalid_bundle_type,
            "Generate invalid bundle, receipt domain block {}#{}",
            opaque_bundle.receipt().domain_block_number,
            opaque_bundle.receipt().domain_block_hash,
        );

        let invalid_tx = match invalid_bundle_type {
            InvalidBundleType::UndecodableTx(_) => OpaqueExtrinsic::default(),
            // The duplicated extrinsic will be illegal due to `Nonce` if it is a signed extrinsic
            InvalidBundleType::IllegalTx(_) if !opaque_bundle.extrinsics.is_empty() => {
                opaque_bundle.extrinsics[0].clone()
            }
            InvalidBundleType::InherentExtrinsic(_) => {
                let inherent_tx = self
                    .domain_client
                    .runtime_api()
                    .construct_timestamp_extrinsic(
                        self.domain_client.info().best_hash,
                        Default::default(),
                    )?;
                OpaqueExtrinsic::from_bytes(&inherent_tx.encode())
                    .expect("We have just encoded a valid extrinsic; qed")
            }
            InvalidBundleType::InvalidBundleWeight => {
                opaque_bundle.sealed_header.header.estimated_bundle_weight =
                    Weight::from_all(123456);
                return Ok(());
            }
            _ => return Ok(()),
        };

        opaque_bundle.extrinsics.push(invalid_tx);

        Ok(())
    }

    fn reseal_bundle(
        &self,
        opaque_bundle: &mut OpaqueBundleFor<Block, CBlock>,
        operator_signing_key: &OperatorPublicKey,
    ) -> Result<(), Box<dyn Error>> {
        opaque_bundle.sealed_header.header.bundle_extrinsics_root =
            HeaderHashingFor::<Block::Header>::ordered_trie_root(
                opaque_bundle
                    .extrinsics
                    .iter()
                    .map(|xt| xt.encode())
                    .collect(),
                sp_core::storage::StateVersion::V1,
            );

        let pre_hash = opaque_bundle.sealed_header.pre_hash();
        opaque_bundle.sealed_header.signature = {
            let s = self
                .keystore
                .sr25519_sign(
                    OperatorPublicKey::ID,
                    operator_signing_key.as_ref(),
                    pre_hash.as_ref(),
                )?
                .expect("The malicious operator's key pair must exist");
            OperatorSignature::decode(&mut s.as_ref())
                .expect("Deconde as OperatorSignature must succeed")
        };
        Ok(())
    }
}

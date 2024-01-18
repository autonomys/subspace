//! Module to check bundle equivocation and produce the Equivocation fraud proof.
//! This is mostly derived from the `sc_consensus_slots::aux_schema` with changes adapted
//! for Bundle headers instead of block headers

use crate::fraud_proof::{BundleEquivocationProof, FraudProof};
use codec::{Decode, Encode};
use sc_client_api::backend::AuxStore;
use sp_blockchain::{Error as ClientError, Result as ClientResult};
use sp_consensus_slots::Slot;
use sp_domains::SealedBundleHeader;
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};
use std::sync::Arc;
use subspace_runtime_primitives::Balance;

const SLOT_BUNDLE_HEADER_MAP_KEY: &[u8] = b"slot_bundle_header_map";
const SLOT_BUNDLE_HEADER_START: &[u8] = b"slot_bundle_header_start";

// TODO: revisit these values when there more than 1000 domains.
/// We keep at least this number of slots in database.
const MAX_SLOT_CAPACITY: u64 = 1000;
/// We prune slots when they reach this number.
const PRUNING_BOUND: u64 = 2 * MAX_SLOT_CAPACITY;

fn load_decode<CClient, T>(client: &Arc<CClient>, key: &[u8]) -> ClientResult<Option<T>>
where
    CClient: AuxStore,
    T: Decode,
{
    match client.get_aux(key)? {
        None => Ok(None),
        Some(t) => T::decode(&mut &t[..])
            .map_err(|e| {
                ClientError::Backend(format!("Slots DB is corrupted. Decode error: {}", e))
            })
            .map(Some),
    }
}

pub type CheckEquivocationResult<CNumber, CHash, DomainHeader> =
    ClientResult<Option<FraudProof<CNumber, CHash, DomainHeader>>>;

/// Checks if the header is an equivocation and returns the proof in that case.
///
/// Note: it detects equivocations only when slot_now - slot <= MAX_SLOT_CAPACITY.
pub fn check_equivocation<CClient, CBlock, DomainHeader>(
    backend: &Arc<CClient>,
    slot_now: Slot,
    bundle_header: SealedBundleHeader<NumberFor<CBlock>, CBlock::Hash, DomainHeader, Balance>,
) -> CheckEquivocationResult<NumberFor<CBlock>, CBlock::Hash, DomainHeader>
where
    CClient: AuxStore,
    CBlock: BlockT,
    DomainHeader: HeaderT,
{
    let slot: Slot = bundle_header.header.proof_of_election.slot_number.into();

    // We don't check equivocations for old headers out of our capacity.
    if slot_now.saturating_sub(*slot) > MAX_SLOT_CAPACITY {
        return Ok(None);
    }

    // Key for this slot.
    let mut curr_slot_key = SLOT_BUNDLE_HEADER_MAP_KEY.to_vec();
    slot.using_encoded(|s| curr_slot_key.extend(s));

    // Get headers of this slot.
    let mut headers_with_sig = load_decode::<
        CClient,
        Vec<SealedBundleHeader<NumberFor<CBlock>, CBlock::Hash, DomainHeader, Balance>>,
    >(backend, &curr_slot_key[..])?
    .unwrap_or_else(Vec::new);

    // Get first slot saved.
    let slot_header_start = SLOT_BUNDLE_HEADER_START.to_vec();
    let first_saved_slot = load_decode::<_, Slot>(backend, &slot_header_start[..])?.unwrap_or(slot);

    if slot_now < first_saved_slot {
        // The code below assumes that slots will be visited sequentially.
        return Ok(None);
    }

    for previous_bundle_header in headers_with_sig.iter() {
        let operator_set_1 = (
            previous_bundle_header.header.proof_of_election.operator_id,
            previous_bundle_header.header.proof_of_election.domain_id,
        );
        let operator_set_2 = (
            bundle_header.header.proof_of_election.operator_id,
            bundle_header.header.proof_of_election.domain_id,
        );

        // A proof of equivocation consists of two headers:
        // 1) signed by the same operator for same domain
        if operator_set_1 == operator_set_2 {
            // 2) with different hash
            return if bundle_header.hash() != previous_bundle_header.hash() {
                log::warn!(
                    "Bundle equivocation occurred: Operator{}; Slot{}; DomainId{}; First Bundle{}; Second Bundle{}",
                    operator_set_1.0,
                    slot,
                    operator_set_1.1,
                    previous_bundle_header.hash(),
                    bundle_header.hash(),
                );
                Ok(Some(FraudProof::BundleEquivocation(
                    BundleEquivocationProof {
                        domain_id: bundle_header.header.proof_of_election.domain_id,
                        slot,
                        first_header: previous_bundle_header.clone(),
                        second_header: bundle_header,
                    },
                )))
            } else {
                // We don't need to continue in case of duplicated header,
                // since it's already saved and a possible equivocation
                // would have been detected before.
                Ok(None)
            };
        }
    }

    let mut keys_to_delete = vec![];
    let mut new_first_saved_slot = first_saved_slot;

    if *slot_now - *first_saved_slot >= PRUNING_BOUND {
        let prefix = SLOT_BUNDLE_HEADER_MAP_KEY.to_vec();
        new_first_saved_slot = slot_now.saturating_sub(MAX_SLOT_CAPACITY);

        for s in u64::from(first_saved_slot)..new_first_saved_slot.into() {
            let mut p = prefix.clone();
            s.using_encoded(|s| p.extend(s));
            keys_to_delete.push(p);
        }
    }

    headers_with_sig.push(bundle_header);

    backend.insert_aux(
        &[
            (&curr_slot_key[..], headers_with_sig.encode().as_slice()),
            (
                &slot_header_start[..],
                new_first_saved_slot.encode().as_slice(),
            ),
        ],
        &keys_to_delete
            .iter()
            .map(|k| &k[..])
            .collect::<Vec<&[u8]>>()[..],
    )?;

    Ok(None)
}

#[cfg(test)]
mod test {
    use super::{check_equivocation, MAX_SLOT_CAPACITY, PRUNING_BOUND};
    use domain_runtime_primitives::opaque::Header as DomainHeader;
    use sp_core::crypto::UncheckedFrom;
    use sp_domains::{
        BundleHeader, DomainId, ExecutionReceipt, OperatorId, OperatorSignature, ProofOfElection,
        SealedBundleHeader,
    };
    use std::sync::Arc;
    use subspace_runtime_primitives::opaque::Block;
    use subspace_runtime_primitives::{Balance, BlockNumber, Hash};

    fn create_header(
        number: BlockNumber,
        slot_number: u64,
        domain_id: DomainId,
        operator_id: OperatorId,
    ) -> SealedBundleHeader<BlockNumber, Hash, DomainHeader, Balance> {
        let mut poe = ProofOfElection::dummy(domain_id, operator_id);
        poe.slot_number = slot_number;
        SealedBundleHeader {
            header: BundleHeader {
                proof_of_election: poe,
                receipt: ExecutionReceipt {
                    domain_block_number: number,
                    domain_block_hash: Default::default(),
                    domain_block_extrinsic_root: Default::default(),
                    parent_domain_block_receipt_hash: Default::default(),
                    consensus_block_number: number,
                    consensus_block_hash: Default::default(),
                    inboxed_bundles: vec![],
                    final_state_root: Default::default(),
                    execution_trace: vec![],
                    execution_trace_root: Default::default(),
                    block_fees: Default::default(),
                },
                bundle_size: 0,
                estimated_bundle_weight: Default::default(),
                bundle_extrinsics_root: Default::default(),
            },
            signature: OperatorSignature::unchecked_from([0u8; 64]),
        }
    }

    #[test]
    fn test_check_equivocation() {
        let client = Arc::new(substrate_test_runtime_client::new());
        let domain_id = DomainId::new(0);
        let operator_id = 1;

        let header1 = create_header(1, 2, domain_id, operator_id); // @ slot 2
        let header2 = create_header(2, 2, domain_id, operator_id); // @ slot 2
        let header3 = create_header(2, 4, domain_id, operator_id); // @ slot 4
        let header4 = create_header(3, MAX_SLOT_CAPACITY + 4, domain_id, operator_id); // @ slot MAX_SLOT_CAPACITY + 4
        let header5 = create_header(4, MAX_SLOT_CAPACITY + 4, domain_id, operator_id); // @ slot MAX_SLOT_CAPACITY + 4
        let header6 = create_header(3, 4, domain_id, operator_id); // @ slot 4

        // It's ok to sign same headers.
        assert!(
            check_equivocation::<_, Block, _>(&client, 2.into(), header1.clone())
                .unwrap()
                .is_none(),
        );

        assert!(
            check_equivocation::<_, Block, _>(&client, 3.into(), header1.clone())
                .unwrap()
                .is_none(),
        );

        // But not two different headers at the same slot.
        assert!(
            check_equivocation::<_, Block, _>(&client, 4.into(), header2)
                .unwrap()
                .is_some(),
        );

        // Different slot is ok.
        assert!(
            check_equivocation::<_, Block, _>(&client, 5.into(), header3)
                .unwrap()
                .is_none(),
        );

        // Here we trigger pruning and save header 4.
        assert!(
            check_equivocation::<_, Block, _>(&client, (PRUNING_BOUND + 2).into(), header4,)
                .unwrap()
                .is_none(),
        );

        // This fails because header 5 is an equivocation of header 4.
        assert!(
            check_equivocation::<_, Block, _>(&client, (PRUNING_BOUND + 3).into(), header5,)
                .unwrap()
                .is_some(),
        );

        // This is ok because we pruned the corresponding header. Shows that we are pruning.
        assert!(
            check_equivocation::<_, Block, _>(&client, (PRUNING_BOUND + 4).into(), header6,)
                .unwrap()
                .is_none(),
        );
    }
}

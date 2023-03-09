use crate::config;
use sp_std::vec;
use sp_std::vec::Vec;
use ssz_rs::prelude::{List, Vector};
use ssz_rs::{Bitlist, Bitvector, Deserialize, Sized, U256};
use ssz_rs_derive::SimpleSerialize;

/// This file contains copy of original generic data structures created in primitives
/// modified to work with current ssz library.
/// For information about individual structure, please see primitives

#[derive(Default, Debug, SimpleSerialize, Clone)]
pub struct SSZVoluntaryExit {
    pub epoch: u64,
    pub validator_index: u64,
}

#[derive(Default, Debug, SimpleSerialize, Clone)]
pub struct SSZDepositData {
    pub pubkey: Vector<u8, { config::PublicKeySize::get() as usize }>,
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
    pub signature: Vector<u8, { config::SignatureSize::get() as usize }>,
}

#[derive(Default, Debug, SimpleSerialize, Clone)]
pub struct SSZDeposit {
    pub proof: Vector<[u8; 32], { config::DepositContractTreeDepth::get() as usize + 1 }>,
    pub data: SSZDepositData,
}

#[derive(Default, SimpleSerialize, Clone, Debug)]
pub struct SSZCheckpoint {
    pub epoch: u64,
    pub root: [u8; 32],
}

#[derive(Default, SimpleSerialize, Clone, Debug)]
pub struct SSZAttestationData {
    pub slot: u64,
    pub index: u64,
    pub beacon_block_root: [u8; 32],
    pub source: SSZCheckpoint,
    pub target: SSZCheckpoint,
}

#[derive(Default, Debug, SimpleSerialize, Clone)]
pub struct SignedBeaconBlockHeader {
    pub message: SSZBeaconBlockHeader,
    pub signature: Vector<u8, { config::SignatureSize::get() as usize }>,
}

#[derive(Default, Debug, SimpleSerialize, Clone)]
pub struct SSZIndexedAttestation {
    pub attesting_indices: List<u64, { config::MaxValidatorsPerCommittee::get() as usize }>,
    pub data: SSZAttestationData,
    pub signature: Vector<u8, { config::SignatureSize::get() as usize }>,
}

#[derive(Default, Debug, SimpleSerialize, Clone)]
pub struct SSZProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Default, Debug, SimpleSerialize, Clone)]
pub struct SSZAttesterSlashing {
    pub attestation_1: SSZIndexedAttestation,
    pub attestation_2: SSZIndexedAttestation,
}

#[derive(Default, Debug, SimpleSerialize, Clone)]
pub struct SSZEth1Data {
    pub deposit_root: [u8; 32],
    pub deposit_count: u64,
    pub block_hash: [u8; 32],
}

#[derive(Default, SimpleSerialize, Clone, Debug)]
pub struct SSZAttestation {
    pub aggregation_bits: Bitlist<{ config::MaxValidatorsPerCommittee::get() as usize }>,
    pub data: SSZAttestationData,
    pub signature: Vector<u8, { config::SignatureSize::get() as usize }>,
}

#[derive(Default, SimpleSerialize)]
pub struct SSZBeaconBlock {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body: SSZBeaconBlockBody,
}

#[derive(Default, SimpleSerialize, Clone, Debug)]
pub struct SSZBeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

#[derive(Default, SimpleSerialize)]
pub struct SSZSyncCommittee {
    pub pubkeys: Vector<
        Vector<u8, { config::PublicKeySize::get() as usize }>,
        { config::SyncCommitteeSize::get() as usize },
    >,
    pub aggregate_pubkey: Vector<u8, { config::PublicKeySize::get() as usize }>,
}

#[derive(Default, Debug, SimpleSerialize, Clone)]
pub struct SSZSyncAggregate {
    pub sync_committee_bits: Bitvector<{ config::SyncCommitteeSize::get() as usize }>,
    pub sync_committee_signature: Vector<u8, { config::SignatureSize::get() as usize }>,
}

#[derive(Default, SimpleSerialize)]
pub struct SSZForkData {
    pub current_version: [u8; 4],
    pub genesis_validators_root: [u8; 32],
}

#[derive(Default, SimpleSerialize)]
pub struct SSZSigningData {
    pub object_root: [u8; 32],
    pub domain: [u8; 32],
}

#[derive(Default, SimpleSerialize, Clone, Debug)]
pub struct SSZExecutionPayload {
    pub parent_hash: [u8; 32],
    pub fee_recipient: Vector<u8, { config::FeeRecipientSize::get() as usize }>,
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: Vector<u8, { config::BytesPerLogsBloom::get() as usize }>,
    pub prev_randao: [u8; 32],
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: List<u8, { config::MaxExtraDataBytes::get() as usize }>,
    pub base_fee_per_gas: U256,
    pub block_hash: [u8; 32],
    pub transactions_root: [u8; 32],
}

#[derive(Default, Debug, SimpleSerialize, Clone)]
pub struct SSZBeaconBlockBody {
    pub randao_reveal: Vector<u8, { config::SignatureSize::get() as usize }>,
    pub eth1_data: SSZEth1Data,
    pub graffiti: [u8; 32],
    pub proposer_slashings:
        List<SSZProposerSlashing, { config::MaxProposerSlashings::get() as usize }>,
    pub attester_slashings:
        List<SSZAttesterSlashing, { config::MaxAttesterSlashings::get() as usize }>,
    pub attestations: List<SSZAttestation, { config::MaxAttestations::get() as usize }>,
    pub deposits: List<SSZDeposit, { config::MaxDeposits::get() as usize }>,
    pub voluntary_exits: List<SSZVoluntaryExit, { config::MaxVoluntaryExits::get() as usize }>,
    pub sync_aggregate: SSZSyncAggregate,
    pub execution_payload: SSZExecutionPayload,
}

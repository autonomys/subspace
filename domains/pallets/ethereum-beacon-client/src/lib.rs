//! # Ethereum Beacon Client
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::large_enum_variant)] // Runtime-generated enums

mod merkleization;

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;

mod ssz;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

mod config;

pub use weights::WeightInfo;

use crate::merkleization::get_sync_committee_bits;
use frame_support::dispatch::DispatchResult;
use frame_support::traits::UnixTime;
use frame_support::{log, transactional};
use frame_system::ensure_signed;
use snowbridge_beacon_primitives::{
    BeaconHeader, BlockUpdate, Body, Domain, ExecutionHeader, ExecutionHeaderState,
    FinalizedHeaderState, FinalizedHeaderUpdate, ForkData, ForkVersion, InitialSync,
    LightClientUpdate, PublicKey, Root, SigningData, SyncCommittee,
};
use sp_core::H256;
use sp_io::hashing::sha2_256;
use sp_std::prelude::*;

pub use pallet::*;

pub type BlockUpdateOf = BlockUpdate<
    config::FeeRecipientSize,
    config::BytesPerLogsBloom,
    config::MaxExtraDataBytes,
    config::MaxDeposits,
    config::PublicKeySize,
    config::SignatureSize,
    config::MaxProofBranchSize,
    config::MaxProposerSlashings,
    config::MaxAttesterSlashings,
    config::MaxVoluntaryExits,
    config::MaxAttestations,
    config::MaxValidatorsPerCommittee,
    config::SyncCommitteeSize,
>;
pub type InitialSyncOf = InitialSync<config::SyncCommitteeSize, config::MaxProofBranchSize>;
pub type LightClientUpdateOf =
    LightClientUpdate<config::SignatureSize, config::MaxProofBranchSize, config::SyncCommitteeSize>;
pub type FinalizedHeaderUpdateOf = FinalizedHeaderUpdate<
    config::SignatureSize,
    config::MaxProofBranchSize,
    config::SyncCommitteeSize,
>;
pub type ExecutionHeaderOf = ExecutionHeader<config::BytesPerLogsBloom, config::MaxExtraDataBytes>;
pub type SyncCommitteeOf = SyncCommittee<config::SyncCommitteeSize>;
pub type BlockBodyOf = Body<
    config::FeeRecipientSize,
    config::BytesPerLogsBloom,
    config::MaxExtraDataBytes,
    config::MaxDeposits,
    config::PublicKeySize,
    config::SignatureSize,
    config::MaxProofBranchSize,
    config::MaxProposerSlashings,
    config::MaxAttesterSlashings,
    config::MaxVoluntaryExits,
    config::MaxAttestations,
    config::MaxValidatorsPerCommittee,
    config::SyncCommitteeSize,
>;

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    use milagro_bls::{AggregatePublicKey, AggregateSignature, AmclError, Signature};
    use snowbridge_beacon_primitives::ForkVersions;
    use sp_core::H160;

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type TimeProvider: UnixTime;
        /// ForkVersions refers to array of ForkVersion object with each object denoting the version
        /// of fork and the slot at which it is activated. The objects must be sorted by the slot.
        #[pallet::constant]
        type ForkVersions: Get<ForkVersions>;

        /// Maximum sync committees to be stored
        #[pallet::constant]
        type SyncCommitteePruneThreshold: Get<u64>;

        /// Maximum execution headers to be stored
        #[pallet::constant]
        type ExecutionHeadersPruneThreshold: Get<u64>;

        /// A period in which a the light client update must be submitted to this light client.
        /// In case we did not receive it, the light client will be blocked.
        type WeakSubjectivityPeriodSeconds: Get<u32>;

        type WeightInfo: WeightInfo;
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        BeaconHeaderImported { block_hash: H256, slot: u64 },
        ExecutionHeaderImported { block_hash: H256, block_number: u64 },
        SyncCommitteeUpdated { period: u64 },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// We do not have sync committee for the given period
        SyncCommitteeMissing,
        /// Less than supermajority of sync committee have signed the payload
        SyncCommitteeParticipantsNotSupermajority,
        /// Merkle proof of the consensus data against state root is invalid
        InvalidHeaderMerkleProof,
        /// Merkle proof of sync committee against state root is invalid
        InvalidSyncCommitteeMerkleProof,
        /// Invalid bls signature
        InvalidSignature,
        /// Invalid bls signature point
        InvalidSignaturePoint,
        /// BLS aggregated public keys are invalid
        InvalidAggregatePublicKeys,
        /// Invalid sync committee bits
        InvalidSyncCommitteeBits,
        /// Unable to verify bls aggregate signature
        SignatureVerificationFailed,
        /// Execution header is not finalized
        HeaderNotFinalized,
        /// Calculating hash tree root of beacon block body failed
        BlockBodyHashTreeRootFailed,
        /// Calculating hash tree root of beacon block header failed
        HeaderHashTreeRootFailed,
        /// Calculating hash tree root of sync committee failed
        SyncCommitteeHashTreeRootFailed,
        /// Calculating hash tree root of signing data failed
        SigningRootHashTreeRootFailed,
        /// Calculating hash tree root of fork data failed
        ForkDataHashTreeRootFailed,
        /// Bridge is blocked at the moment
        BridgeBlocked,
        /// Slot ordering of light client update is invalid
        InvalidSlotsOrdering,
        /// Sync committee signed the attested header is not recognized
        UnrecognizedSyncCommittee,
        /// Light client update does not contain any new information
        NonRelevantUpdate,
        /// Light client update does not contain enough information to be considered
        NotApplicableUpdate,
        /// Light client update should not contain finalized header
        NonEmptyFinalizedHeader,
        /// Light client update should not contain sync committee
        NonEmptySyncCommittee,
        /// Next sync committee in light client does not match stored committee for that period
        NextSyncCommitteeMismatch,
        /// Finalized header's sync committee period does not match store's current period
        FinalizedPeriodMismatch,
        /// Unable to store non sequential sync committee update
        NonSequentialSyncCommitteeUpdate,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

    /// Historical execution headers
    #[pallet::storage]
    pub(super) type ExecutionHeaders<T: Config> =
        CountedStorageMap<_, Identity, H256, ExecutionHeaderOf, OptionQuery>;

    /// Mapping of count -> Execution header hash. Used to prune older headers
    #[pallet::storage]
    pub(super) type ExecutionHeadersMapping<T: Config> =
        StorageMap<_, Identity, u64, H256, ValueQuery>;

    /// Historical sync committees till the sync committee of latest finalized header.
    #[pallet::storage]
    pub(super) type SyncCommittees<T: Config> =
        CountedStorageMap<_, Identity, u64, SyncCommitteeOf, ValueQuery>;

    /// Genesis validators root
    #[pallet::storage]
    pub(super) type GenesisValidatorsRoot<T: Config> = StorageValue<_, H256, ValueQuery>;

    /// Latest finalized header observed
    #[pallet::storage]
    pub(super) type LatestFinalizedHeaderState<T: Config> =
        StorageValue<_, FinalizedHeaderState, ValueQuery>;

    /// Latest execution header observed
    #[pallet::storage]
    pub(super) type LatestExecutionHeaderState<T: Config> =
        StorageValue<_, ExecutionHeaderState, ValueQuery>;

    /// Latest sync committee period observed
    #[pallet::storage]
    pub(super) type LatestSyncCommitteePeriod<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// Boolean signifying whether the bridge is blocked or not
    #[pallet::storage]
    pub(super) type Blocked<T: Config> = StorageValue<_, bool, ValueQuery>;

    #[pallet::genesis_config]
    #[derive(Default)]
    pub struct GenesisConfig {
        pub initial_sync: Option<InitialSyncOf>,
    }

    #[cfg(feature = "std")]
    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig {
        fn build(&self) {
            log::info!(
                target: "ethereum-beacon-client",
                "💫 Sync committee size is: {}",
                config::SyncCommitteeSize::get()
            );

            if let Some(initial_sync) = self.initial_sync.clone() {
                Pallet::<T>::initial_sync(initial_sync).expect("Genesis sync cannot fail");
            }
        }
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Updates the light client state
        #[pallet::weight(T::WeightInfo::sync_committee_period_update())]
        #[transactional]
        #[pallet::call_index(0)]
        pub fn light_client_update(
            origin: OriginFor<T>,
            light_client_update: LightClientUpdateOf,
        ) -> DispatchResult {
            let _sender = ensure_signed(origin)?;

            Self::check_bridge_blocked_state()?;

            let sync_committee_period = light_client_update.sync_committee_period;
            log::info!(
                target: "ethereum-beacon-client",
                "💫 Received light client update for sync committee period {}. Applying update",
                sync_committee_period
            );

            Self::process_light_client_update(light_client_update).map_err(|err| {
                log::error!(
                    target: "ethereum-beacon-client",
                    "💫 Light client update failed with error {:?}",
                    err
                );
                err
            })?;

            log::info!(
                target: "ethereum-beacon-client",
                "💫 Light client update for sync committee period {} succeeded.",
                sync_committee_period
            );

            Ok(())
        }

        /// Import an execution header
        #[pallet::weight(T::WeightInfo::import_execution_header())]
        #[transactional]
        #[pallet::call_index(1)]
        pub fn import_execution_header(
            origin: OriginFor<T>,
            update: BlockUpdateOf,
        ) -> DispatchResult {
            let _sender = ensure_signed(origin)?;

            Self::check_bridge_blocked_state()?;

            let slot = update.block.slot;
            let block_hash = update.block.body.execution_payload.block_hash;

            log::info!(
                target: "ethereum-beacon-client",
                "💫 Received header update for slot {}.",
                slot
            );

            Self::process_header(update).map_err(|err| {
                log::error!(
                    target: "ethereum-beacon-client",
                    "💫 Header update failed with error {:?}",
                    err
                );
                err
            })?;

            log::info!(
                target: "ethereum-beacon-client",
                "💫 Stored execution header {} at beacon slot {}.",
                block_hash,
                slot
            );

            Ok(())
        }

        /// Unblock the bridge. Can only be called by root.
        #[pallet::weight(1000)]
        #[transactional]
        #[pallet::call_index(2)]
        pub fn unblock_bridge(origin: OriginFor<T>) -> DispatchResult {
            ensure_root(origin)?;

            <Blocked<T>>::set(false);

            log::info!(target: "ethereum-beacon-client","💫 syncing bridge from governance provided checkpoint.");

            // TODO: Import governance provided checkpoint

            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn process_initial_sync(initial_sync: InitialSyncOf) -> DispatchResult {
            let sync_committee_root =
                merkleization::hash_tree_root_sync_committee(&initial_sync.current_sync_committee)
                    .map_err(|_| Error::<T>::SyncCommitteeHashTreeRootFailed)?;
            Self::verify_sync_committee(
                sync_committee_root.into(),
                initial_sync.current_sync_committee_branch,
                initial_sync.header.state_root,
                config::CurrentSyncCommitteeDepth::get(),
                config::CurrentSyncCommitteeIndex::get(),
            )?;

            let period = Self::compute_sync_committee_period(initial_sync.header.slot);

            let block_root: H256 =
                merkleization::hash_tree_root_beacon_header(initial_sync.header.clone())
                    .map_err(|_| Error::<T>::HeaderHashTreeRootFailed)?
                    .into();

            Self::store_sync_committee(period, initial_sync.current_sync_committee)?;
            Self::store_finalized_header(block_root, initial_sync.header);
            Self::store_validators_root(initial_sync.validators_root);

            Ok(())
        }

        fn is_next_sync_committee_known(finalized_period: u64) -> bool {
            <SyncCommittees<T>>::get(finalized_period + 1).pubkeys.len() != 0
        }

        fn stored_next_sync_committee(finalized_period: u64) -> SyncCommitteeOf {
            <SyncCommittees<T>>::get(finalized_period + 1)
        }

        fn stored_current_sync_committee(finalized_period: u64) -> SyncCommitteeOf {
            <SyncCommittees<T>>::get(finalized_period)
        }

        fn is_sync_committee_update(update: &LightClientUpdateOf) -> bool {
            update.next_sync_committee_branch.len() != 0
        }

        fn is_finality_update(update: &LightClientUpdateOf) -> bool {
            update.finality_branch.len() != 0
        }

        fn validate_light_client_update(
            update: &LightClientUpdateOf,
            current_slot: u64,
            validators_root: Root,
        ) -> DispatchResult {
            let sync_committee_bits =
                get_sync_committee_bits(update.sync_aggregate.sync_committee_bits.clone())
                    .map_err(|_| Error::<T>::InvalidSyncCommitteeBits)?;
            Self::sync_committee_participation_is_supermajority(sync_committee_bits.clone())?;

            let update_attested_slot = update.attested_header.slot;
            let update_finalized_slot = update.finalized_header.slot;

            ensure!(
                current_slot >= update.signature_slot
                    && update.signature_slot > update_attested_slot
                    && update_attested_slot >= update_finalized_slot,
                Error::<T>::InvalidSlotsOrdering
            );

            let stored_latest_finalized_header_state = <LatestFinalizedHeaderState<T>>::get();
            let store_period = Self::compute_sync_committee_period(
                stored_latest_finalized_header_state.beacon_slot,
            );
            let update_signature_period =
                Self::compute_sync_committee_period(update.signature_slot);

            if Self::is_next_sync_committee_known(store_period) {
                ensure!(
                    update_signature_period == store_period
                        || update_signature_period == store_period + 1,
                    Error::<T>::UnrecognizedSyncCommittee
                );
            } else {
                ensure!(
                    update_signature_period == store_period,
                    Error::<T>::UnrecognizedSyncCommittee
                );
            }

            let update_attested_period = Self::compute_sync_committee_period(update_attested_slot);
            let update_has_next_sync_committee = !Self::is_next_sync_committee_known(store_period)
                && (Self::is_sync_committee_update(update)
                    && update_attested_period == store_period);

            ensure!(
                update_attested_slot > stored_latest_finalized_header_state.beacon_slot
                    || update_has_next_sync_committee,
                Error::<T>::NonRelevantUpdate
            );

            if !Self::is_finality_update(update) {
                ensure!(
                    update.finalized_header == Default::default(),
                    Error::<T>::NonEmptyFinalizedHeader
                );
            } else {
                let mut finalized_block_root: H256 = Default::default();
                if update_finalized_slot == config::GenesisSlot::get() {
                    ensure!(
                        update.finalized_header == Default::default(),
                        Error::<T>::NonEmptyFinalizedHeader
                    );
                } else {
                    finalized_block_root = merkleization::hash_tree_root_beacon_header(
                        update.finalized_header.clone(),
                    )
                    .map_err(|_| Error::<T>::HeaderHashTreeRootFailed)?
                    .into();
                }

                Self::verify_header(
                    finalized_block_root,
                    update.finality_branch.clone(),
                    update.attested_header.state_root,
                    config::FinalizedRootDepth::get(),
                    config::FinalizedRootIndex::get(),
                )?;
            }

            if !Self::is_sync_committee_update(update) {
                ensure!(
                    update.next_sync_committee == Default::default(),
                    Error::<T>::NonEmptySyncCommittee
                );
            } else {
                if update_attested_period == store_period
                    && Self::is_next_sync_committee_known(store_period)
                {
                    let stored_next_committee = Self::stored_next_sync_committee(store_period);
                    ensure!(
                        update.next_sync_committee.eq(&stored_next_committee),
                        Error::<T>::NextSyncCommitteeMismatch
                    );
                }

                let next_sync_committee_root =
                    merkleization::hash_tree_root_sync_committee(&update.next_sync_committee)
                        .map_err(|_| Error::<T>::SyncCommitteeHashTreeRootFailed)?;

                Self::verify_sync_committee(
                    next_sync_committee_root.into(),
                    update.next_sync_committee_branch.clone(),
                    update.attested_header.state_root,
                    config::NextSyncCommitteeDepth::get(),
                    config::NextSyncCommitteeIndex::get(),
                )?;
            }

            let sync_committee_to_validate = if update_signature_period == store_period {
                Self::stored_current_sync_committee(store_period)
            } else {
                Self::stored_next_sync_committee(store_period)
            };

            Self::verify_signed_header(
                sync_committee_bits,
                update.sync_aggregate.sync_committee_signature.clone(),
                sync_committee_to_validate.pubkeys,
                update.attested_header.clone(),
                validators_root,
                update.signature_slot,
            )?;

            Ok(())
        }

        fn apply_light_client_update(
            update: LightClientUpdateOf,
            store_period: u64,
            finalized_header_state: FinalizedHeaderState,
        ) -> DispatchResult {
            let update_finalized_period =
                Self::compute_sync_committee_period(update.finalized_header.slot);

            if !Self::is_next_sync_committee_known(store_period) {
                ensure!(
                    update_finalized_period == store_period,
                    Error::<T>::FinalizedPeriodMismatch
                );
                Self::store_sync_committee(store_period + 1, update.next_sync_committee)?;
            } else if update_finalized_period == store_period + 1 {
                Self::store_sync_committee(store_period + 2, update.next_sync_committee)?;
            }

            if update.finalized_header.slot > finalized_header_state.beacon_slot {
                let block_root: H256 =
                    merkleization::hash_tree_root_beacon_header(update.finalized_header.clone())
                        .map_err(|_| Error::<T>::HeaderHashTreeRootFailed)?
                        .into();
                Self::store_finalized_header(block_root, update.finalized_header);
            }

            Ok(())
        }

        // Contract: It is assumed that the light client do not skip sync committee.
        fn prune_older_sync_committees() {
            let threshold = T::SyncCommitteePruneThreshold::get();
            let stored_sync_committees = <SyncCommittees<T>>::count();

            if stored_sync_committees as u64 > threshold {
                let latest_sync_committee_period = <LatestSyncCommitteePeriod<T>>::get();
                let highest_period_to_remove = latest_sync_committee_period - threshold;
                let number_of_sync_committees_to_remove = stored_sync_committees as u64 - threshold;

                let mut current_sync_committee_to_remove = highest_period_to_remove;
                while current_sync_committee_to_remove
                    > (highest_period_to_remove - number_of_sync_committees_to_remove)
                {
                    <SyncCommittees<T>>::remove(current_sync_committee_to_remove);
                    current_sync_committee_to_remove -= 1;
                }
            }
        }

        fn process_light_client_update(update: LightClientUpdateOf) -> DispatchResult {
            let last_finalized_header = <LatestFinalizedHeaderState<T>>::get();
            let import_time = last_finalized_header.import_time;
            let max_weak_subjectivity_period =
                import_time + T::WeakSubjectivityPeriodSeconds::get() as u64;
            let time: u64 = T::TimeProvider::now().as_secs();

            log::info!(
                target: "ethereum-beacon-client",
                "💫 Checking weak subjectivity period. Current time is :{:?} Weak subjectivity period check: {:?}.",
                time,
                max_weak_subjectivity_period
            );

            if time > max_weak_subjectivity_period {
                log::info!(target: "ethereum-beacon-client","💫 Weak subjectivity period exceeded, blocking bridge.",);
                <Blocked<T>>::set(true);
                return Err(Error::<T>::BridgeBlocked.into());
            }

            let validators_root = <GenesisValidatorsRoot<T>>::get();
            Self::validate_light_client_update(&update, update.signature_slot, validators_root)?;
            let sync_committee_bits = update.sync_aggregate.sync_committee_bits.clone();

            let stored_latest_finalized_header_state = <LatestFinalizedHeaderState<T>>::get();
            let store_period = Self::compute_sync_committee_period(
                stored_latest_finalized_header_state.beacon_slot,
            );
            let update_has_finalized_next_sync_committee =
                !Self::is_next_sync_committee_known(store_period)
                    && Self::is_sync_committee_update(&update)
                    && Self::is_finality_update(&update)
                    && (Self::compute_sync_committee_period(update.finalized_header.slot)
                        == Self::compute_sync_committee_period(update.attested_header.slot));

            if (Self::get_sync_committee_sum(sync_committee_bits.to_vec()) * 3
                >= sync_committee_bits.clone().len() as u64 * 2)
                && ((update.finalized_header.slot
                    > stored_latest_finalized_header_state.beacon_slot)
                    || update_has_finalized_next_sync_committee)
            {
                Self::apply_light_client_update(
                    update,
                    store_period,
                    stored_latest_finalized_header_state,
                )?;
                Self::prune_older_sync_committees();
            } else {
                return Err(Error::<T>::NotApplicableUpdate.into());
            }

            Ok(())
        }

        fn process_header(update: BlockUpdateOf) -> DispatchResult {
            let last_finalized_header = <LatestFinalizedHeaderState<T>>::get();
            let latest_finalized_header_slot = last_finalized_header.beacon_slot;
            let block_slot = update.block.slot;
            if block_slot > latest_finalized_header_slot {
                return Err(Error::<T>::HeaderNotFinalized.into());
            }

            let current_period = Self::compute_sync_committee_period(update.block.slot);
            let sync_committee = Self::get_sync_committee_for_period(current_period)?;

            let body_root = merkleization::hash_tree_root_beacon_body(update.block.body.clone())
                .map_err(|_| Error::<T>::BlockBodyHashTreeRootFailed)?;
            let body_root_hash: H256 = body_root.into();

            let header = BeaconHeader {
                slot: update.block.slot,
                proposer_index: update.block.proposer_index,
                parent_root: update.block.parent_root,
                state_root: update.block.state_root,
                body_root: body_root_hash,
            };

            let beacon_block_root: H256 =
                merkleization::hash_tree_root_beacon_header(header.clone())
                    .map_err(|_| Error::<T>::HeaderHashTreeRootFailed)?
                    .into(); // TODO check denylist headers

            let validators_root = <GenesisValidatorsRoot<T>>::get();
            let sync_committee_bits =
                get_sync_committee_bits(update.sync_aggregate.sync_committee_bits.clone())
                    .map_err(|_| Error::<T>::InvalidSyncCommitteeBits)?;
            Self::sync_committee_participation_is_supermajority(sync_committee_bits.clone())?;
            Self::verify_signed_header(
                sync_committee_bits,
                update.sync_aggregate.sync_committee_signature,
                sync_committee.pubkeys,
                header,
                validators_root,
                update.signature_slot,
            )?;

            let execution_payload = update.block.body.execution_payload;

            let mut fee_recipient = [0u8; 20];
            let fee_slice = execution_payload.fee_recipient.as_slice();
            if fee_slice.len() == 20 {
                fee_recipient[0..20].copy_from_slice(fee_slice);
            } else {
                log::trace!(
                    target: "ethereum-beacon-client",
                    "fee recipient not 20 characters, len is: {}.",
                    fee_slice.len()
                );
            }

            Self::store_execution_header(
                execution_payload.block_hash,
                ExecutionHeader {
                    parent_hash: execution_payload.parent_hash,
                    fee_recipient: H160::from(fee_recipient),
                    state_root: execution_payload.state_root,
                    receipts_root: execution_payload.receipts_root,
                    logs_bloom: execution_payload.logs_bloom,
                    prev_randao: execution_payload.prev_randao,
                    block_number: execution_payload.block_number,
                    gas_used: execution_payload.gas_used,
                    gas_limit: execution_payload.gas_limit,
                    timestamp: execution_payload.timestamp,
                    extra_data: execution_payload.extra_data,
                    base_fee_per_gas: execution_payload.base_fee_per_gas,
                    block_hash: execution_payload.block_hash,
                    transactions_root: execution_payload.transactions_root,
                },
                block_slot,
                beacon_block_root,
            );

            Ok(())
        }

        fn check_bridge_blocked_state() -> DispatchResult {
            if <Blocked<T>>::get() {
                return Err(Error::<T>::BridgeBlocked.into());
            }

            Ok(())
        }

        pub(super) fn verify_signed_header(
            sync_committee_bits: Vec<u8>,
            sync_committee_signature: BoundedVec<u8, config::SignatureSize>,
            sync_committee_pubkeys: BoundedVec<PublicKey, config::SyncCommitteeSize>,
            header: BeaconHeader,
            validators_root: H256,
            signature_slot: u64,
        ) -> DispatchResult {
            let mut participant_pubkeys: Vec<PublicKey> = Vec::new();
            // Gathers all the pubkeys of the sync committee members that participated in siging the
            // header.
            for (bit, pubkey) in sync_committee_bits
                .iter()
                .zip(sync_committee_pubkeys.iter())
            {
                if *bit == 1_u8 {
                    let pubk = pubkey.clone();
                    participant_pubkeys.push(pubk);
                }
            }

            let fork_version = Self::compute_fork_version(Self::compute_epoch_at_slot(
                signature_slot,
                config::SlotsPerEpoch::get(),
            ));
            let domain_type = config::DomainSyncCommittee::get().to_vec();
            // Domains are used for for seeds, for signatures, and for selecting aggregators.
            let domain = Self::compute_domain(domain_type, fork_version, validators_root)?;
            // Hash tree root of SigningData - object root + domain
            let signing_root = Self::compute_signing_root(header, domain)?;

            // Verify sync committee aggregate signature.
            Self::bls_fast_aggregate_verify(
                participant_pubkeys,
                signing_root,
                sync_committee_signature,
            )?;

            Ok(())
        }

        pub(super) fn compute_epoch_at_slot(signature_slot: u64, slots_per_epoch: u64) -> u64 {
            signature_slot / slots_per_epoch
        }

        pub(super) fn bls_fast_aggregate_verify(
            pubkeys: Vec<PublicKey>,
            message: H256,
            signature: BoundedVec<u8, config::SignatureSize>,
        ) -> DispatchResult {
            let sig =
                Signature::from_bytes(&signature[..]).map_err(|_e| Error::<T>::InvalidSignature)?;
            let agg_sig = AggregateSignature::from_signature(&sig);

            let public_keys = pubkeys
                .iter()
                .map(|bytes| milagro_bls::PublicKey::from_bytes_unchecked(&bytes.0))
                .collect::<Result<Vec<milagro_bls::PublicKey>, _>>()
                .map_err(|e| match e {
                    AmclError::InvalidPoint => Error::<T>::InvalidSignaturePoint,
                    _ => Error::<T>::InvalidSignature,
                })?;

            let agg_pub_key = AggregatePublicKey::into_aggregate(&public_keys)
                .map_err(|err| {
                    log::error!(target: "ethereum-beacon-client", "💫 invalid public keys with an error: {:?}.", err);
                    Error::<T>::InvalidAggregatePublicKeys
                })?;

            ensure!(
                agg_sig.fast_aggregate_verify_pre_aggregated(message.as_bytes(), &agg_pub_key),
                Error::<T>::SignatureVerificationFailed
            );

            Ok(())
        }

        pub(super) fn compute_signing_root(
            beacon_header: BeaconHeader,
            domain: Domain,
        ) -> Result<Root, DispatchError> {
            let beacon_header_root = merkleization::hash_tree_root_beacon_header(beacon_header)
                .map_err(|_| Error::<T>::HeaderHashTreeRootFailed)?;

            let header_hash_tree_root: H256 = beacon_header_root.into();

            let hash_root = merkleization::hash_tree_root_signing_data(SigningData {
                object_root: header_hash_tree_root,
                domain,
            })
            .map_err(|_| Error::<T>::SigningRootHashTreeRootFailed)?;

            Ok(hash_root.into())
        }

        fn verify_sync_committee(
            sync_committee_root: H256,
            sync_committee_branch: BoundedVec<H256, config::MaxProofBranchSize>,
            header_state_root: H256,
            depth: u64,
            index: u64,
        ) -> DispatchResult {
            ensure!(
                Self::is_valid_merkle_branch(
                    sync_committee_root,
                    sync_committee_branch,
                    depth,
                    index,
                    header_state_root
                ),
                Error::<T>::InvalidSyncCommitteeMerkleProof
            );

            Ok(())
        }

        fn verify_header(
            block_root: H256,
            proof_branch: BoundedVec<H256, config::MaxProofBranchSize>,
            attested_header_state_root: H256,
            depth: u64,
            index: u64,
        ) -> DispatchResult {
            ensure!(
                Self::is_valid_merkle_branch(
                    block_root,
                    proof_branch,
                    depth,
                    index,
                    attested_header_state_root
                ),
                Error::<T>::InvalidHeaderMerkleProof
            );

            Ok(())
        }

        fn store_sync_committee(period: u64, sync_committee: SyncCommitteeOf) -> DispatchResult {
            let latest_committee_period = <LatestSyncCommitteePeriod<T>>::get();
            // We only store sync committee sequentially except during initial update
            ensure!(
                latest_committee_period == 0 || latest_committee_period + 1 == period,
                Error::<T>::NonSequentialSyncCommitteeUpdate
            );
            <SyncCommittees<T>>::insert(period, sync_committee);
            <LatestSyncCommitteePeriod<T>>::set(period);

            log::trace!(
                target: "ethereum-beacon-client",
                "💫 Saved sync committee for period {}.",
                period
            );
            Self::deposit_event(Event::SyncCommitteeUpdated { period });

            Ok(())
        }

        fn store_finalized_header(block_root: Root, header: BeaconHeader) {
            let slot = header.slot;

            log::trace!(
                target: "ethereum-beacon-client",
                "💫 Saved finalized block root {} at slot {}.",
                block_root,
                slot
            );

            let mut last_finalized_header = <LatestFinalizedHeaderState<T>>::get();
            let latest_finalized_header_slot = last_finalized_header.beacon_slot;

            if slot > latest_finalized_header_slot {
                log::trace!(
                    target: "ethereum-beacon-client",
                    "💫 Updated latest finalized slot to {}.",
                    slot
                );
                last_finalized_header.import_time = T::TimeProvider::now().as_secs();
                last_finalized_header.beacon_block_header = header;
                last_finalized_header.beacon_slot = slot;
                last_finalized_header.beacon_block_root = block_root;

                <LatestFinalizedHeaderState<T>>::set(last_finalized_header);
            }

            Self::deposit_event(Event::BeaconHeaderImported {
                block_hash: block_root,
                slot,
            });
        }

        fn prune_older_execution_headers() {
            let threshold = T::ExecutionHeadersPruneThreshold::get();
            let stored_execution_headers = <ExecutionHeaders<T>>::count() as u64;

            if stored_execution_headers > threshold {
                let mut current_execution_header_to_delete = threshold + 1;
                while current_execution_header_to_delete <= stored_execution_headers {
                    let execution_header_hash =
                        <ExecutionHeadersMapping<T>>::get(current_execution_header_to_delete);
                    <ExecutionHeadersMapping<T>>::remove(current_execution_header_to_delete);
                    <ExecutionHeaders<T>>::remove(execution_header_hash);
                    current_execution_header_to_delete += 1;
                }
            }
        }

        fn store_execution_header(
            block_hash: H256,
            header: ExecutionHeaderOf,
            beacon_slot: u64,
            beacon_block_root: H256,
        ) {
            let block_number = header.block_number;

            <ExecutionHeaders<T>>::insert(block_hash, header);
            <ExecutionHeadersMapping<T>>::insert(
                <ExecutionHeaders<T>>::count() as u64 + 1,
                block_hash,
            );
            Self::prune_older_execution_headers();

            let mut execution_header_state = <LatestExecutionHeaderState<T>>::get();

            let latest_execution_block_number = execution_header_state.block_number;

            if block_number > latest_execution_block_number {
                log::trace!(
                    target: "ethereum-beacon-client",
                    "💫 Updated latest execution block number to {}.",
                    block_number
                );

                execution_header_state.beacon_block_root = beacon_block_root;
                execution_header_state.beacon_slot = beacon_slot;
                execution_header_state.block_hash = block_hash;
                execution_header_state.block_number = block_number;

                <LatestExecutionHeaderState<T>>::set(execution_header_state);
            }

            Self::deposit_event(Event::ExecutionHeaderImported {
                block_hash,
                block_number,
            });
        }

        fn store_validators_root(validators_root: H256) {
            <GenesisValidatorsRoot<T>>::set(validators_root);
        }

        /// Sums the bit vector of sync committee particpation.
        ///
        /// # Examples
        ///
        /// let sync_committee_bits = vec![0, 1, 0, 1, 1, 1];
        /// ensure!(get_sync_committee_sum(sync_committee_bits), 4);
        pub(super) fn get_sync_committee_sum(sync_committee_bits: Vec<u8>) -> u64 {
            sync_committee_bits
                .iter()
                .fold(0, |acc: u64, x| acc + *x as u64)
        }

        pub(super) fn compute_sync_committee_period(slot: u64) -> u64 {
            slot / config::SlotsPerEpoch::get() / config::EpochsPerSyncCommitteePeriod::get()
        }

        /// Return the domain for the domain_type and fork_version.
        pub(super) fn compute_domain(
            domain_type: Vec<u8>,
            fork_version: ForkVersion,
            genesis_validators_root: Root,
        ) -> Result<Domain, DispatchError> {
            let fork_data_root =
                Self::compute_fork_data_root(fork_version, genesis_validators_root)?;

            let mut domain = [0u8; 32];
            domain[0..4].copy_from_slice(&(domain_type));
            domain[4..32].copy_from_slice(&(fork_data_root.0[..28]));

            Ok(domain.into())
        }

        fn compute_fork_data_root(
            current_version: ForkVersion,
            genesis_validators_root: Root,
        ) -> Result<Root, DispatchError> {
            let hash_root = merkleization::hash_tree_root_fork_data(ForkData {
                current_version,
                genesis_validators_root: genesis_validators_root.into(),
            })
            .map_err(|_| Error::<T>::ForkDataHashTreeRootFailed)?;

            Ok(hash_root.into())
        }

        pub(super) fn is_valid_merkle_branch(
            leaf: H256,
            branch: BoundedVec<H256, config::MaxProofBranchSize>,
            depth: u64,
            index: u64,
            root: Root,
        ) -> bool {
            if branch.len() != depth as usize {
                log::error!(target: "ethereum-beacon-client", "Merkle proof branch length doesn't match depth.");

                return false;
            }
            let mut value = leaf;
            if leaf.as_bytes().len() < 32_usize {
                log::error!(target: "ethereum-beacon-client", "Merkle proof leaf not 32 bytes.");

                return false;
            }
            for i in 0..depth {
                if branch[i as usize].as_bytes().len() < 32_usize {
                    log::error!(target: "ethereum-beacon-client", "Merkle proof branch not 32 bytes.");

                    return false;
                }
                if (index / (2u32.pow(i as u32) as u64) % 2) == 0 {
                    // left node
                    let mut data = [0u8; 64];
                    data[0..32].copy_from_slice(&(value.0));
                    data[32..64].copy_from_slice(&(branch[i as usize].0));
                    value = sha2_256(&data).into();
                } else {
                    let mut data = [0u8; 64]; // right node
                    data[0..32].copy_from_slice(&(branch[i as usize].0));
                    data[32..64].copy_from_slice(&(value.0));
                    value = sha2_256(&data).into();
                }
            }

            value == root
        }

        pub(super) fn sync_committee_participation_is_supermajority(
            sync_committee_bits: Vec<u8>,
        ) -> DispatchResult {
            let sync_committee_sum = Self::get_sync_committee_sum(sync_committee_bits.clone());
            ensure!(
                (sync_committee_sum * 3 >= sync_committee_bits.len() as u64 * 2),
                Error::<T>::SyncCommitteeParticipantsNotSupermajority
            );

            Ok(())
        }

        pub(super) fn get_sync_committee_for_period(
            period: u64,
        ) -> Result<SyncCommitteeOf, DispatchError> {
            let sync_committee = <SyncCommittees<T>>::get(period);

            if sync_committee.pubkeys.len() == 0 {
                log::error!(target: "ethereum-beacon-client", "💫 Sync committee for period {} missing", period);
                return Err(Error::<T>::SyncCommitteeMissing.into());
            }

            Ok(sync_committee)
        }

        pub(super) fn compute_fork_version(epoch: u64) -> ForkVersion {
            let fork_versions = T::ForkVersions::get();

            if epoch >= fork_versions.bellatrix.epoch {
                return fork_versions.bellatrix.version;
            }
            if epoch >= fork_versions.altair.epoch {
                return fork_versions.altair.version;
            }

            fork_versions.genesis.version
        }

        pub(super) fn initial_sync(initial_sync: InitialSyncOf) -> Result<(), &'static str> {
            log::info!(
                target: "ethereum-beacon-client",
                "💫 Received initial sync, starting processing.",
            );

            Self::process_initial_sync(initial_sync).map_err(|err| {
                log::error!(
                    target: "ethereum-beacon-client",
                    "Initial sync failed with error {:?}",
                    err
                );
                <&str>::from(err)
            })?;

            log::info!(
                target: "ethereum-beacon-client",
                "💫 Initial sync processing succeeded.",
            );

            Ok(())
        }
    }
}

// Copyright (C) 2021 Subspace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

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

//! Light client substrate primitives for Subspace.
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_arithmetic::traits::{CheckedAdd, CheckedSub, One, Zero};
use sp_consensus_slots::Slot;
use sp_consensus_subspace::digests::{
    extract_pre_digest, extract_subspace_digest_items, verify_next_digests, CompatibleDigestItem,
    Error as DigestError, ErrorDigestType, NextDigestsVerificationParams, PreDigest,
    SubspaceDigestItems,
};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature};
use sp_runtime::traits::Header as HeaderT;
use sp_runtime::ArithmeticError;
use sp_std::cmp::Ordering;
use sp_std::collections::btree_map::BTreeMap;
use std::marker::PhantomData;
use subspace_core_primitives::crypto::kzg;
use subspace_core_primitives::crypto::kzg::Kzg;
use subspace_core_primitives::{
    BlockWeight, PublicKey, Randomness, RecordsRoot, RewardSignature, SectorId, SegmentIndex,
    SolutionRange, PIECES_IN_SEGMENT,
};
use subspace_solving::{derive_global_challenge, REWARD_SIGNING_CONTEXT};
use subspace_verification::{
    check_reward_signature, verify_solution, PieceCheckParams, VerifySolutionParams,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod mock;

/// Chain constants.
#[derive(Debug, Encode, Decode, Clone, TypeInfo)]
pub struct ChainConstants<Header: HeaderT> {
    /// K Depth at which we finalize the heads.
    pub k_depth: NumberOf<Header>,

    /// Genesis digest items at the start of the chain since the genesis block will not have any digests
    /// to verify the Block #1 digests.
    pub genesis_digest_items: NextDigestItems,

    /// Genesis block records roots to verify the Block #1 and other block solutions until Block #1 is finalized.
    /// When Block #1 is finalized, these records roots are present in Block #1 are stored in the storage.
    pub genesis_records_roots: BTreeMap<SegmentIndex, RecordsRoot>,

    /// Defines interval at which randomness is updated.
    pub global_randomness_interval: NumberOf<Header>,

    /// Era duration at which solution range is updated.
    pub era_duration: NumberOf<Header>,

    /// Slot probability.
    pub slot_probability: (u64, u64),

    /// Storage bound for the light client store.
    pub storage_bound: StorageBound<NumberOf<Header>>,
}

/// Defines the storage bound for the light client store.
#[derive(Default, Debug, Encode, Decode, TypeInfo, Clone)]
pub enum StorageBound<Number> {
    /// Keeps all the headers in the storage.
    #[default]
    Unbounded,
    /// Keeps only # number of headers beyond K depth.
    NumberOfHeaderToKeepBeyondKDepth(Number),
}

/// HeaderExt describes an extended block chain header at a specific height along with some computed values.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct HeaderExt<Header> {
    /// Actual header of the subspace block chain at a specific number.
    pub header: Header,
    /// Cumulative weight of chain until this header.
    pub total_weight: BlockWeight,
    /// Slot at which current era started.
    pub era_start_slot: Slot,
    /// Should adjust solution range on era change.
    pub should_adjust_solution_range: bool,
    /// Solution range override for the current era.
    pub maybe_current_solution_range_override: Option<SolutionRange>,
    /// Solution range override for the next era.
    pub maybe_next_solution_range_override: Option<SolutionRange>,
    /// Restrict block authoring to this public key.
    pub maybe_root_plot_public_key: Option<FarmerPublicKey>,

    #[cfg(test)]
    test_overrides: mock::TestOverrides,
}

/// Type to hold next digest items present in parent header that are used to verify the immediate descendant.
#[derive(Default, Debug, Encode, Decode, Clone, TypeInfo)]
pub struct NextDigestItems {
    next_global_randomness: Randomness,
    next_solution_range: SolutionRange,
}

impl NextDigestItems {
    /// Constructs self with provided next digest items.
    pub fn new(next_global_randomness: Randomness, next_solution_range: SolutionRange) -> Self {
        Self {
            next_global_randomness,
            next_solution_range,
        }
    }
}

impl<Header: HeaderT> HeaderExt<Header> {
    /// Extracts the next digest items Randomness, Solution range, and Salt present in the Header.
    /// If next digests are not present, then we fallback to the current ones.
    fn extract_next_digest_items(&self) -> Result<NextDigestItems, ImportError<Header>> {
        let SubspaceDigestItems {
            global_randomness,
            solution_range,
            next_global_randomness,
            next_solution_range,
            ..
        } = extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
            &self.header,
        )?;

        // if there is override for solution range for current era, override it
        let solution_range = self
            .maybe_current_solution_range_override
            .unwrap_or(solution_range);

        #[cfg(test)]
        let solution_range = {
            if self.test_overrides.solution_range.is_some() {
                self.test_overrides.solution_range.unwrap()
            } else {
                solution_range
            }
        };

        #[cfg(test)]
        let next_solution_range = {
            if self.test_overrides.next_solution_range.is_some() {
                self.test_overrides.next_solution_range
            } else {
                next_solution_range
            }
        };

        Ok(NextDigestItems {
            next_global_randomness: next_global_randomness.unwrap_or(global_randomness),
            next_solution_range: next_solution_range.unwrap_or(solution_range),
        })
    }
}

type HashOf<T> = <T as HeaderT>::Hash;
type NumberOf<T> = <T as HeaderT>::Number;

/// Storage responsible for storing headers.
pub trait Storage<Header: HeaderT> {
    /// Returns the chain constants.
    fn chain_constants(&self) -> ChainConstants<Header>;

    /// Queries a header at a specific block number or block hash.
    fn header(&self, hash: HashOf<Header>) -> Option<HeaderExt<Header>>;

    /// Stores the extended header.
    /// `as_best_header` signifies of the header we are importing is considered best.
    fn store_header(&mut self, header_ext: HeaderExt<Header>, as_best_header: bool);

    /// Returns the best known tip of the chain.
    fn best_header(&self) -> HeaderExt<Header>;

    /// Returns headers at a given number.
    fn headers_at_number(&self, number: NumberOf<Header>) -> Vec<HeaderExt<Header>>;

    /// Prunes header with hash.
    fn prune_header(&mut self, hash: HashOf<Header>);

    /// Marks a given header with hash as finalized.
    fn finalize_header(&mut self, hash: HashOf<Header>);

    /// Returns the latest finalized header.
    fn finalized_header(&self) -> HeaderExt<Header>;

    /// Stores records roots for fast retrieval by segment index at or below finalized header.
    fn store_records_roots(&mut self, records_roots: BTreeMap<SegmentIndex, RecordsRoot>);

    /// Returns a records root for a given segment index.
    fn records_root(&self, segment_index: SegmentIndex) -> Option<RecordsRoot>;

    /// Returns the stored segment count.
    fn number_of_segments(&self) -> u64;
}

/// Error type that holds the current finalized number and the header number we are trying to import.
#[derive(Debug, PartialEq, Eq)]
pub struct HeaderBelowArchivingDepthError<Header: HeaderT> {
    current_finalized_number: NumberOf<Header>,
    header_number: NumberOf<Header>,
}

/// Error during the header import.
#[derive(Debug, PartialEq, Eq)]
pub enum ImportError<Header: HeaderT> {
    /// Header already imported.
    HeaderAlreadyImported,
    /// Missing parent header.
    MissingParent(HashOf<Header>),
    /// Missing header associated with hash.
    MissingHeader(HashOf<Header>),
    /// Missing ancestor header at the number.
    MissingAncestorHeader(HashOf<Header>, NumberOf<Header>),
    /// Error while extracting digests from header.
    DigestError(DigestError),
    /// Invalid digest in the header.
    InvalidDigest(ErrorDigestType),
    /// Invalid slot when compared with parent header.
    InvalidSlot,
    /// Block signature is invalid.
    InvalidBlockSignature,
    /// Total number of pieces can't be zero
    TotalNumberOfPiecesCantBeZero,
    /// Solution present in the header is invalid.
    InvalidSolution(subspace_verification::Error),
    /// Arithmetic error.
    ArithmeticError(ArithmeticError),
    /// Switched to different fork beyond archiving depth.
    SwitchedToForkBelowArchivingDepth,
    /// Header being imported is below the archiving depth.
    HeaderIsBelowArchivingDepth(HeaderBelowArchivingDepthError<Header>),
    /// Missing records root for a given segment index.
    MissingRecordsRoot(SegmentIndex),
    /// Incorrect block author.
    IncorrectBlockAuthor(FarmerPublicKey),
}

impl<Header: HeaderT> From<DigestError> for ImportError<Header> {
    fn from(error: DigestError) -> Self {
        ImportError::DigestError(error)
    }
}

/// Verifies and import headers.
#[derive(Debug)]
pub struct HeaderImporter<Header: HeaderT, Store: Storage<Header>> {
    store: Store,
    _phantom: PhantomData<Header>,
}

impl<Header: HeaderT, Store: Storage<Header>> HeaderImporter<Header, Store> {
    /// Returns a new instance of HeaderImporter with provided Storage impls
    pub fn new(store: Store) -> Self {
        HeaderImporter {
            store,
            _phantom: Default::default(),
        }
    }

    /// Verifies header, computes consensus values for block progress and stores the HeaderExt.
    pub fn import_header(&mut self, mut header: Header) -> Result<(), ImportError<Header>> {
        // check if the header is already imported
        match self.store.header(header.hash()) {
            Some(_) => Err(ImportError::HeaderAlreadyImported),
            None => Ok(()),
        }?;

        // only try and import headers above the finalized number
        let current_finalized_number = *self.store.finalized_header().header.number();
        if *header.number() <= current_finalized_number {
            return Err(ImportError::HeaderIsBelowArchivingDepth(
                HeaderBelowArchivingDepthError {
                    current_finalized_number,
                    header_number: *header.number(),
                },
            ));
        }

        // fetch parent header
        let parent_header = self
            .store
            .header(*header.parent_hash())
            .ok_or_else(|| ImportError::MissingParent(header.hash()))?;

        // verify global randomness and solution range from the parent header
        let header_digests = self.verify_header_digest_with_parent(&parent_header, &header)?;

        // verify next digest items
        let constants = self.store.chain_constants();
        let mut maybe_root_plot_public_key = parent_header.maybe_root_plot_public_key;
        if let Some(root_plot_public_key) = &maybe_root_plot_public_key {
            if root_plot_public_key != &header_digests.pre_digest.solution.public_key {
                return Err(ImportError::IncorrectBlockAuthor(
                    header_digests.pre_digest.solution.public_key,
                ));
            }
        }

        let mut should_adjust_solution_range = parent_header.should_adjust_solution_range;
        let mut maybe_next_solution_range_override =
            parent_header.maybe_next_solution_range_override;
        verify_next_digests::<Header>(NextDigestsVerificationParams {
            number: *header.number(),
            header_digests: &header_digests,
            global_randomness_interval: constants.global_randomness_interval,
            era_duration: constants.era_duration,
            slot_probability: constants.slot_probability,
            era_start_slot: parent_header.era_start_slot,
            should_adjust_solution_range: &mut should_adjust_solution_range,
            maybe_next_solution_range_override: &mut maybe_next_solution_range_override,
            maybe_root_plot_public_key: &mut maybe_root_plot_public_key,
        })?;

        // slot must be strictly increasing from the parent header
        Self::verify_slot(&parent_header.header, &header_digests.pre_digest)?;

        // verify block signature
        Self::verify_block_signature(&mut header, &header_digests.pre_digest.solution.public_key)?;

        // verify solution
        let sector_id = SectorId::new(
            &(&header_digests.pre_digest.solution.public_key).into(),
            header_digests.pre_digest.solution.sector_index,
        );

        let piece_index = sector_id
            .derive_piece_index(
                header_digests.pre_digest.solution.piece_offset,
                header_digests.pre_digest.solution.total_pieces,
            )
            .map_err(|()| ImportError::TotalNumberOfPiecesCantBeZero)?;
        let position = u32::try_from(piece_index % u64::from(PIECES_IN_SEGMENT))
            .expect("Position within segment always fits into u32; qed");
        let segment_index: SegmentIndex = piece_index / SegmentIndex::from(PIECES_IN_SEGMENT);

        let records_root =
            self.find_records_root_for_segment_index(segment_index, parent_header.header.hash())?;

        // TODO: Probably should have public parameters in chain constants instead
        let kzg = Kzg::new(kzg::test_public_parameters());

        verify_solution(
            &header_digests.pre_digest.solution,
            header_digests.pre_digest.slot.into(),
            VerifySolutionParams {
                global_randomness: &header_digests.global_randomness,
                solution_range: header_digests.solution_range,
                piece_check_params: Some(PieceCheckParams {
                    records_root: &records_root,
                    position,
                    kzg: &kzg,
                    pieces_in_segment: PIECES_IN_SEGMENT,
                }),
            },
        )
        .map_err(ImportError::InvalidSolution)?;

        let block_weight = Self::calculate_block_weight(&sector_id, &header_digests);
        let total_weight = parent_header.total_weight + block_weight;

        // last best header should ideally be parent header. if not check for forks and pick the best chain
        let last_best_header = self.store.best_header();
        let is_best_header = if last_best_header.header.hash() == parent_header.header.hash() {
            // header is extending the current best header. consider this best header
            true
        } else {
            let last_best_weight = last_best_header.total_weight;
            match total_weight.cmp(&last_best_weight) {
                // current weight is greater than last best. pick this header as best
                Ordering::Greater => true,
                // if weights are equal, pick the longest chain
                Ordering::Equal => header.number() > last_best_header.header.number(),
                // we already are on the best chain
                Ordering::Less => false,
            }
        };

        // check if era has changed
        let era_start_slot = if Self::has_era_changed(&header, constants.era_duration) {
            header_digests.pre_digest.slot
        } else {
            parent_header.era_start_slot
        };

        // check if we should update current solution range override
        let mut maybe_current_solution_range_override =
            parent_header.maybe_current_solution_range_override;

        // if there is override of solution range in this header, use it
        if let Some(current_solution_range_override) =
            header_digests.enable_solution_range_adjustment_and_override
        {
            maybe_current_solution_range_override = current_solution_range_override;
        }

        // check if the era has changed and there is a current solution range override, reset it
        if maybe_current_solution_range_override.is_some()
            && Self::has_era_changed(&header, constants.era_duration)
        {
            maybe_current_solution_range_override = None
        }

        // store header
        let header_ext = HeaderExt {
            header,
            total_weight,
            era_start_slot,
            should_adjust_solution_range,
            maybe_current_solution_range_override,
            maybe_next_solution_range_override,
            maybe_root_plot_public_key,

            #[cfg(test)]
            test_overrides: Default::default(),
        };

        self.store.store_header(header_ext, is_best_header);

        // finalize, prune forks, and ensure storage is bounded if the chain has progressed
        if is_best_header {
            self.finalize_header_at_k_depth()?;
            self.ensure_storage_bound();
        }

        Ok(())
    }

    fn has_era_changed(header: &Header, era_duration: NumberOf<Header>) -> bool {
        // special case when the current header is one, then first era begins
        // or
        // era duration interval has reached, so era has changed
        header.number().is_one() || *header.number() % era_duration == Zero::zero()
    }

    /// Verifies if the header digests matches with logs from the parent header.
    fn verify_header_digest_with_parent(
        &self,
        parent_header: &HeaderExt<Header>,
        header: &Header,
    ) -> Result<
        SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature>,
        ImportError<Header>,
    > {
        // extract digest items from the header
        let pre_digest_items = extract_subspace_digest_items(header)?;
        // extract next digest items from the parent header
        let next_digest_items = {
            // if the header we are verifying is #1, then parent header, genesis, wont have the next digests
            // instead fetch them from the constants provided by the store
            if header.number() == &One::one() {
                self.store.chain_constants().genesis_digest_items
            } else {
                parent_header.extract_next_digest_items()?
            }
        };

        // check the digest items against the next digest items from parent header
        if pre_digest_items.global_randomness != next_digest_items.next_global_randomness {
            return Err(ImportError::InvalidDigest(
                ErrorDigestType::GlobalRandomness,
            ));
        }

        if pre_digest_items.solution_range != next_digest_items.next_solution_range {
            return Err(ImportError::InvalidDigest(ErrorDigestType::SolutionRange));
        }

        Ok(pre_digest_items)
    }

    /// Verifies that slot present in the header is strictly increasing from the slot in the parent.
    fn verify_slot(
        parent_header: &Header,
        pre_digest: &PreDigest<FarmerPublicKey, FarmerPublicKey>,
    ) -> Result<(), ImportError<Header>> {
        let parent_pre_digest = extract_pre_digest(parent_header)?;

        if pre_digest.slot <= parent_pre_digest.slot {
            return Err(ImportError::InvalidSlot);
        }

        Ok(())
    }

    /// Verifies the block signature present in the last digest log.
    fn verify_block_signature(
        header: &mut Header,
        public_key: &FarmerPublicKey,
    ) -> Result<(), ImportError<Header>> {
        let seal =
            header
                .digest_mut()
                .pop()
                .ok_or(ImportError::DigestError(DigestError::Missing(
                    ErrorDigestType::Seal,
                )))?;

        let signature = seal
            .as_subspace_seal()
            .ok_or(ImportError::InvalidDigest(ErrorDigestType::Seal))?;

        // the pre-hash of the header doesn't include the seal and that's what we sign
        let pre_hash = header.hash();

        // verify that block is signed properly
        check_reward_signature(
            pre_hash.as_ref(),
            &RewardSignature::from(&signature),
            &PublicKey::from(public_key),
            &schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT),
        )
        .map_err(|_| ImportError::InvalidBlockSignature)?;

        // push the seal back into the header
        header.digest_mut().push(seal);
        Ok(())
    }

    /// Calculates block weight from randomness and predigest.
    fn calculate_block_weight(
        sector_id: &SectorId,
        header_digests: &SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature>,
    ) -> BlockWeight {
        let global_challenge = derive_global_challenge(
            &header_digests.global_randomness,
            header_digests.pre_digest.slot.into(),
        );

        let local_challenge = sector_id.derive_local_challenge(&global_challenge);

        let expanded_chunk = header_digests
            .pre_digest
            .solution
            .chunk
            .expand(local_challenge);

        BlockWeight::from(
            SolutionRange::MAX
                - subspace_core_primitives::bidirectional_distance(
                    &local_challenge,
                    &expanded_chunk,
                ),
        )
    }

    /// Returns the ancestor of the header at number.
    fn find_ancestor_of_header_at_number(
        &self,
        hash: HashOf<Header>,
        ancestor_number: NumberOf<Header>,
    ) -> Option<HeaderExt<Header>> {
        let header = self.store.header(hash)?;

        // header number must be greater than the ancestor number
        if *header.header.number() < ancestor_number {
            return None;
        }

        let headers_at_ancestor_number = self.store.headers_at_number(ancestor_number);

        // short circuit if there are no fork headers at the ancestor number
        if headers_at_ancestor_number.len() == 1 {
            return headers_at_ancestor_number.into_iter().next();
        }

        // start tree route till the ancestor
        let mut header = header;
        while *header.header.number() > ancestor_number {
            header = self.store.header(*header.header.parent_hash())?;
        }

        Some(header)
    }

    /// Prunes header and its descendant header chain(s).
    fn prune_header_and_its_descendants(
        &mut self,
        header: HeaderExt<Header>,
    ) -> Result<(), ImportError<Header>> {
        // prune the header
        self.store.prune_header(header.header.hash());

        // start pruning all the descendant headers from the current header
        //        header(at number n)
        //        /         \
        //  descendant-1   descendant-2
        //     /
        //  descendant-3
        let mut pruned_parent_hashes = vec![header.header.hash()];
        let mut current_number = *header.header.number();

        while !pruned_parent_hashes.is_empty() {
            current_number = current_number
                .checked_add(&One::one())
                .ok_or(ImportError::ArithmeticError(ArithmeticError::Overflow))?;

            // get headers at the current number and filter the headers descended from the pruned parents
            let descendant_header_hashes = self
                .store
                .headers_at_number(current_number)
                .into_iter()
                .filter(|descendant_header| {
                    pruned_parent_hashes.contains(descendant_header.header.parent_hash())
                })
                .map(|header| header.header.hash())
                .collect::<Vec<HashOf<Header>>>();

            // prune the descendant headers
            descendant_header_hashes
                .iter()
                .for_each(|hash| self.store.prune_header(*hash));

            pruned_parent_hashes = descendant_header_hashes;
        }

        Ok(())
    }

    /// Returns the total pieces on chain where chain_tip is the hash of the tip of the chain.
    /// We count the total segments to calculate total pieces as follows,
    /// - Fetch the segment count from the store.
    /// - Count the segments from each header that is not finalized.
    // TODO: This function will become useful in the future for verifying sector expiration
    #[allow(dead_code)]
    fn total_pieces(&self, chain_tip: HashOf<Header>) -> Result<u64, ImportError<Header>> {
        // fetch the segment count from the store
        let records_roots_count_till_finalized_header = self.store.number_of_segments();

        let finalized_header = self.store.finalized_header();
        let mut records_roots_count = records_roots_count_till_finalized_header;

        // special case when Block #1 is not finalized yet, then include the genesis segment count
        if finalized_header.header.number().is_zero() {
            records_roots_count += self.store.chain_constants().genesis_records_roots.len() as u64;
        }

        // calculate segment count present in each header from header till finalized header
        let mut header = self
            .store
            .header(chain_tip)
            .ok_or(ImportError::MissingHeader(chain_tip))?;

        while header.header.hash() != finalized_header.header.hash() {
            let digest_items = extract_subspace_digest_items::<
                _,
                FarmerPublicKey,
                FarmerPublicKey,
                FarmerSignature,
            >(&header.header)?;
            records_roots_count += digest_items.records_roots.len() as u64;

            header = self
                .store
                .header(*header.header.parent_hash())
                .ok_or_else(|| ImportError::MissingParent(header.header.hash()))?;
        }

        Ok(records_roots_count * u64::from(PIECES_IN_SEGMENT))
    }

    /// Finds a records root mapped against a segment index in the chain with chain_tip as the tip of the chain.
    /// We try to find the records root as follows,
    ///  - Find records root from the store and return if found.
    ///  - Find records root from the genesis record roots and return if found.
    ///  - Find the records root present in the non finalized headers.
    fn find_records_root_for_segment_index(
        &self,
        segment_index: SegmentIndex,
        chain_tip: HashOf<Header>,
    ) -> Result<RecordsRoot, ImportError<Header>> {
        // check if the records root is already in the store
        if let Some(records_root) = self.store.records_root(segment_index) {
            return Ok(records_root);
        };

        // special case: check the genesis records roots if the Block #1 is not finalized yet
        if let Some(records_root) = self
            .store
            .chain_constants()
            .genesis_records_roots
            .get(&segment_index)
        {
            return Ok(*records_root);
        }

        // find the records root from the headers which are not finalized yet.
        let finalized_header = self.store.finalized_header();
        let mut header = self
            .store
            .header(chain_tip)
            .ok_or(ImportError::MissingHeader(chain_tip))?;

        while header.header.hash() != finalized_header.header.hash() {
            let digest_items = extract_subspace_digest_items::<
                _,
                FarmerPublicKey,
                FarmerPublicKey,
                FarmerSignature,
            >(&header.header)?;

            if let Some(records_root) = digest_items.records_roots.get(&segment_index) {
                return Ok(*records_root);
            }

            header = self
                .store
                .header(*header.header.parent_hash())
                .ok_or_else(|| ImportError::MissingParent(header.header.hash()))?;
        }

        Err(ImportError::MissingRecordsRoot(segment_index))
    }

    /// Stores finalized header and records roots present in the header.
    fn store_finalized_header_and_records_roots(
        &mut self,
        header: &Header,
    ) -> Result<(), ImportError<Header>> {
        let digests_items =
            extract_subspace_digest_items::<_, FarmerPublicKey, FarmerPublicKey, FarmerSignature>(
                header,
            )?;

        // mark header as finalized
        self.store.finalize_header(header.hash());

        // store the records roots present in the header digests
        self.store.store_records_roots(digests_items.records_roots);
        Ok(())
    }

    /// Finalize the header at K-depth from the best block and prune remaining forks at that number.
    /// We want to finalize the header from the current finalized header until the K-depth number of the best.
    /// 1. In an ideal scenario, the current finalized head is one number less than number to be finalized.
    /// 2. If there was a re-org to longer chain when new header was imported, we do not want to miss
    ///    pruning fork headers between current and to be finalized number. So we go number by number and prune fork headers.
    /// 3. If there was a re-org to a shorter chain and to be finalized header was below the current finalized head,
    ///    fail and let user know.
    fn finalize_header_at_k_depth(&mut self) -> Result<(), ImportError<Header>> {
        let k_depth = self.store.chain_constants().k_depth;
        let current_finalized_header = self.store.finalized_header();

        // ensure we have imported at least K-depth number of headers
        let number_to_finalize = match self
            .store
            .best_header()
            .header
            .number()
            .checked_sub(&k_depth)
        {
            // we have not progressed that far to finalize yet
            None => {
                // if the chain re-org happened to smaller chain and if there was any finalized heads,
                // fail and let the user decide what to do
                if *current_finalized_header.header.number() > Zero::zero() {
                    return Err(ImportError::SwitchedToForkBelowArchivingDepth);
                }

                return Ok(());
            }

            Some(number) => number,
        };

        match number_to_finalize.cmp(current_finalized_header.header.number()) {
            Ordering::Less => Err(ImportError::SwitchedToForkBelowArchivingDepth),
            // nothing to do as we finalized the header already
            Ordering::Equal => Ok(()),
            // finalize heads one after the other and prune any forks
            Ordering::Greater => {
                let mut current_finalized_number = *current_finalized_header.header.number();

                while current_finalized_number < number_to_finalize {
                    current_finalized_number = current_finalized_number
                        .checked_add(&One::one())
                        .ok_or(ImportError::ArithmeticError(ArithmeticError::Overflow))?;

                    // find the headers at the number to be finalized
                    let headers_at_number_to_be_finalized =
                        self.store.headers_at_number(current_finalized_number);
                    // if there is just one header at that number, we mark that header as finalized and move one
                    if headers_at_number_to_be_finalized.len() == 1 {
                        let header_to_finalize = headers_at_number_to_be_finalized
                            .first()
                            .expect("First item must exist as the len is 1.");

                        self.store_finalized_header_and_records_roots(&header_to_finalize.header)?
                    } else {
                        // there are multiple headers at the number to be finalized.
                        // find the correct ancestor header of the current best header.
                        // finalize it and prune all the remaining fork headers.
                        let current_best_header = self.store.best_header();
                        let (current_best_hash, current_best_number) = (
                            current_best_header.header.hash(),
                            *current_best_header.header.number(),
                        );

                        let header_to_finalize = self
                            .find_ancestor_of_header_at_number(
                                current_best_hash,
                                current_finalized_number,
                            )
                            .ok_or(ImportError::MissingAncestorHeader(
                                current_best_hash,
                                current_best_number,
                            ))?;

                        // filter fork headers and prune them
                        let headers_to_prune = headers_at_number_to_be_finalized
                            .into_iter()
                            .filter(|header| {
                                header.header.hash() != header_to_finalize.header.hash()
                            })
                            .collect::<Vec<HeaderExt<Header>>>();

                        for header_to_prune in headers_to_prune {
                            self.prune_header_and_its_descendants(header_to_prune)?;
                        }

                        // mark the header as finalized
                        self.store_finalized_header_and_records_roots(&header_to_finalize.header)?
                    }
                }

                Ok(())
            }
        }
    }

    /// Ensure light client storage is bounded by the defined storage bound constant.
    /// If unbounded, we keep all the finalized headers in the store.
    /// If bounded, we fetch the finalized head and then prune all the headers
    /// beyond K depth as per bounded value.
    /// If finalized head is at x and storage is bounded to keep y headers beyond, then
    /// prune all headers at and below (x - y - 1)
    fn ensure_storage_bound(&mut self) {
        let storage_bound = self.store.chain_constants().storage_bound;
        let number_of_headers_to_keep_beyond_k_depth = match storage_bound {
            // unbounded storage, so return
            StorageBound::Unbounded => return,
            // bounded storage, keep only # number of headers beyond K depth
            StorageBound::NumberOfHeaderToKeepBeyondKDepth(number_of_headers_to_keep) => {
                number_of_headers_to_keep
            }
        };

        let finalized_head_number = *self.store.finalized_header().header.number();
        // (finalized_number - bound_value - 1)
        let mut maybe_prune_headers_from_number = finalized_head_number
            .checked_sub(&number_of_headers_to_keep_beyond_k_depth)
            .and_then(|number| number.checked_sub(&One::one()));

        let mut headers_to_prune = maybe_prune_headers_from_number
            .map(|number| self.store.headers_at_number(number))
            .unwrap_or_default();

        while !headers_to_prune.is_empty() {
            // loop and prune even though there should be only 1 head beyond finalized head
            for header in headers_to_prune {
                self.store.prune_header(header.header.hash())
            }

            maybe_prune_headers_from_number =
                maybe_prune_headers_from_number.and_then(|number| number.checked_sub(&One::one()));

            headers_to_prune = maybe_prune_headers_from_number
                .map(|number| self.store.headers_at_number(number))
                .unwrap_or_default();
        }
    }
}

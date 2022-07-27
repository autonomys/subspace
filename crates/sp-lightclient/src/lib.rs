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
use sp_consensus_subspace::digests::{
    extract_pre_digest, extract_subspace_digest_items, CompatibleDigestItem, Error as DigestError,
    ErrorDigestType, PreDigest, SubspaceDigestItems,
};
use sp_consensus_subspace::{FarmerPublicKey, FarmerSignature};
use sp_runtime::traits::Header as HeaderT;
use sp_runtime::ArithmeticError;
use sp_std::cmp::Ordering;
use std::marker::PhantomData;
use subspace_core_primitives::{PublicKey, Randomness, RewardSignature, Salt};
use subspace_solving::{derive_global_challenge, derive_target, REWARD_SIGNING_CONTEXT};
use subspace_verification::{check_reward_signature, verify_solution, VerifySolutionParams};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod mock;

// TODO(ved): move them to consensus primitives and change usages across
/// Type of solution range.
type SolutionRange = u64;

/// BlockWeight type for fork choice rules.
type BlockWeight = u128;

/// Chain constants.
#[derive(Debug, Clone)]
pub struct ChainConstants<Header: HeaderT> {
    /// K Depth at which we finalize the heads.
    pub k_depth: NumberOf<Header>,
}

/// HeaderExt describes an extended block chain header at a specific height along with some computed values.
#[derive(Default, Debug, Encode, Decode, Clone, Eq, PartialEq, TypeInfo)]
pub struct HeaderExt<Header> {
    /// Actual header of the subspace block chain at a specific number.
    pub header: Header,
    /// Global randomness after importing the header above.
    /// This is same as the parent block unless update interval is met.
    pub derived_global_randomness: Randomness,
    /// Solution range after importing the header above.
    /// This is same as the parent block unless update interval is met.
    pub derived_solution_range: SolutionRange,
    /// Salt after importing the header above.
    /// This is same as the parent block unless update interval is met.
    pub derived_salt: Salt,
    /// Cumulative weight of chain until this header.
    pub total_weight: BlockWeight,
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
}

/// Error during the header import.
#[derive(Debug, PartialEq, Eq)]
pub enum ImportError<Header: HeaderT> {
    /// Header already imported.
    HeaderAlreadyImported,
    /// Missing parent header.
    MissingParent(HashOf<Header>),
    /// Missing ancestor header at the number.
    MissingAncestorHeader(HashOf<Header>, NumberOf<Header>),
    /// Error while extracting digests from header.
    DigestExtractionError(DigestError),
    /// Invalid digest in the header.
    InvalidDigest(ErrorDigestType),
    /// Invalid slot when compared with parent header.
    InvalidSlot,
    /// Block signature is invalid.
    InvalidBlockSignature,
    /// Solution present in the header is invalid.
    InvalidSolution(subspace_verification::Error),
    /// Arithmetic error.
    ArithmeticError(ArithmeticError),
    /// Switched to different fork beyond archiving depth.
    SwitchedToForkBelowArchivingDepth,
    /// Header being imported is below the archiving depth.
    HeaderIsBelowArchivingDepth,
}

impl<Header: HeaderT> From<DigestError> for ImportError<Header> {
    fn from(error: DigestError) -> Self {
        ImportError::DigestExtractionError(error)
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
        if header.number() <= self.store.finalized_header().header.number() {
            return Err(ImportError::HeaderIsBelowArchivingDepth);
        }

        // fetch parent header
        let parent_header = self
            .store
            .header(*header.parent_hash())
            .ok_or_else(|| ImportError::MissingParent(header.hash()))?;

        // TODO(ved): check for farmer equivocation

        // verify global randomness, solution range, and salt from the parent header
        let SubspaceDigestItems {
            pre_digest,
            signature: _,
            global_randomness,
            solution_range,
            salt,
            next_global_randomness: _,
            next_solution_range: _,
            next_salt: _,
            records_roots: _,
        } = Self::verify_header_digest_with_parent(&parent_header, &header)?;

        // slot must be strictly increasing from the parent header
        Self::verify_slot(&parent_header.header, &pre_digest)?;

        // verify block signature
        Self::verify_block_signature(&mut header, &pre_digest.solution.public_key)?;

        // verify solution
        verify_solution(
            &pre_digest.solution,
            pre_digest.slot.into(),
            VerifySolutionParams {
                global_randomness: &global_randomness,
                solution_range,
                salt,
                // TODO(ved): verify POAS once we have access to record root
                piece_check_params: None,
            },
        )
        .map_err(ImportError::InvalidSolution)?;

        let block_weight = Self::calculate_block_weight(&global_randomness, &pre_digest);
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

        // TODO(ved): derive randomness, solution range, salt if interval is met
        // TODO(ved): extract record roots from the header
        // TODO(ved); extract an equivocations from the header

        // store header
        let header_ext = HeaderExt {
            header,
            derived_global_randomness: global_randomness,
            derived_solution_range: solution_range,
            derived_salt: salt,
            total_weight,
        };

        self.store.store_header(header_ext, is_best_header);

        // finalize and prune forks if the chain has progressed
        if is_best_header {
            self.finalize_header_at_k_depth()?;
        }

        Ok(())
    }

    /// Verifies if the header digests matches with logs from the parent header.
    fn verify_header_digest_with_parent(
        parent_header: &HeaderExt<Header>,
        header: &Header,
    ) -> Result<
        SubspaceDigestItems<FarmerPublicKey, FarmerPublicKey, FarmerSignature>,
        ImportError<Header>,
    > {
        let pre_digest_items = extract_subspace_digest_items(header)?;
        if pre_digest_items.global_randomness != parent_header.derived_global_randomness {
            return Err(ImportError::InvalidDigest(
                ErrorDigestType::GlobalRandomness,
            ));
        }

        if pre_digest_items.solution_range != parent_header.derived_solution_range {
            return Err(ImportError::InvalidDigest(ErrorDigestType::SolutionRange));
        }

        if pre_digest_items.salt != parent_header.derived_salt {
            return Err(ImportError::InvalidDigest(ErrorDigestType::Salt));
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
        let seal = header
            .digest_mut()
            .pop()
            .ok_or(ImportError::DigestExtractionError(DigestError::Missing(
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
            &Into::<RewardSignature>::into(&signature),
            &Into::<PublicKey>::into(public_key),
            &schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT),
        )
        .map_err(|_| ImportError::InvalidBlockSignature)?;

        // push the seal back into the header
        header.digest_mut().push(seal);
        Ok(())
    }

    /// Calculates block weight from randomness and predigest.
    fn calculate_block_weight(
        global_randomness: &Randomness,
        pre_digest: &PreDigest<FarmerPublicKey, FarmerPublicKey>,
    ) -> BlockWeight {
        let global_challenge = derive_global_challenge(global_randomness, pre_digest.slot.into());

        let target = u64::from_be_bytes(
            derive_target(
                &schnorrkel::PublicKey::from_bytes(pre_digest.solution.public_key.as_ref())
                    .expect("Always correct length; qed"),
                global_challenge,
                &pre_digest.solution.local_challenge,
            )
            .expect("Verification of the local challenge was done before this; qed"),
        );
        let tag = u64::from_be_bytes(pre_digest.solution.tag);
        u128::from(u64::MAX - subspace_core_primitives::bidirectional_distance(&target, &tag))
    }

    /// Returns the ancestor of the header at number.
    fn find_ancestor_of_header_at_number(
        &self,
        header: HeaderExt<Header>,
        ancestor_number: NumberOf<Header>,
    ) -> Option<HeaderExt<Header>> {
        // header number must be greater than the ancestor number
        if ancestor_number >= *header.header.number() {
            return None;
        }

        let headers_at_ancestor_number = self.store.headers_at_number(ancestor_number);
        let finalized_header = self.store.finalized_header();

        // short circuit if the ancestor number is at the same or lower number than finalized head
        if ancestor_number.le(finalized_header.header.number())
            // short circuit if there are no forks at the depth
            || headers_at_ancestor_number.len() == 1
        {
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
                    let number_to_finalize = current_finalized_number
                        .checked_add(&One::one())
                        .ok_or(ImportError::ArithmeticError(ArithmeticError::Overflow))?;

                    // find the headers at the number to be finalized
                    let headers_at_number_to_be_finalized =
                        self.store.headers_at_number(number_to_finalize);
                    // if there is just one header at that number, we mark that header as finalized and move one
                    if headers_at_number_to_be_finalized.len() == 1 {
                        let header_to_finalize = headers_at_number_to_be_finalized
                            .into_iter()
                            .next()
                            .expect("Safe to unwrap because of the check above.");

                        self.store.finalize_header(header_to_finalize.header.hash());
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
                                current_best_header,
                                number_to_finalize,
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
                        self.store.finalize_header(header_to_finalize.header.hash())
                    }

                    current_finalized_number = number_to_finalize;
                }

                Ok(())
            }
        }
    }
}

use codec::{Decode, Encode};
use finality_grandpa::voter_set::VoterSet;
use frame_support::Parameter;
use frame_support::RuntimeDebug;
use num_traits::AsPrimitive;
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_finality_grandpa::{AuthorityId, AuthorityList, AuthoritySignature, SetId};
use sp_runtime::traits::{
    AtLeast32BitUnsigned, Hash as HashT, Header as HeaderT, MaybeDisplay, MaybeMallocSizeOf,
    MaybeSerializeDeserialize, Member, Saturating, SimpleBitOps, Verify,
};
use sp_std::collections::{btree_map::BTreeMap, btree_set::BTreeSet};
use sp_std::prelude::*;
use sp_std::{hash::Hash, str::FromStr, vec::Vec};

/// Minimal Substrate-based chain representation that may be used from no_std environment.
pub trait Chain: Send + Sync + 'static {
    /// A type that fulfills the abstract idea of what a Substrate block number is.
    // Constraits come from the associated Number type of `sp_runtime::traits::Header`
    // See here for more info:
    // https://crates.parity.io/sp_runtime/traits/trait.Header.html#associatedtype.Number
    //
    // Note that the `AsPrimitive<usize>` trait is required by the GRANDPA justification
    // verifier, and is not usually part of a Substrate Header's Number type.
    type BlockNumber: Parameter
        + Member
        + MaybeSerializeDeserialize
        + Hash
        + Copy
        + Default
        + MaybeDisplay
        + AtLeast32BitUnsigned
        + FromStr
        + MaybeMallocSizeOf
        + AsPrimitive<usize>
        + Default
        + Saturating
        // original `sp_runtime::traits::Header::BlockNumber` doesn't have this trait, but
        // `sp_runtime::generic::Era` requires block number -> `u64` conversion.
        + Into<u64>;

    /// A type that fulfills the abstract idea of what a Substrate hash is.
    // Constraits come from the associated Hash type of `sp_runtime::traits::Header`
    // See here for more info:
    // https://crates.parity.io/sp_runtime/traits/trait.Header.html#associatedtype.Hash
    type Hash: Parameter
        + Member
        + MaybeSerializeDeserialize
        + Hash
        + Ord
        + Copy
        + MaybeDisplay
        + Default
        + SimpleBitOps
        + AsRef<[u8]>
        + AsMut<[u8]>
        + MaybeMallocSizeOf;

    /// A type that fulfills the abstract idea of what a Substrate hasher (a type
    /// that produces hashes) is.
    // Constraits come from the associated Hashing type of `sp_runtime::traits::Header`
    // See here for more info:
    // https://crates.parity.io/sp_runtime/traits/trait.Header.html#associatedtype.Hashing
    type Hasher: HashT<Output = Self::Hash>;

    /// A type that fulfills the abstract idea of what a Substrate header is.
    // See here for more info:
    // https://crates.parity.io/sp_runtime/traits/trait.Header.html
    type Header: Parameter
        + HeaderT<Number = Self::BlockNumber, Hash = Self::Hash>
        + MaybeSerializeDeserialize;

    /// Signature type, used on this chain.
    type Signature: Parameter + Verify;
}

/// Block number used by the chain.
pub type BlockNumberOf<C> = <C as Chain>::BlockNumber;

/// Hash type used by the chain.
pub type HashOf<C> = <C as Chain>::Hash;

/// Hasher type used by the chain.
pub type HasherOf<C> = <C as Chain>::Hasher;

/// Header type used by the chain.
pub type HeaderOf<C> = <C as Chain>::Header;

/// A GRANDPA Justification is a proof that a given header was finalized
/// at a certain height and with a certain set of authorities.
///
/// This particular proof is used to prove that headers on a bridged chain
/// (so not our chain) have been finalized correctly.
#[derive(Encode, Decode, RuntimeDebug, Clone, PartialEq, Eq, TypeInfo)]
pub struct GrandpaJustification<Header: HeaderT> {
    /// The round (voting period) this justification is valid for.
    pub round: u64,
    /// The set of votes for the chain which is to be finalized.
    pub commit:
        finality_grandpa::Commit<Header::Hash, Header::Number, AuthoritySignature, AuthorityId>,
    /// A proof that the chain of blocks in the commit are related to each other.
    pub votes_ancestries: Vec<Header>,
}

/// A GRANDPA Authority List and ID.
#[derive(Default, Encode, Decode, RuntimeDebug, PartialEq, Clone, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct AuthoritySet {
    /// List of GRANDPA authorities for the current round.
    pub authorities: AuthorityList,
    /// Monotonic identifier of the current GRANDPA authority set.
    pub set_id: SetId,
}

/// Votes ancestries with useful methods.
#[derive(RuntimeDebug)]
pub struct AncestryChain<Header: HeaderT> {
    /// Header hash => parent header hash mapping.
    pub parents: BTreeMap<Header::Hash, Header::Hash>,
    /// Hashes of headers that were not visited by `is_ancestor` method.
    pub unvisited: BTreeSet<Header::Hash>,
}

impl<Header: HeaderT> AncestryChain<Header> {
    /// Create new ancestry chain.
    fn new(ancestry: &[Header]) -> AncestryChain<Header> {
        let mut parents = BTreeMap::new();
        let mut unvisited = BTreeSet::new();
        for ancestor in ancestry {
            let hash = ancestor.hash();
            let parent_hash = *ancestor.parent_hash();
            parents.insert(hash, parent_hash);
            unvisited.insert(hash);
        }
        AncestryChain { parents, unvisited }
    }

    /// Returns `Ok(_)` if `precommit_target` is a descendant of the `commit_target` block and
    /// `Err(_)` otherwise.
    fn ensure_descendant(
        mut self,
        commit_target: &Header::Hash,
        precommit_target: &Header::Hash,
    ) -> Result<Self, Error> {
        let mut current_hash = *precommit_target;
        loop {
            if current_hash == *commit_target {
                break;
            }

            let is_visited_before = !self.unvisited.remove(&current_hash);
            current_hash = match self.parents.get(&current_hash) {
                Some(parent_hash) => {
                    if is_visited_before {
                        // `Some(parent_hash)` means that the `current_hash` is in the `parents`
                        // container `is_visited_before` means that it has been visited before in
                        // some of previous calls => since we assume that previous call has finished
                        // with `true`, this also will be finished with `true`
                        return Ok(self);
                    }

                    *parent_hash
                }
                None => return Err(Error::PrecommitIsNotCommitDescendant),
            };
        }
        Ok(self)
    }
}

/// Justification verification error.
#[derive(RuntimeDebug, PartialEq)]
pub enum Error {
    /// Failed to decode justification.
    JustificationDecode,
    /// Justification is finalizing unexpected header.
    InvalidJustificationTarget,
    /// The authority has provided an invalid signature.
    InvalidAuthoritySignature,
    /// The justification contains precommit for header that is not a descendant of the commit
    /// header.
    PrecommitIsNotCommitDescendant,
    /// The cumulative weight of all votes in the justification is not enough to justify commit
    /// header finalization.
    TooLowCumulativeWeight,
    /// The justification contains extra (unused) headers in its `votes_ancestries` field.
    ExtraHeadersInVotesAncestries,
}

/// Verify that justification, that is generated by given authority set, finalizes given header.
pub fn verify_justification<Header: HeaderT>(
    finalized_target: (Header::Hash, Header::Number),
    authorities_set_id: SetId,
    authorities_set: &VoterSet<AuthorityId>,
    justification: &GrandpaJustification<Header>,
) -> Result<(), Error>
where
    Header::Number: finality_grandpa::BlockNumberOps,
{
    // ensure that it is justification for the expected header
    if (
        justification.commit.target_hash,
        justification.commit.target_number,
    ) != finalized_target
    {
        return Err(Error::InvalidJustificationTarget);
    }

    let mut chain = AncestryChain::new(&justification.votes_ancestries);
    let mut signature_buffer = Vec::new();
    let mut votes = BTreeSet::new();
    let mut cumulative_weight = 0u64;
    for signed in &justification.commit.precommits {
        // authority must be in the set
        let authority_info = match authorities_set.get(&signed.id) {
            Some(authority_info) => authority_info,
            None => {
                // just ignore precommit from unknown authority as
                // `finality_grandpa::import_precommit` does
                continue;
            }
        };

        // check if authority has already voted in the same round.
        //
        // there's a lot of code in `validate_commit` and `import_precommit` functions inside
        // `finality-grandpa` crate (mostly related to reporting equivocations). But the only thing
        // that we care about is that only first vote from the authority is accepted
        if !votes.insert(signed.id.clone()) {
            continue;
        }

        // everything below this line can't just `continue`, because state is already altered

        // precommits aren't allowed for block lower than the target
        if signed.precommit.target_number < justification.commit.target_number {
            return Err(Error::PrecommitIsNotCommitDescendant);
        }
        // all precommits must be descendants of target block
        chain = chain.ensure_descendant(
            &justification.commit.target_hash,
            &signed.precommit.target_hash,
        )?;
        // since we know now that the precommit target is the descendant of the justification
        // target, we may increase 'weight' of the justification target
        //
        // there's a lot of code in the `VoteGraph::insert` method inside `finality-grandpa` crate,
        // but in the end it is only used to find GHOST, which we don't care about. The only thing
        // that we care about is that the justification target has enough weight
        cumulative_weight = cumulative_weight.checked_add(authority_info.weight().0.into()).expect(
            "sum of weights of ALL authorities is expected not to overflow - this is guaranteed by\
				existence of VoterSet;\
				the order of loop conditions guarantees that we can account vote from same authority\
				multiple times;\
				thus we'll never overflow the u64::MAX;\
				qed",
        );
        // verify authority signature
        if !sp_finality_grandpa::check_message_signature_with_buffer(
            &finality_grandpa::Message::Precommit(signed.precommit.clone()),
            &signed.id,
            &signed.signature,
            justification.round,
            authorities_set_id,
            &mut signature_buffer,
        ) {
            return Err(Error::InvalidAuthoritySignature);
        }
    }

    // check that there are no extra headers in the justification
    if !chain.unvisited.is_empty() {
        return Err(Error::ExtraHeadersInVotesAncestries);
    }

    // check that the cumulative weight of validators voted for the justification target (or one
    // of its descendents) is larger than required threshold.
    let threshold = authorities_set.threshold().0.into();
    if cumulative_weight >= threshold {
        Ok(())
    } else {
        Err(Error::TooLowCumulativeWeight)
    }
}

use codec::{Decode, Encode};
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
use sp_std::prelude::*;
use sp_std::{hash::Hash, str::FromStr, vec, vec::Vec};

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

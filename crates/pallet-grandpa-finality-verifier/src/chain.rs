use super::*;
use frame_support::Parameter;
use num_traits::AsPrimitive;
use sp_core::Hasher as HasherT;
use sp_runtime::generic;
use sp_runtime::traits::BlakeTwo256;
use sp_runtime::traits::{
    AtLeast32BitUnsigned, Hash as HashT, Header as HeaderT, MaybeDisplay, MaybeMallocSizeOf,
    MaybeSerializeDeserialize, Member, Saturating, SimpleBitOps,
};
use sp_std::{hash::Hash, str::FromStr};

// ChainType represents the kind of the Chain type we are verifying the GRANDPA finality for
#[derive(Encode, Decode, TypeInfo)]
pub(crate) enum ChainType {
    PolkadotLike,
}

/// Polkadot-like chain.
struct PolkadotLike;

impl Chain for PolkadotLike {
    type BlockNumber = u32;
    type Hash = <BlakeTwo256 as HasherT>::Out;
    type Hasher = BlakeTwo256;
    type Header = generic::Header<u32, BlakeTwo256>;
}

/// Minimal Substrate-based chain representation that may be used from no_std environment.
pub trait Chain {
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
}

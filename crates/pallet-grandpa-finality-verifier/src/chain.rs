use crate::{grandpa::GrandpaJustification, Config, Error};
use codec::Decode;
use frame_support::Parameter;
use num_traits::AsPrimitive;
use sp_runtime::{
    generic,
    traits::{
        AtLeast32BitUnsigned, Header as HeaderT, MaybeDisplay, MaybeMallocSizeOf,
        MaybeSerializeDeserialize, Member, Saturating, SimpleBitOps,
    },
    OpaqueExtrinsic,
};
use sp_std::{hash::Hash, str::FromStr};

pub type SignedBlock<Header> = generic::SignedBlock<generic::Block<Header, OpaqueExtrinsic>>;

/// Minimal Substrate-based chain representation that may be used from no_std environment.
pub trait Chain {
    /// A type that fulfills the abstract idea of what a Substrate block number is.
    // Constraints come from the associated Number type of `sp_runtime::traits::Header`
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
    // Constraints come from the associated Hash type of `sp_runtime::traits::Header`
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
        + MaybeMallocSizeOf
        // since we want to use the hash as a key in DSN,
        // we need the target chain to use Hash out length to be 32
        + Into<[u8; 32]>;

    /// A type that fulfills the abstract idea of what a Substrate header is.
    // See here for more info:
    // https://crates.parity.io/sp_runtime/traits/trait.Header.html
    type Header: Parameter
        + HeaderT<Number = Self::BlockNumber, Hash = Self::Hash>
        + MaybeSerializeDeserialize;

    fn decode_block<T: Config>(block: &[u8]) -> Result<SignedBlock<Self::Header>, Error<T>> {
        SignedBlock::<Self::Header>::decode(&mut &*block).map_err(|error| {
            log::error!("Cannot decode block, error: {:?}", error);
            Error::<T>::FailedDecodingBlock
        })
    }

    fn decode_header<T: Config>(header: &[u8]) -> Result<Self::Header, Error<T>> {
        Self::Header::decode(&mut &*header).map_err(|error| {
            log::error!("Cannot decode header, error: {:?}", error);
            Error::<T>::FailedDecodingHeader
        })
    }

    fn decode_grandpa_justifications<T: Config>(
        justifications: &[u8],
    ) -> Result<GrandpaJustification<Self::Header>, Error<T>> {
        GrandpaJustification::<Self::Header>::decode(&mut &*justifications).map_err(|error| {
            log::error!("Cannot decode justifications, error: {:?}", error);
            Error::<T>::FailedDecodingJustifications
        })
    }
}

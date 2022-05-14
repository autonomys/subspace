use crate::{grandpa::GrandpaJustification, Config, EncodedBlockHash, EncodedBlockNumber, Error};
use codec::Decode;
use frame_support::Parameter;
use num_traits::AsPrimitive;
use sp_runtime::{
    generic,
    traits::{
        AtLeast32BitUnsigned, Hash as HashT, Header as HeaderT, MaybeDisplay, MaybeMallocSizeOf,
        MaybeSerializeDeserialize, Member, Saturating, SimpleBitOps,
    },
};
use sp_std::{hash::Hash, str::FromStr, vec::Vec};

pub(crate) type OpaqueExtrinsic = Vec<u8>;
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
        + Saturating;

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
        + MaybeMallocSizeOf;

    /// A type that fulfills the abstract idea of what a Substrate header is.
    // See here for more info:
    // https://crates.parity.io/sp_runtime/traits/trait.Header.html
    type Header: Parameter
        + HeaderT<Number = Self::BlockNumber, Hash = Self::Hash>
        + MaybeSerializeDeserialize;

    /// A type that fulfills the abstract idea of what a Substrate hasher (a type
    /// that produces hashes) is.
    // Constraints come from the associated Hashing type of `sp_runtime::traits::Header`
    // See here for more info:
    // https://crates.parity.io/sp_runtime/traits/trait.Header.html#associatedtype.Hashing
    type Hasher: HashT<Output = Self::Hash>;

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

    fn decode_block_number_and_hash<T: Config>(
        pair: (EncodedBlockNumber, EncodedBlockHash),
    ) -> Result<(Self::BlockNumber, Self::Hash), Error<T>> {
        let number = Self::decode_block_number::<T>(pair.0.as_slice())?;
        let hash = Self::decode_block_hash::<T>(pair.1.as_slice())?;
        Ok((number, hash))
    }

    fn decode_block_number<T: Config>(number: &[u8]) -> Result<Self::BlockNumber, Error<T>> {
        Self::BlockNumber::decode(&mut &*number).map_err(|error| {
            log::error!("Cannot decode block number, error: {:?}", error);
            Error::<T>::FailedDecodingBlockNumber
        })
    }

    fn decode_block_hash<T: Config>(hash: &[u8]) -> Result<Self::Hash, Error<T>> {
        Self::Hash::decode(&mut &*hash).map_err(|error| {
            log::error!("Cannot decode block hash, error: {:?}", error);
            Error::<T>::FailedDecodingBlockHash
        })
    }
}

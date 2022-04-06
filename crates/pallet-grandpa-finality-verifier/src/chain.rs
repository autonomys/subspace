use crate::{
    grandpa::{verify_justification, AuthoritySet, GrandpaJustification},
    Config, Error,
};
use codec::Decode;
use finality_grandpa::voter_set::VoterSet;
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

type SignedBlock<Header> = generic::SignedBlock<generic::Block<Header, OpaqueExtrinsic>>;

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

    /// Verify a GRANDPA justification (finality proof) for a given header.
    ///
    /// Will use the GRANDPA current authorities known to the pallet.
    ///
    /// If successful it returns the decoded GRANDPA justification so we can refund any weight which
    /// was overcharged in the initial call.
    fn verify_justification<T: Config>(
        justification: &GrandpaJustification<Self::Header>,
        hash: Self::Hash,
        number: Self::BlockNumber,
        authority_set: AuthoritySet,
    ) -> Result<(), Error<T>> {
        let voter_set =
            VoterSet::new(authority_set.authorities).ok_or(Error::<T>::InvalidAuthoritySet)?;
        let set_id = authority_set.set_id;
        verify_justification::<Self::Header>((hash, number), set_id, &voter_set, justification)
            .map_err(|e| {
                log::error!(
                    target: "runtime::grandpa-finality-verifier",
                    "Received invalid justification for {:?}: {:?}",
                    hash,
                    e,
                );
                Error::<T>::InvalidJustification
            })
    }

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

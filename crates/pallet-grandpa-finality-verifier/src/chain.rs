use super::*;
use crate::grandpa::{verify_justification, AuthoritySet, GrandpaJustification};
use finality_grandpa::voter_set::VoterSet;
use frame_support::Parameter;
use num_traits::AsPrimitive;
use sp_core::Hasher as HasherT;
use sp_runtime::traits::BlakeTwo256;
use sp_runtime::traits::{
    AtLeast32BitUnsigned, Header as HeaderT, MaybeDisplay, MaybeMallocSizeOf,
    MaybeSerializeDeserialize, Member, Saturating, SimpleBitOps,
};
use sp_runtime::{generic, OpaqueExtrinsic};
use sp_std::{hash::Hash, str::FromStr, vec::Vec};

// ChainType represents the kind of the Chain type we are verifying the GRANDPA finality for
#[derive(Encode, Decode, TypeInfo)]
pub(crate) enum ChainType {
    PolkadotLike,
}

/// Polkadot-like chain.
pub(crate) struct PolkadotLike;

impl Chain for PolkadotLike {
    type BlockNumber = u32;
    type Hash = <BlakeTwo256 as HasherT>::Out;
    type Header = generic::Header<u32, BlakeTwo256>;
}

type SignedBlock<Header> = generic::SignedBlock<generic::Block<Header, OpaqueExtrinsic>>;

/// Finality for block B is proved by providing:
/// 1) the justification for the descendant block F;
/// 2) headers sub-chain (B; F] if B != F;
#[derive(Debug, PartialEq, Encode, Decode, Clone)]
pub(crate) struct FinalityProof<Header: HeaderT> {
    /// The hash of block F for which justification is provided.
    pub block: Header::Hash,
    /// Justification of the block F.
    pub justification: Vec<u8>,
    /// The set of headers in the range (B; F] that we believe are unknown to the caller. Ordered.
    pub unknown_headers: Vec<Header>,
}

/// Minimal Substrate-based chain representation that may be used from no_std environment.
pub(crate) trait Chain {
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

    fn decode_finality_proof<T: Config>(
        proof: &[u8],
    ) -> Result<FinalityProof<Self::Header>, Error<T>> {
        FinalityProof::<Self::Header>::decode(&mut &*proof).map_err(|error| {
            log::error!("Cannot decode finality proof, error: {:?}", error);
            Error::<T>::FailedDecodingFinalityProof
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

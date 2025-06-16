//! Weights for pallet-messenger extensions

use core::marker::PhantomData;
use frame_support::pallet_prelude::Weight;

/// Weight functions needed for pallet messenger extension.
pub trait WeightInfo: FromConsensusWeightInfo + FromDomainWeightInfo {
    fn mmr_proof_verification_on_consensus() -> Weight;
    fn mmr_proof_verification_on_domain() -> Weight;
}

pub trait FromConsensusWeightInfo {
    fn from_consensus_relay_message_channel_open() -> Weight;
    fn from_consensus_relay_message() -> Weight;
    fn from_consensus_relay_message_response() -> Weight;
}

impl FromConsensusWeightInfo for () {
    fn from_consensus_relay_message_channel_open() -> Weight {
        Weight::zero()
    }
    fn from_consensus_relay_message() -> Weight {
        Weight::zero()
    }
    fn from_consensus_relay_message_response() -> Weight {
        Weight::zero()
    }
}

pub trait FromDomainWeightInfo {
    fn from_domains_relay_message_channel_open() -> Weight;
    fn from_domains_relay_message() -> Weight;
    fn from_domains_relay_message_response() -> Weight;
}

impl FromDomainWeightInfo for () {
    fn from_domains_relay_message_channel_open() -> Weight {
        Weight::zero()
    }
    fn from_domains_relay_message() -> Weight {
        Weight::zero()
    }
    fn from_domains_relay_message_response() -> Weight {
        Weight::zero()
    }
}

/// Weight functions for `pallet_messenger_extension`.
pub struct SubstrateWeight<T, C, D>(PhantomData<(T, C, D)>);

impl<T: frame_system::Config, C: FromConsensusWeightInfo, D> FromConsensusWeightInfo
    for SubstrateWeight<T, C, D>
{
    fn from_consensus_relay_message_channel_open() -> Weight {
        C::from_consensus_relay_message_channel_open()
    }

    fn from_consensus_relay_message() -> Weight {
        C::from_consensus_relay_message()
    }

    fn from_consensus_relay_message_response() -> Weight {
        C::from_consensus_relay_message_response()
    }
}

impl<T: frame_system::Config, C, D: FromDomainWeightInfo> FromDomainWeightInfo
    for SubstrateWeight<T, C, D>
{
    fn from_domains_relay_message_channel_open() -> Weight {
        D::from_domains_relay_message_channel_open()
    }

    fn from_domains_relay_message() -> Weight {
        D::from_domains_relay_message()
    }

    fn from_domains_relay_message_response() -> Weight {
        D::from_domains_relay_message_response()
    }
}

impl<T: frame_system::Config, C: FromConsensusWeightInfo, D: FromDomainWeightInfo> WeightInfo
    for SubstrateWeight<T, C, D>
{
    fn mmr_proof_verification_on_consensus() -> Weight {
        // Execution time to verify a given MMR proof on consensus chain
        // is around 153_000_000 pico seconds
        Weight::from_parts(153_000_000, 0)
    }

    fn mmr_proof_verification_on_domain() -> Weight {
        // Execution time to verify a given MMR proof on domain chain
        // using a host function is around 595_000_000 pico seconds
        Weight::from_parts(595_000_000, 0)
    }
}

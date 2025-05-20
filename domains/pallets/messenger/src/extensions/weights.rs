//! Weights for pallet-messenger extensions

use crate::extensions::weights_from_consensus::WeightInfo as WeightsFromConsensus;
use crate::extensions::weights_from_domains::WeightInfo as WeightsFromDomains;
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

pub trait FromDomainWeightInfo {
    fn from_domains_relay_message_channel_open() -> Weight;
    fn from_domains_relay_message() -> Weight;
    fn from_domains_relay_message_response() -> Weight;
}

/// Weight functions for `pallet_messenger_extension`.
pub struct SubstrateWeight<T>(PhantomData<T>);

impl<T: frame_system::Config> FromConsensusWeightInfo for SubstrateWeight<T> {
    fn from_consensus_relay_message_channel_open() -> Weight {
        WeightsFromConsensus::<T>::from_consensus_relay_message_channel_open()
    }

    fn from_consensus_relay_message() -> Weight {
        WeightsFromConsensus::<T>::from_consensus_relay_message()
    }

    fn from_consensus_relay_message_response() -> Weight {
        WeightsFromConsensus::<T>::from_consensus_relay_message_response()
    }
}

impl<T: frame_system::Config> FromDomainWeightInfo for SubstrateWeight<T> {
    fn from_domains_relay_message_channel_open() -> Weight {
        WeightsFromDomains::<T>::from_domains_relay_message_channel_open()
    }

    fn from_domains_relay_message() -> Weight {
        WeightsFromDomains::<T>::from_domains_relay_message()
    }

    fn from_domains_relay_message_response() -> Weight {
        WeightsFromDomains::<T>::from_domains_relay_message_response()
    }
}

impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
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

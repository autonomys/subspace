use frame_support::traits::Get;
use sc_network::config::MultiaddrWithPeerId;
use sc_service::Properties;
use sp_core::crypto::AccountId32;
use sp_core::{Pair, Public, sr25519};
use sp_domains::DomainId;
use sp_runtime::MultiSigner;
use sp_runtime::traits::IdentifyAccount;
use std::collections::HashMap;
use subspace_runtime::SS58Prefix;
use subspace_runtime_primitives::DECIMAL_PLACES;

/// Shared chain spec properties related to the coin.
pub(crate) fn chain_spec_properties() -> Properties {
    let mut properties = Properties::new();

    properties.insert("dsnBootstrapNodes".to_string(), Vec::<String>::new().into());
    properties.insert(
        "ss58Format".to_string(),
        <SS58Prefix as Get<u16>>::get().into(),
    );
    properties.insert("tokenDecimals".to_string(), DECIMAL_PLACES.into());
    properties.insert("tokenSymbol".to_string(), "AI3".into());
    properties.insert(
        "domainsBootstrapNodes".to_string(),
        serde_json::to_value(HashMap::<DomainId, Vec<MultiaddrWithPeerId>>::new())
            .expect("Serialization is infallible; qed"),
    );

    properties
}

/// Get public key from keypair seed.
pub(crate) fn get_public_key_from_seed<TPublic: Public>(
    seed: &'static str,
) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{seed}"), None)
        .expect("Static values are valid; qed")
        .public()
}

/// Generate an account ID from seed.
pub(crate) fn get_account_id_from_seed(seed: &'static str) -> AccountId32 {
    MultiSigner::from(get_public_key_from_seed::<sr25519::Public>(seed)).into_account()
}

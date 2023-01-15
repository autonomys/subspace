use frame_support::traits::Get;
use sc_service::Properties;
use sp_core::crypto::AccountId32;
use sp_core::{sr25519, Pair, Public};
use sp_runtime::traits::IdentifyAccount;
use sp_runtime::MultiSigner;
use subspace_runtime::SS58Prefix;
use subspace_runtime_primitives::DECIMAL_PLACES;

/// Shared chain spec properties related to the coin.
pub(crate) fn chain_spec_properties() -> Properties {
    let mut properties = Properties::new();

    properties.insert("ss58Format".into(), <SS58Prefix as Get<u16>>::get().into());
    properties.insert("tokenDecimals".into(), DECIMAL_PLACES.into());
    properties.insert("tokenSymbol".into(), "tSSC".into());

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

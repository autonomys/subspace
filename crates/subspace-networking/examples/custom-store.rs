use libp2p::identity::ed25519::Keypair;
use libp2p::kad::record::Key;
use libp2p::kad::ProviderRecord;
use libp2p::PeerId;
use std::collections::HashSet;
use subspace_networking::{peer_id, ParityDbProviderStorage, ProviderStorage};
use tempfile::TempDir;

#[allow(clippy::mutable_key_type)] // we use hash set for sorting to compare collections
fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let db_path = TempDir::new()
        .expect("We should be able to crate temp directory.")
        .path()
        .join("subspace_example_custom_provider_storage_db")
        .into_boxed_path();

    let keypair = Keypair::generate();
    let local_peer_id = peer_id(&libp2p::identity::Keypair::Ed25519(keypair));

    let mut provider_storage = ParityDbProviderStorage::new(&db_path, local_peer_id)
        .expect("Provider storage DB path should be valid.");

    let key1: Key = b"key1".to_vec().into();
    let provider1 = PeerId::random();
    let rec1 = ProviderRecord {
        provider: provider1,
        key: key1,
        expires: None,
        addresses: Vec::new(),
    };

    let key2: Key = b"key2".to_vec().into();
    let provider2 = local_peer_id;
    let rec2 = ProviderRecord {
        provider: provider2,
        key: key2.clone(),
        expires: None,
        addresses: Vec::new(),
    };

    let provider3 = PeerId::random();
    let rec3 = ProviderRecord {
        provider: provider3,
        key: key2.clone(),
        expires: None,
        addresses: Vec::new(),
    };

    // Check adding
    provider_storage.add_provider(rec1).unwrap();
    provider_storage.add_provider(rec2.clone()).unwrap();
    provider_storage.add_provider(rec3.clone()).unwrap();

    // Check local providers retrieval
    let provided_collection: HashSet<ProviderRecord> =
        HashSet::from_iter(provider_storage.provided().map(|i| i.into_owned()));

    assert_eq!(
        HashSet::from_iter(vec![rec2.clone()].into_iter()),
        provided_collection
    );

    // Check single provider retrieval
    let provided_collection: HashSet<ProviderRecord> =
        HashSet::from_iter(provider_storage.providers(&key2).into_iter());

    assert_eq!(
        HashSet::from_iter(vec![rec2.clone(), rec3].into_iter()),
        provided_collection
    );

    // Remove provider
    provider_storage.remove_provider(&key2, &provider3);
    let provided_collection: HashSet<ProviderRecord> =
        HashSet::from_iter(provider_storage.providers(&key2).into_iter());

    assert_eq!(
        HashSet::from_iter(vec![rec2].into_iter()),
        provided_collection
    );

    Ok(())
}

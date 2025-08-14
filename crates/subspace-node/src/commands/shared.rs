use clap::Parser;
use sc_cli::Error;
use sc_keystore::LocalKeystore;
use sp_core::Pair as PairT;
use sp_core::crypto::{ExposeSecret, SecretString};
use sp_core::sr25519::Pair;
use sp_domains::KEY_TYPE;
use sp_keystore::Keystore;
use std::path::PathBuf;

/// Options used for keystore
#[derive(Debug, Parser)]
pub(super) struct KeystoreOptions {
    /// Use interactive shell for entering the password used by the keystore.
    #[arg(long, conflicts_with_all = &["keystore_password", "keystore_password_filename"])]
    pub(super) keystore_password_interactive: bool,
    /// Password used by the keystore. This allows appending an extra user-defined secret to the
    /// seed.
    #[arg(long, conflicts_with_all = &["keystore_password_interactive", "keystore_password_filename"])]
    pub(super) keystore_password: Option<SecretString>,
    /// File that contains the password used by the keystore.
    #[arg(long, conflicts_with_all = &["keystore_password_interactive", "keystore_password"])]
    pub(super) keystore_password_filename: Option<PathBuf>,
}

#[expect(clippy::result_large_err, reason = "Comes from Substrate")]
pub(super) fn derive_keypair(
    suri: &SecretString,
    password: &Option<SecretString>,
) -> Result<Pair, Error> {
    let keypair_result = Pair::from_string(
        suri.expose_secret(),
        password
            .as_ref()
            .map(|password| password.expose_secret().as_str()),
    );

    keypair_result.map_err(|err| Error::Input(format!("Invalid password {err:?}")))
}

#[expect(clippy::result_large_err, reason = "Comes from Substrate")]
pub(super) fn store_key_in_keystore(
    keystore_path: PathBuf,
    suri: &SecretString,
    password: Option<SecretString>,
) -> Result<(), Error> {
    let keypair = derive_keypair(suri, &password)?;

    LocalKeystore::open(keystore_path, password)?
        .insert(KEY_TYPE, suri.expose_secret(), &keypair.public())
        .map_err(|()| Error::Application("Failed to insert key into keystore".to_string().into()))
}

use clap::Parser;
use sc_cli::Error;
use sc_keystore::LocalKeystore;
use sp_core::crypto::{ExposeSecret, SecretString};
use sp_core::sr25519::Pair;
use sp_core::Pair as PairT;
use sp_domains::KEY_TYPE;
use sp_keystore::Keystore;
use std::panic;
use std::path::PathBuf;
use std::process::exit;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

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

    keypair_result.map_err(|err| Error::Input(format!("Invalid password {:?}", err)))
}

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

/// Install a panic handler which exits on panics, rather than unwinding. Unwinding can hang the
/// tokio runtime waiting for stuck tasks or threads.
pub(crate) fn set_exit_on_panic() {
    let default_panic_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        default_panic_hook(panic_info);
        exit(1);
    }));
}

pub(super) fn init_logger() {
    // TODO: Workaround for https://github.com/tokio-rs/tracing/issues/2214, also on
    //  Windows terminal doesn't support the same colors as bash does
    let enable_color = if cfg!(windows) {
        false
    } else {
        supports_color::on(supports_color::Stream::Stderr).is_some()
    };
    tracing_subscriber::registry()
        .with(
            fmt::layer().with_ansi(enable_color).with_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            ),
        )
        .init();
}

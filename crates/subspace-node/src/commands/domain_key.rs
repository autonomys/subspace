use crate::commands::shared::{derive_keypair, store_key_in_keystore, KeystoreOptions};
use bip39::Mnemonic;
use clap::Parser;
use sc_cli::{Error, KeystoreParams};
use sc_service::config::KeystoreConfig;
use sp_core::crypto::{ExposeSecret, SecretString};
use sp_core::Pair;
use sp_domains::DomainId;
use std::path::PathBuf;
use subspace_logging::init_logger;
use tracing::{info, warn};

/// Options for creating domain key
#[derive(Debug, Parser)]
pub struct CreateDomainKeyOptions {
    /// Base path where to store node files
    #[arg(long)]
    base_path: PathBuf,
    /// ID of the domain to store key for
    #[arg(long, required = true)]
    domain_id: DomainId,
    /// Options for domain keystore
    #[clap(flatten)]
    keystore_options: KeystoreOptions,
}

#[expect(clippy::result_large_err, reason = "Comes from Substrate")]
pub fn create_domain_key(options: CreateDomainKeyOptions) -> Result<(), Error> {
    init_logger();
    let CreateDomainKeyOptions {
        base_path,
        domain_id,
        keystore_options,
    } = options;
    let domain_path = base_path.join("domains").join(domain_id.to_string());

    let keystore_params = KeystoreParams {
        keystore_path: None,
        password_interactive: keystore_options.keystore_password_interactive,
        password: keystore_options.keystore_password,
        password_filename: keystore_options.keystore_password_filename,
    };

    let keystore_config = keystore_params.keystore_config(&domain_path)?;

    let (path, password) = match &keystore_config {
        KeystoreConfig::Path { path, password, .. } => (path.clone(), password.clone()),
        KeystoreConfig::InMemory => {
            unreachable!("Just constructed non-memory keystore config; qed");
        }
    };

    let has_password = password.is_some();

    let mnemonic = Mnemonic::generate(12)
        .map_err(|error| Error::Input(format!("Mnemonic generation failed: {error}")))?;
    let phrase = SecretString::from(mnemonic.to_string());

    let public_key = derive_keypair(&phrase, &password)?.public();

    store_key_in_keystore(path, &phrase, password)?;

    info!("Successfully generated and imported keypair!");
    info!("Public key: 0x{}", hex::encode(public_key.0));
    info!("Seed: \"{}\"", phrase.expose_secret());
    if has_password {
        info!("Password: as specified in CLI options");
    }
    warn!("⚠ Make sure to keep ^ seed secure and never share with anyone to avoid loss of funds ⚠");

    Ok(())
}

/// Options for inserting domain key
#[derive(Debug, Parser)]
pub struct InsertDomainKeyOptions {
    /// Base path where to store node files
    #[arg(long)]
    base_path: PathBuf,
    /// ID of the domain to store key for
    #[arg(long, required = true)]
    domain_id: DomainId,
    /// Operator secret key URI to insert into keystore.
    ///
    /// Example: "//Alice".
    ///
    /// If the value is a file, the file content is used as URI.
    #[arg(long, required = true)]
    keystore_suri: SecretString,
    /// Options for domain keystore
    #[clap(flatten)]
    keystore_options: KeystoreOptions,
}

#[expect(clippy::result_large_err, reason = "Comes from Substrate")]
pub fn insert_domain_key(options: InsertDomainKeyOptions) -> Result<(), Error> {
    init_logger();
    let InsertDomainKeyOptions {
        base_path,
        domain_id,
        keystore_suri,
        keystore_options,
    } = options;
    let domain_path = base_path.join("domains").join(domain_id.to_string());

    let keystore_params = KeystoreParams {
        keystore_path: None,
        password_interactive: keystore_options.keystore_password_interactive,
        password: keystore_options.keystore_password,
        password_filename: keystore_options.keystore_password_filename,
    };

    let keystore_config = keystore_params.keystore_config(&domain_path)?;

    let (path, password) = match &keystore_config {
        KeystoreConfig::Path { path, password, .. } => (path.clone(), password.clone()),
        KeystoreConfig::InMemory => {
            unreachable!("Just constructed non-memory keystore config; qed");
        }
    };

    store_key_in_keystore(path, &keystore_suri, password)?;

    info!("Success");

    Ok(())
}

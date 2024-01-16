use crate::commands::shared::{init_logger, store_key_in_keystore, KeystoreOptions};
use clap::Parser;
use sc_cli::{Error, KeystoreParams};
use sc_service::config::KeystoreConfig;
use sp_domains::DomainId;
use std::path::PathBuf;
use tracing::info;

/// Options for running a node
#[derive(Debug, Parser)]
pub struct InsertDomainKeyOptions {
    /// Base path where to store node files
    #[arg(long)]
    base_path: PathBuf,
    /// ID of the domain to store key for
    #[arg(long, required = true)]
    domain_id: DomainId,
    /// Options for domain keystore
    #[clap(flatten)]
    keystore_options: KeystoreOptions<true>,
}

pub fn insert_domain_key(options: InsertDomainKeyOptions) -> Result<(), Error> {
    init_logger();

    let InsertDomainKeyOptions {
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

    let Some(keystore_suri) = keystore_options.keystore_suri else {
        unreachable!("--keystore-suri is set to required; qed");
    };

    let (path, password) = match &keystore_config {
        KeystoreConfig::Path { path, password, .. } => (path.clone(), password.clone()),
        KeystoreConfig::InMemory => {
            unreachable!("Just constructed non-memory keystore config; qed");
        }
    };

    store_key_in_keystore(path, password, &keystore_suri)?;

    info!("Success");

    Ok(())
}

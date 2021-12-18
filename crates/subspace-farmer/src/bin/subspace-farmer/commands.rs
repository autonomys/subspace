mod farm;

use bip39::{Language, Mnemonic};
pub(crate) use farm::farm;
use log::info;
use sp_core::crypto::{Ss58AddressFormatRegistry, Ss58Codec, UncheckedFrom};
use sp_core::sr25519::Public;
use std::path::Path;
use std::{fs, io};
use subspace_farmer::Identity;

pub(crate) fn identity<P: AsRef<Path>>(
    path: P,
    address: bool,
    public_key: bool,
    mnemonic: bool,
) -> anyhow::Result<()> {
    let identity = match Identity::open(&path)? {
        Some(identity) => identity,
        None => {
            anyhow::bail!("Identity doesn't exist");
        }
    };

    let public = Public::unchecked_from(identity.public_key().to_bytes());

    if (false, false, false) == (address, public_key, mnemonic) || address {
        eprint!("Address:\n  ");

        println!(
            "{}",
            public.to_ss58check_with_version(
                Ss58AddressFormatRegistry::SubspaceTestnetAccount.into()
            )
        );
    }

    if public_key {
        eprint!("PublicKey:\n  ");

        println!("0x{}", hex::encode(public));
    }

    if mnemonic {
        eprint!("Mnemonic (NOTE: never share this with anyone!):\n  ");

        println!(
            "{}",
            Mnemonic::from_entropy(identity.entropy(), Language::English).unwrap()
        );
    }

    Ok(())
}

/// Helper function for ignoring the error that given file/directory does not exist.
fn try_remove<P: AsRef<Path>>(
    path: P,
    remove: impl FnOnce(P) -> std::io::Result<()>,
) -> io::Result<()> {
    if path.as_ref().exists() {
        remove(path)?;
    }
    Ok(())
}

pub(crate) fn erase_plot<P: AsRef<Path>>(path: P) -> io::Result<()> {
    info!("Erasing the plot");
    try_remove(path.as_ref().join("plot.bin"), fs::remove_file)?;
    info!("Erasing plot metadata");
    try_remove(path.as_ref().join("plot-metadata"), fs::remove_dir_all)?;
    info!("Erasing plot commitments");
    try_remove(path.as_ref().join("commitments"), fs::remove_dir_all)?;
    info!("Erasing object mappings");
    try_remove(path.as_ref().join("object-mappings"), fs::remove_dir_all)?;

    Ok(())
}

pub(crate) fn wipe<P: AsRef<Path>>(path: P) -> io::Result<()> {
    erase_plot(path.as_ref())?;

    info!("Erasing identity");
    try_remove(path.as_ref().join("identity.bin"), fs::remove_file)?;

    Ok(())
}

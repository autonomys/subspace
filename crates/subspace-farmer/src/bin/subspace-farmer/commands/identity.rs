use crate::{utils, IdentityCommand};
use anyhow::bail;
use bip39::{Language, Mnemonic};
use sp_core::crypto::{Ss58AddressFormatRegistry, Ss58Codec, UncheckedFrom};
use sp_core::sr25519::Public;
use std::path::Path;
use subspace_farmer::Identity;
use zeroize::Zeroize;

pub(crate) fn identity(identity_command: IdentityCommand) -> anyhow::Result<()> {
    match identity_command {
        IdentityCommand::View {
            address,
            public_key,
            mnemonic,
            custom_path,
        } => {
            let path = utils::get_path(custom_path);
            view(&path, address, public_key, mnemonic)
        }
        IdentityCommand::ImportFromMnemonic {
            mut phrase,
            custom_path,
        } => {
            let path = utils::get_path(custom_path);
            if Identity::open(&path)?.is_some() {
                bail!("Identity already exists, can't import!");
            }

            let result = Identity::import_from_mnemonic(path, &phrase).map(|_identity| ());
            phrase.zeroize();
            result
        }
    }
}

fn view<P: AsRef<Path>>(
    path: P,
    address: bool,
    public_key: bool,
    mnemonic: bool,
) -> anyhow::Result<()> {
    let identity = match Identity::open(&path)? {
        Some(identity) => identity,
        None => {
            bail!("Identity doesn't exist");
        }
    };

    let public = Public::unchecked_from(identity.public_key().to_bytes());

    if (false, false, false) == (address, public_key, mnemonic) || address {
        eprint!("Address (SS58 format):\n  ");

        println!(
            "{}",
            public.to_ss58check_with_version(
                Ss58AddressFormatRegistry::SubspaceTestnetAccount.into()
            )
        );
    }

    if public_key {
        eprint!("Public key (hex format):\n  ");

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

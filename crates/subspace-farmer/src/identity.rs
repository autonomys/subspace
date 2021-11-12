use anyhow::Error;
use log::info;
use schnorrkel::{context::SigningContext, Keypair, PublicKey, SecretKey, Signature};
use std::fs;
use std::path::Path;
use subspace_solving::SOLUTION_SIGNING_CONTEXT;

/// `Identity` struct is an abstraction of public & secret key related operations
///
/// It is basically a wrapper of the keypair (which holds public & secret keys)
/// and a context that will be used for signing
#[derive(Clone)]
pub struct Identity {
    keypair: Keypair,
    ctx: SigningContext,
}

impl Identity {
    /// Opens the existing identity, or creates a new one
    pub fn open_or_create<B: AsRef<Path>>(base_directory: B) -> Result<Identity, Error> {
        let identity_file = base_directory.as_ref().join("identity.bin");
        let keypair = if identity_file.exists() {
            info!("Opening existing keypair"); // TODO: turn this into a channel
            Keypair::from_bytes(&fs::read(identity_file)?).map_err(Error::msg)?
        } else {
            info!("Generating new keypair"); // TODO: turn this into a channel
            let new_keypair = Keypair::generate();
            fs::write(identity_file, new_keypair.to_bytes())?;
            new_keypair
        };
        Ok(Identity {
            keypair,
            ctx: schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT),
        })
    }

    /// Returns the public key of the identity
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public
    }

    /// Returns the secret key of the identity
    pub fn secret_key(&self) -> SecretKey {
        self.keypair.secret.clone()
    }

    /// Signs the data, using the context, and returns the signature
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.keypair.sign(self.ctx.bytes(data))
    }
}

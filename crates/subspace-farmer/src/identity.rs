use anyhow::Error;
use bip39::{Language, Mnemonic, MnemonicType};
use log::debug;
use schnorrkel::{context::SigningContext, Keypair, PublicKey, SecretKey, Signature};
use sp_core::sr25519::Pair;
use std::fs;
use std::path::Path;
use subspace_solving::SOLUTION_SIGNING_CONTEXT;

// Signing context hardcoded in Substrate implementation and used for signing blocks.
const SUBSTRATE_SIGNING_CONTEXT: &[u8] = b"substrate";

// TODO: Use `zeroize::Zeroizing`
/// `Identity` struct is an abstraction of public & secret key related operations.
///
/// It is basically a wrapper of the keypair (which holds public & secret keys)
/// and a context that will be used for signing.
#[derive(Clone)]
pub struct Identity {
    keypair: Keypair,
    entropy: Vec<u8>,
    farmer_solution_ctx: SigningContext,
    substrate_ctx: SigningContext,
}

impl Identity {
    /// Opens the existing identity, or creates a new one.
    pub fn open_or_create<B: AsRef<Path>>(base_directory: B) -> Result<Identity, Error> {
        let identity_file = base_directory.as_ref().join("identity.bin");
        let entropy = if identity_file.exists() {
            debug!("Opening existing keypair");
            fs::read(identity_file)?
        } else {
            debug!("Generating new keypair");
            let entropy = Mnemonic::new(MnemonicType::Words24, Language::English)
                .entropy()
                .to_vec();
            fs::write(identity_file, &entropy)?;
            entropy
        };
        let (pair, _seed) = Pair::from_entropy(&entropy, None);

        Ok(Identity {
            keypair: pair.into(),
            entropy,
            farmer_solution_ctx: schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT),
            substrate_ctx: schnorrkel::context::signing_context(SUBSTRATE_SIGNING_CONTEXT),
        })
    }

    /// Opens the existing identity, returns `Ok(None)` if it doesn't exist.
    pub fn open<B: AsRef<Path>>(base_directory: B) -> Result<Option<Identity>, Error> {
        let identity_file = base_directory.as_ref().join("identity.bin");
        if identity_file.exists() {
            let entropy = fs::read(identity_file)?;
            let (pair, _seed) = Pair::from_entropy(&entropy, None);

            Ok(Some(Identity {
                keypair: pair.into(),
                entropy,
                farmer_solution_ctx: schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT),
                substrate_ctx: schnorrkel::context::signing_context(SUBSTRATE_SIGNING_CONTEXT),
            }))
        } else {
            Ok(None)
        }
    }

    /// Returns the public key of the identity.
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public
    }

    /// Returns the secret key of the identity.
    pub fn secret_key(&self) -> SecretKey {
        self.keypair.secret.clone()
    }

    /// Returns entropy used to generate keypair.
    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }

    /// Sign farmer solution.
    pub fn sign_farmer_solution(&self, data: &[u8]) -> Signature {
        self.keypair.sign(self.farmer_solution_ctx.bytes(data))
    }

    /// Sign substrate block.
    pub fn block_signing(&self, header_hash: &[u8]) -> Signature {
        self.keypair.sign(self.substrate_ctx.bytes(header_hash))
    }
}

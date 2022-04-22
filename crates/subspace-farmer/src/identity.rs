use anyhow::Error;
use log::debug;
use parity_scale_codec::{Decode, Encode};
use schnorrkel::{context::SigningContext, Keypair, PublicKey, SecretKey, Signature};
use sp_core::sr25519::Pair;
use std::fs;
use std::path::Path;
use subspace_solving::SOLUTION_SIGNING_CONTEXT;
use zeroize::{Zeroize, Zeroizing};

/// Signing context hardcoded in Substrate implementation and used for signing blocks.
const SUBSTRATE_SIGNING_CONTEXT: &[u8] = b"substrate";
/// Entropy used for identity generation.
const ENTROPY_LENGTH: usize = 32;

#[derive(Debug, Encode, Decode)]
struct IdentityFileContents {
    entropy: Vec<u8>,
}

/// `Identity` struct is an abstraction of public & secret key related operations.
///
/// It is basically a wrapper of the keypair (which holds public & secret keys)
/// and a context that will be used for signing.
#[derive(Clone)]
pub struct Identity {
    keypair: Zeroizing<Keypair>,
    entropy: Zeroizing<Vec<u8>>,
    farmer_solution_ctx: SigningContext,
    substrate_ctx: SigningContext,
}

impl Identity {
    /// Opens the existing identity, or creates a new one.
    pub fn open_or_create<B: AsRef<Path>>(base_directory: B) -> Result<Self, Error> {
        if let Some(identity) = Self::open(base_directory.as_ref())? {
            Ok(identity)
        } else {
            Self::create(base_directory)
        }
    }

    /// Opens the existing identity, returns `Ok(None)` if it doesn't exist.
    pub fn open<B: AsRef<Path>>(base_directory: B) -> Result<Option<Self>, Error> {
        let identity_file = base_directory.as_ref().join("identity.bin");
        if identity_file.exists() {
            debug!("Opening existing keypair");
            let bytes = Zeroizing::new(fs::read(identity_file)?);
            let IdentityFileContents { entropy } =
                IdentityFileContents::decode(&mut bytes.as_ref())?;

            let (pair, mut seed) = Pair::from_entropy(&entropy, None);
            seed.zeroize();

            Ok(Some(Self {
                keypair: Zeroizing::new(pair.into()),
                entropy: Zeroizing::new(entropy),
                farmer_solution_ctx: schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT),
                substrate_ctx: schnorrkel::context::signing_context(SUBSTRATE_SIGNING_CONTEXT),
            }))
        } else {
            debug!("Existing keypair not found");
            Ok(None)
        }
    }

    /// Creates new identity, overrides identity that might already exist.
    pub fn create<B: AsRef<Path>>(base_directory: B) -> Result<Self, Error> {
        let identity_file = base_directory.as_ref().join("identity.bin");
        debug!("Generating new keypair");
        let entropy = rand::random::<[u8; ENTROPY_LENGTH]>().to_vec();

        let identity_file_contents = IdentityFileContents { entropy };
        fs::write(identity_file, identity_file_contents.encode())?;

        let IdentityFileContents { entropy } = identity_file_contents;
        let (pair, mut seed) = Pair::from_entropy(&entropy, None);
        seed.zeroize();

        Ok(Self {
            keypair: Zeroizing::new(pair.into()),
            entropy: Zeroizing::new(entropy),
            farmer_solution_ctx: schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT),
            substrate_ctx: schnorrkel::context::signing_context(SUBSTRATE_SIGNING_CONTEXT),
        })
    }

    /// Create identity from given entropy, overrides identity that might already exist.
    ///
    /// Primarily used for testing.
    #[doc(hidden)]
    pub fn from_entropy<B: AsRef<Path>>(
        base_directory: B,
        entropy: Vec<u8>,
    ) -> Result<Self, Error> {
        let identity_file = base_directory.as_ref().join("identity.bin");
        debug!("Creating identity from provided entropy");

        let identity_file_contents = IdentityFileContents { entropy };
        fs::write(identity_file, identity_file_contents.encode())?;

        let IdentityFileContents { entropy } = identity_file_contents;
        let (pair, mut seed) = Pair::from_entropy(&entropy, None);
        seed.zeroize();

        Ok(Self {
            keypair: Zeroizing::new(pair.into()),
            entropy: Zeroizing::new(entropy),
            farmer_solution_ctx: schnorrkel::context::signing_context(SOLUTION_SIGNING_CONTEXT),
            substrate_ctx: schnorrkel::context::signing_context(SUBSTRATE_SIGNING_CONTEXT),
        })
    }

    /// Returns the public key of the identity.
    pub fn public_key(&self) -> &PublicKey {
        &self.keypair.public
    }

    /// Returns the secret key of the identity.
    pub fn secret_key(&self) -> &SecretKey {
        &self.keypair.secret
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
    pub fn sign_block_header_hash(&self, header_hash: &[u8]) -> Signature {
        self.keypair.sign(self.substrate_ctx.bytes(header_hash))
    }
}

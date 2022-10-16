use anyhow::Error;
use parity_scale_codec::{Decode, Encode};
use schnorrkel::context::SigningContext;
use schnorrkel::{ExpansionMode, Keypair, PublicKey, SecretKey, Signature};
use std::fs;
use std::ops::Deref;
use std::path::Path;
use subspace_core_primitives::{Chunk, ChunkSignature};
use subspace_solving::{create_chunk_signature, REWARD_SIGNING_CONTEXT};
use substrate_bip39::mini_secret_from_entropy;
use tracing::debug;
use zeroize::Zeroizing;

/// Entropy used for identity generation.
const ENTROPY_LENGTH: usize = 32;

#[derive(Debug, Encode, Decode)]
struct IdentityFileContents {
    entropy: Vec<u8>,
}

fn keypair_from_entropy(entropy: &[u8]) -> Keypair {
    mini_secret_from_entropy(entropy, "")
        .expect("32 bytes can always build a key; qed")
        .expand_to_keypair(ExpansionMode::Ed25519)
}

/// `Identity` struct is an abstraction of public & secret key related operations.
///
/// It is basically a wrapper of the keypair (which holds public & secret keys)
/// and a context that will be used for signing.
#[derive(Clone)]
pub struct Identity {
    keypair: Zeroizing<Keypair>,
    entropy: Zeroizing<Vec<u8>>,
    substrate_ctx: SigningContext,
}

impl Deref for Identity {
    type Target = Keypair;

    fn deref(&self) -> &Self::Target {
        &self.keypair
    }
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

            Ok(Some(Self {
                keypair: Zeroizing::new(keypair_from_entropy(&entropy)),
                entropy: Zeroizing::new(entropy),
                substrate_ctx: schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT),
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

        Ok(Self {
            keypair: Zeroizing::new(keypair_from_entropy(&entropy)),
            entropy: Zeroizing::new(entropy),
            substrate_ctx: schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT),
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

        Ok(Self {
            keypair: Zeroizing::new(keypair_from_entropy(&entropy)),
            entropy: Zeroizing::new(entropy),
            substrate_ctx: schnorrkel::context::signing_context(REWARD_SIGNING_CONTEXT),
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

    pub fn create_chunk_signature(&self, chunk: &Chunk) -> ChunkSignature {
        create_chunk_signature(&self.keypair, chunk)
    }

    /// Sign reward hash.
    pub fn sign_reward_hash(&self, header_hash: &[u8]) -> Signature {
        self.keypair.sign(self.substrate_ctx.bytes(header_hash))
    }
}

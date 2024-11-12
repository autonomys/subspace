//! Farm identity

use parity_scale_codec::{Decode, Encode};
use schnorrkel::context::SigningContext;
use schnorrkel::{ExpansionMode, Keypair, PublicKey, SecretKey, Signature};
use std::ops::Deref;
use std::path::Path;
use std::{fmt, fs, io};
use subspace_core_primitives::REWARD_SIGNING_CONTEXT;
use substrate_bip39::mini_secret_from_entropy;
use thiserror::Error;
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

/// Errors happening when trying to create/open single disk farm
#[derive(Debug, Error)]
pub enum IdentityError {
    /// I/O error occurred
    #[error("Identity I/O error: {0}")]
    Io(#[from] io::Error),
    /// Invalid contents
    #[error("Invalid contents")]
    InvalidContents,
    /// Decoding error
    #[error("Decoding error: {0}")]
    Decoding(#[from] parity_scale_codec::Error),
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

impl fmt::Debug for Identity {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("keypair", &self.keypair)
            .finish_non_exhaustive()
    }
}

impl Deref for Identity {
    type Target = Keypair;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.keypair
    }
}

impl Identity {
    pub(crate) const FILE_NAME: &'static str = "identity.bin";

    /// Size of the identity file on disk
    pub fn file_size() -> usize {
        IdentityFileContents {
            entropy: vec![0; ENTROPY_LENGTH],
        }
        .encoded_size()
    }

    /// Opens the existing identity, or creates a new one.
    pub fn open_or_create<B: AsRef<Path>>(base_directory: B) -> Result<Self, IdentityError> {
        if let Some(identity) = Self::open(base_directory.as_ref())? {
            Ok(identity)
        } else {
            Self::create(base_directory)
        }
    }

    /// Opens the existing identity, returns `Ok(None)` if it doesn't exist.
    pub fn open<B: AsRef<Path>>(base_directory: B) -> Result<Option<Self>, IdentityError> {
        let identity_file = base_directory.as_ref().join(Self::FILE_NAME);
        if identity_file.exists() {
            debug!("Opening existing keypair");
            let bytes = Zeroizing::new(fs::read(identity_file)?);
            let IdentityFileContents { entropy } =
                IdentityFileContents::decode(&mut bytes.as_ref())?;

            if entropy.len() != ENTROPY_LENGTH {
                return Err(IdentityError::InvalidContents);
            }

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
    pub fn create<B: AsRef<Path>>(base_directory: B) -> Result<Self, IdentityError> {
        let identity_file = base_directory.as_ref().join(Self::FILE_NAME);
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

    /// Sign reward hash.
    pub fn sign_reward_hash(&self, header_hash: &[u8]) -> Signature {
        self.keypair.sign(self.substrate_ctx.bytes(header_hash))
    }
}

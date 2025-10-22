//! FN-DSA (Falcon) signature types for post-quantum security

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use core::fmt;
use derive_more::Deref;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// FN-DSA-512 signature size (from rust-fn-dsa)
pub const FN_DSA_512_SIGNATURE_SIZE: usize = 666;
/// FN-DSA-512 public key size
pub const FN_DSA_512_PUBLIC_KEY_SIZE: usize = 897;
/// FN-DSA-512 private key size
pub const FN_DSA_512_PRIVATE_KEY_SIZE: usize = 1281;

/// FN-DSA-1024 signature size (from rust-fn-dsa)
pub const FN_DSA_1024_SIGNATURE_SIZE: usize = 1280;
/// FN-DSA-1024 public key size
pub const FN_DSA_1024_PUBLIC_KEY_SIZE: usize = 1793;
/// FN-DSA-1024 private key size
pub const FN_DSA_1024_PRIVATE_KEY_SIZE: usize = 2305;

/// FN-DSA signature with variable length encoding
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo, Deref)]
pub struct FnDsaSignature(Vec<u8>);

impl MaxEncodedLen for FnDsaSignature {
    fn max_encoded_len() -> usize {
        // Use the maximum size for FN-DSA-1024 signature
        FN_DSA_1024_SIGNATURE_SIZE
    }
}

impl fmt::Debug for FnDsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FnDsaSignature({} bytes)", self.0.len())
    }
}

#[cfg(feature = "serde")]
impl Serialize for FnDsaSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            hex::encode(&self.0).serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for FnDsaSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let hex_str = String::deserialize(deserializer)?;
            let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
            Ok(Self(bytes))
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Ok(Self(bytes))
        }
    }
}

impl AsRef<[u8]> for FnDsaSignature {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FnDsaSignature {
    /// Create FN-DSA signature from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get signature length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if signature is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// FN-DSA private key
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo, Deref)]
pub struct FnDsaPrivateKey(Vec<u8>);

impl fmt::Debug for FnDsaPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FnDsaPrivateKey({} bytes)", self.0.len())
    }
}

#[cfg(feature = "serde")]
impl Serialize for FnDsaPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            hex::encode(&self.0).serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for FnDsaPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let hex_str = String::deserialize(deserializer)?;
            let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
            Ok(Self(bytes))
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Ok(Self(bytes))
        }
    }
}

impl AsRef<[u8]> for FnDsaPrivateKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FnDsaPrivateKey {
    /// Create FN-DSA private key from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get private key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get private key length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if private key is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// FN-DSA public key
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash, Encode, Decode, TypeInfo, Deref)]
pub struct FnDsaPublicKey(Vec<u8>);

impl MaxEncodedLen for FnDsaPublicKey {
    fn max_encoded_len() -> usize {
        // Use the maximum size for FN-DSA-1024 public key
        FN_DSA_1024_PUBLIC_KEY_SIZE
    }
}

impl fmt::Debug for FnDsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FnDsaPublicKey({} bytes)", self.0.len())
    }
}

#[cfg(feature = "serde")]
impl Serialize for FnDsaPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            hex::encode(&self.0).serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for FnDsaPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let hex_str = String::deserialize(deserializer)?;
            let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
            Ok(Self(bytes))
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Ok(Self(bytes))
        }
    }
}

impl AsRef<[u8]> for FnDsaPublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FnDsaPublicKey {
    /// Create FN-DSA public key from bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get public key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get public key length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if public key is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// FN-DSA signature verification error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FnDsaError {
    /// Invalid signature format
    InvalidSignature,
    /// Invalid public key format
    InvalidPublicKey,
    /// Signature verification failed
    VerificationFailed,
    /// Unsupported operation
    UnsupportedOperation,
}

impl fmt::Display for FnDsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FnDsaError::InvalidSignature => write!(f, "Invalid signature format"),
            FnDsaError::InvalidPublicKey => write!(f, "Invalid public key format"),
            FnDsaError::VerificationFailed => write!(f, "Signature verification failed"),
            FnDsaError::UnsupportedOperation => write!(f, "Unsupported operation"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FnDsaError {}

/// FN-DSA key pair generation trait
pub trait FnDsaKeyGenerator {
    /// Generate a new FN-DSA key pair
    fn generate_keypair(logn: u32) -> Result<(FnDsaPrivateKey, FnDsaPublicKey), FnDsaError>;
}

/// FN-DSA signing trait
pub trait FnDsaSigner {
    /// Sign a message with FN-DSA
    fn sign(message: &[u8], signing_key: &FnDsaPrivateKey) -> Result<FnDsaSignature, FnDsaError>;
}

/// FN-DSA signature verification trait
pub trait FnDsaVerifier {
    /// Verify FN-DSA signature
    fn verify(
        message: &[u8],
        signature: &FnDsaSignature,
        public_key: &FnDsaPublicKey,
    ) -> Result<(), FnDsaError>;
}

#[cfg(feature = "fn-dsa")]
impl FnDsaKeyGenerator for FnDsaPrivateKey {
    fn generate_keypair(logn: u32) -> Result<(FnDsaPrivateKey, FnDsaPublicKey), FnDsaError> {
        use fn_dsa::{KeyPairGenerator, KeyPairGeneratorStandard, sign_key_size, vrfy_key_size};

        #[cfg(feature = "std")]
        {
            use rand::rngs::OsRng;

            let mut sign_key = vec![0u8; sign_key_size(logn)];
            let mut vrfy_key = vec![0u8; vrfy_key_size(logn)];

            let mut kg = KeyPairGeneratorStandard::default();
            kg.keygen(logn, &mut OsRng, &mut sign_key, &mut vrfy_key);

            Ok((
                FnDsaPrivateKey::new(sign_key),
                FnDsaPublicKey::new(vrfy_key),
            ))
        }

        #[cfg(not(feature = "std"))]
        {
            Err(FnDsaError::UnsupportedOperation)
        }
    }
}

#[cfg(feature = "fn-dsa")]
impl FnDsaSigner for FnDsaSignature {
    fn sign(message: &[u8], signing_key: &FnDsaPrivateKey) -> Result<FnDsaSignature, FnDsaError> {
        use fn_dsa::{DOMAIN_NONE, HASH_ID_RAW, SigningKey, SigningKeyStandard, signature_size};

        #[cfg(feature = "std")]
        {
            use rand::rngs::OsRng;

            // Decode the signing key
            let mut sk =
                SigningKeyStandard::decode(&signing_key.0).ok_or(FnDsaError::InvalidSignature)?;

            // Create signature buffer
            let mut sig = vec![0u8; signature_size(sk.get_logn())];

            // Sign the message
            sk.sign(&mut OsRng, &DOMAIN_NONE, &HASH_ID_RAW, message, &mut sig);

            Ok(FnDsaSignature::new(sig))
        }

        #[cfg(not(feature = "std"))]
        {
            Err(FnDsaError::UnsupportedOperation)
        }
    }
}

#[cfg(feature = "fn-dsa")]
impl FnDsaVerifier for FnDsaSignature {
    fn verify(
        message: &[u8],
        signature: &FnDsaSignature,
        public_key: &FnDsaPublicKey,
    ) -> Result<(), FnDsaError> {
        use fn_dsa::{DOMAIN_NONE, HASH_ID_RAW, VerifyingKey, VerifyingKeyStandard};

        // Decode the verifying key
        let vk = VerifyingKeyStandard::decode(&public_key.0).ok_or(FnDsaError::InvalidPublicKey)?;

        // Verify the signature
        if vk.verify(&signature.0, &DOMAIN_NONE, &HASH_ID_RAW, message) {
            Ok(())
        } else {
            Err(FnDsaError::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fn_dsa_signature_creation() {
        let test_bytes = vec![0u8; 100];
        let signature = FnDsaSignature::new(test_bytes.clone());
        assert_eq!(signature.as_bytes(), &test_bytes);
        assert_eq!(signature.len(), 100);
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_fn_dsa_public_key_creation() {
        let test_bytes = vec![0u8; 897]; // FN-DSA-512 public key size
        let public_key = FnDsaPublicKey::new(test_bytes.clone());
        assert_eq!(public_key.as_bytes(), &test_bytes);
        assert_eq!(public_key.len(), 897);
        assert!(!public_key.is_empty());
    }

    #[test]
    fn test_fn_dsa_signature_serialization() {
        let test_bytes = vec![1, 2, 3, 4, 5];
        let signature = FnDsaSignature::new(test_bytes.clone());

        let encoded = signature.encode();
        let decoded = FnDsaSignature::decode(&mut &encoded[..]).unwrap();

        assert_eq!(signature, decoded);
    }

    #[test]
    fn test_fn_dsa_public_key_serialization() {
        let test_bytes = vec![1, 2, 3, 4, 5];
        let public_key = FnDsaPublicKey::new(test_bytes.clone());

        let encoded = public_key.encode();
        let decoded = FnDsaPublicKey::decode(&mut &encoded[..]).unwrap();

        assert_eq!(public_key, decoded);
    }

    #[test]
    fn test_fn_dsa_private_key_creation() {
        let test_bytes = vec![0u8; 1281]; // FN-DSA-512 private key size
        let private_key = FnDsaPrivateKey::new(test_bytes.clone());
        assert_eq!(private_key.as_bytes(), &test_bytes);
        assert_eq!(private_key.len(), 1281);
        assert!(!private_key.is_empty());
    }

    #[test]
    fn test_fn_dsa_private_key_serialization() {
        let test_bytes = vec![1, 2, 3, 4, 5];
        let private_key = FnDsaPrivateKey::new(test_bytes.clone());

        let encoded = private_key.encode();
        let decoded = FnDsaPrivateKey::decode(&mut &encoded[..]).unwrap();

        assert_eq!(private_key, decoded);
    }

    #[cfg(feature = "fn-dsa")]
    #[test]
    fn test_fn_dsa_key_generation() {
        use crate::fn_dsa::FnDsaKeyGenerator;

        // Test FN-DSA-512 key generation
        let result = FnDsaPrivateKey::generate_keypair(9u32); // FN_DSA_LOGN_512
        assert!(result.is_ok());

        let (private_key, public_key) = result.unwrap();
        assert_eq!(private_key.len(), FN_DSA_512_PRIVATE_KEY_SIZE);
        assert_eq!(public_key.len(), FN_DSA_512_PUBLIC_KEY_SIZE);
    }

    #[cfg(feature = "fn-dsa")]
    #[test]
    fn test_fn_dsa_sign_and_verify() {
        use crate::fn_dsa::{FnDsaKeyGenerator, FnDsaSigner, FnDsaVerifier};

        // Generate key pair
        let (private_key, public_key) = FnDsaPrivateKey::generate_keypair(9u32).unwrap();

        // Sign a message
        let message = b"test message";
        let signature = FnDsaSignature::sign(message, &private_key).unwrap();

        // Verify the signature
        let result = FnDsaSignature::verify(message, &signature, &public_key);
        assert!(result.is_ok());

        // Verify with wrong message should fail
        let wrong_message = b"wrong message";
        let result = FnDsaSignature::verify(wrong_message, &signature, &public_key);
        assert!(result.is_err());
    }
}

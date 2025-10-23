//! Extended MultiSignature supporting FN-DSA for post-quantum security

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

use parity_scale_codec::{Decode, Encode, Input, MaxEncodedLen};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_core::{ecdsa, ed25519, sr25519};
use sp_runtime::MultiSignature;
use sp_runtime::traits::{IdentifyAccount, Lazy, Verify};

#[cfg(feature = "fn-dsa")]
use subspace_core_primitives::{FnDsaPublicKey, FnDsaSignature, FnDsaVerifier};

/// Extended MultiSignature supporting FN-DSA for post-quantum security
///
/// This extends Substrate's standard `MultiSignature` to include FN-DSA (Falcon),
/// a (soon to be) NIST-standardized post-quantum signature scheme.
///
/// Uses a wrapper approach for better compatibility and maintainability.
/// Custom encoding ensures backwards compatibility with standard MultiSignature.
#[derive(Clone, Debug, Eq, PartialEq, TypeInfo, Serialize, Deserialize)]
pub enum ExtendedMultiSignature {
    /// Standard Substrate signatures (Ed25519, Sr25519, Ecdsa)
    Standard(MultiSignature),
    /// FN-DSA signature (post-quantum)
    #[cfg(feature = "fn-dsa")]
    #[codec(skip)]
    #[serde(skip)]
    FnDsa(FnDsaSignature),
}

impl Encode for ExtendedMultiSignature {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Standard(sig) => {
                // Flatten encoding for backwards compatibility
                // Standard signatures encode as: [variant] + signature bytes
                match sig {
                    MultiSignature::Ed25519(s) => {
                        let mut v = vec![0u8];
                        v.extend_from_slice(&s.0);
                        v
                    }
                    MultiSignature::Sr25519(s) => {
                        let mut v = vec![1u8];
                        v.extend_from_slice(&s.0);
                        v
                    }
                    MultiSignature::Ecdsa(s) => {
                        let mut v = vec![2u8];
                        v.extend_from_slice(&s.0);
                        v
                    }
                }
            }
            #[cfg(feature = "fn-dsa")]
            Self::FnDsa(sig) => {
                // FN-DSA uses variant 3
                let mut v = vec![3u8];
                v.extend_from_slice(sig.as_bytes());
                v
            }
        }
    }
}

impl Decode for ExtendedMultiSignature {
    fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
        let variant = input.read_byte()?;
        match variant {
            0 => {
                // Ed25519
                let mut sig = [0u8; 64];
                input.read(&mut sig[..])?;
                Ok(Self::Standard(MultiSignature::Ed25519(
                    ed25519::Signature::from_raw(sig),
                )))
            }
            1 => {
                // Sr25519
                let mut sig = [0u8; 64];
                input.read(&mut sig[..])?;
                Ok(Self::Standard(MultiSignature::Sr25519(
                    sr25519::Signature::from_raw(sig),
                )))
            }
            2 => {
                // ECDSA
                let mut sig = [0u8; 65];
                input.read(&mut sig[..])?;
                Ok(Self::Standard(MultiSignature::Ecdsa(
                    ecdsa::Signature::from_raw(sig),
                )))
            }
            #[cfg(feature = "fn-dsa")]
            3 => {
                // FN-DSA - variable length
                let mut bytes = Vec::new();
                while let Ok(b) = input.read_byte() {
                    bytes.push(b);
                }
                Ok(Self::FnDsa(FnDsaSignature::new(bytes)))
            }
            _ => Err("Invalid signature variant".into()),
        }
    }
}

impl MaxEncodedLen for ExtendedMultiSignature {
    fn max_encoded_len() -> usize {
        // Enum discriminant (1 byte) + max variant size
        // Standard MultiSignature is max 65 bytes (ECDSA)
        #[cfg(feature = "fn-dsa")]
        {
            1 + MultiSignature::max_encoded_len().max(FnDsaSignature::max_encoded_len())
        }
        #[cfg(not(feature = "fn-dsa"))]
        {
            1 + MultiSignature::max_encoded_len()
        }
    }
}

impl From<sr25519::Signature> for ExtendedMultiSignature {
    fn from(sig: sr25519::Signature) -> Self {
        Self::Standard(MultiSignature::Sr25519(sig))
    }
}

impl From<ed25519::Signature> for ExtendedMultiSignature {
    fn from(sig: ed25519::Signature) -> Self {
        Self::Standard(MultiSignature::Ed25519(sig))
    }
}

impl From<ecdsa::Signature> for ExtendedMultiSignature {
    fn from(sig: ecdsa::Signature) -> Self {
        Self::Standard(MultiSignature::Ecdsa(sig))
    }
}

#[cfg(feature = "fn-dsa")]
impl From<FnDsaSignature> for ExtendedMultiSignature {
    fn from(sig: FnDsaSignature) -> Self {
        Self::FnDsa(sig)
    }
}

impl From<MultiSignature> for ExtendedMultiSignature {
    fn from(sig: MultiSignature) -> Self {
        Self::Standard(sig)
    }
}

impl TryFrom<ExtendedMultiSignature> for MultiSignature {
    type Error = &'static str;

    fn try_from(ext_sig: ExtendedMultiSignature) -> Result<Self, Self::Error> {
        match ext_sig {
            ExtendedMultiSignature::Standard(sig) => Ok(sig),
            #[cfg(feature = "fn-dsa")]
            ExtendedMultiSignature::FnDsa(_) => {
                Err("FN-DSA signature cannot be converted to standard MultiSignature")
            }
        }
    }
}

impl Verify for ExtendedMultiSignature {
    type Signer = ExtendedMultiSigner;

    #[cfg(feature = "std")]
    fn verify<L: Lazy<[u8]>>(&self, msg: L, signer: &sp_runtime::AccountId32) -> bool {
        match self {
            // Delegate standard signatures to the standard MultiSignature
            Self::Standard(sig) => {
                // Try to convert AccountId32 to each possible MultiSigner type
                if let Ok(pk) = sr25519::Public::try_from(signer.as_ref()) {
                    let multi_signer = sp_runtime::MultiSigner::Sr25519(pk);
                    let account_id =
                        <sp_runtime::MultiSigner as IdentifyAccount>::into_account(multi_signer);
                    return sig.verify(msg, &account_id);
                }
                if let Ok(pk) = ed25519::Public::try_from(signer.as_ref()) {
                    let multi_signer = sp_runtime::MultiSigner::Ed25519(pk);
                    let account_id =
                        <sp_runtime::MultiSigner as IdentifyAccount>::into_account(multi_signer);
                    return sig.verify(msg, &account_id);
                }
                if let Ok(pk) = ecdsa::Public::try_from(signer.as_ref()) {
                    let multi_signer = sp_runtime::MultiSigner::Ecdsa(pk);
                    let account_id =
                        <sp_runtime::MultiSigner as IdentifyAccount>::into_account(multi_signer);
                    return sig.verify(msg, &account_id);
                }
                false
            }
            // Handle FN-DSA signature - requires explicit public key
            #[cfg(feature = "fn-dsa")]
            Self::FnDsa(_sig) => {
                // Cannot verify FN-DSA with just AccountId32
                // Must use verify_with_public_key instead
                false
            }
        }
    }

    #[cfg(not(feature = "std"))]
    fn verify<L: Lazy<[u8]>>(&self, _msg: L, _signer: &sp_runtime::AccountId32) -> bool {
        // In no_std environments, verification requires explicit public keys
        // Use verify_with_public_key instead
        false
    }
}

impl ExtendedMultiSignature {
    /// Verify signature with an explicit public key signer
    ///
    /// This is useful for FN-DSA signatures where the public key cannot be
    /// reconstructed from the account ID or recovered from the signature.
    #[cfg(feature = "fn-dsa")]
    pub fn verify_with_public_key<L: Lazy<[u8]>>(
        &self,
        mut msg: L,
        signer: &ExtendedMultiSigner,
    ) -> bool {
        match (self, signer) {
            // Delegate standard signatures to the standard MultiSignature
            (Self::Standard(sig), ExtendedMultiSigner::Standard(who)) => {
                // Need to convert MultiSigner to AccountId32 for verification
                let account_id = who.clone().into_account();
                sig.verify(msg, &account_id)
            }
            // FN-DSA verification using direct verification (no host function)
            (Self::FnDsa(sig), ExtendedMultiSigner::FnDsa(pk)) => {
                FnDsaSignature::verify(msg.get(), sig, pk).is_ok()
            }
            // Mismatched signature and signer types
            _ => false,
        }
    }
}

/// Extended MultiSigner supporting FN-DSA public keys
///
/// This extends Substrate's standard `MultiSigner` to include FN-DSA public keys
/// for post-quantum security.
#[derive(
    Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Encode, Decode, TypeInfo, Serialize, Deserialize,
)]
pub enum ExtendedMultiSigner {
    /// Standard Substrate signers (Ed25519, Sr25519, Ecdsa)
    Standard(sp_runtime::MultiSigner),
    /// FN-DSA public key (post-quantum)
    #[cfg(feature = "fn-dsa")]
    #[codec(skip)]
    #[serde(skip)]
    FnDsa(FnDsaPublicKey),
}

impl MaxEncodedLen for ExtendedMultiSigner {
    fn max_encoded_len() -> usize {
        // Enum discriminant (1 byte) + max variant size
        // MultiSigner doesn't have MaxEncodedLen, so we estimate based on ECDSA (33 bytes)
        #[cfg(feature = "fn-dsa")]
        {
            1 + 33.max(FnDsaPublicKey::max_encoded_len())
        }
        #[cfg(not(feature = "fn-dsa"))]
        {
            1 + 33
        }
    }
}

impl From<sr25519::Public> for ExtendedMultiSigner {
    fn from(pk: sr25519::Public) -> Self {
        Self::Standard(sp_runtime::MultiSigner::Sr25519(pk))
    }
}

impl From<ed25519::Public> for ExtendedMultiSigner {
    fn from(pk: ed25519::Public) -> Self {
        Self::Standard(sp_runtime::MultiSigner::Ed25519(pk))
    }
}

impl From<ecdsa::Public> for ExtendedMultiSigner {
    fn from(pk: ecdsa::Public) -> Self {
        Self::Standard(sp_runtime::MultiSigner::Ecdsa(pk))
    }
}

#[cfg(feature = "fn-dsa")]
impl From<FnDsaPublicKey> for ExtendedMultiSigner {
    fn from(pk: FnDsaPublicKey) -> Self {
        Self::FnDsa(pk)
    }
}

impl From<sp_runtime::MultiSigner> for ExtendedMultiSigner {
    fn from(signer: sp_runtime::MultiSigner) -> Self {
        Self::Standard(signer)
    }
}

impl IdentifyAccount for ExtendedMultiSigner {
    type AccountId = sp_runtime::AccountId32;

    fn into_account(self) -> Self::AccountId {
        match self {
            Self::Standard(signer) => signer.into_account(),
            #[cfg(feature = "fn-dsa")]
            Self::FnDsa(pk) => {
                // For FN-DSA, we hash the public key to create a 32-byte AccountId
                // This is consistent with how other signature schemes work
                blake2_256(pk.as_bytes()).into()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backwards_compatibility() {
        // Test that standard signatures encode/decode identically to how they would have
        // before the extension (i.e., without the wrapper byte)

        // Create a standard signature
        let std_sig = MultiSignature::Sr25519(sr25519::Signature::from_raw([42u8; 64]));

        // Convert to extended
        let ext_sig = ExtendedMultiSignature::from(std_sig.clone());

        // Encode extended signature
        let ext_encoded = ext_sig.encode();

        // Standard signature should encode the same way
        let std_encoded = std_sig.encode();

        // They should be identical for backwards compatibility
        assert_eq!(ext_encoded, std_encoded);

        // Decode should work both ways
        let decoded_ext = ExtendedMultiSignature::decode(&mut &ext_encoded[..]).unwrap();
        assert!(matches!(
            decoded_ext,
            ExtendedMultiSignature::Standard(MultiSignature::Sr25519(_))
        ));
    }

    #[cfg(feature = "fn-dsa")]
    #[test]
    fn test_fn_dsa_encoding() {
        let fn_dsa_sig = FnDsaSignature::new(vec![0xAA, 0xBB, 0xCC]);
        let ext_sig = ExtendedMultiSignature::FnDsa(fn_dsa_sig.clone());

        let encoded = ext_sig.encode();

        // Should start with variant 3 (FN-DSA)
        assert_eq!(encoded[0], 3);

        // Should contain the signature bytes
        assert_eq!(&encoded[1..], fn_dsa_sig.as_bytes());

        // Decode should work
        let decoded = ExtendedMultiSignature::decode(&mut &encoded[..]).unwrap();
        assert!(matches!(decoded, ExtendedMultiSignature::FnDsa(_)));
    }

    #[cfg(feature = "fn-dsa")]
    #[test]
    fn test_extended_multisignature_variants() {
        // Test that each variant can be created
        let _sr25519_sig = ExtendedMultiSignature::Standard(MultiSignature::Sr25519(
            sr25519::Signature::from_raw([0u8; 64]),
        ));
        let _ed25519_sig = ExtendedMultiSignature::Standard(MultiSignature::Ed25519(
            ed25519::Signature::from_raw([0u8; 64]),
        ));
        let _ecdsa_sig = ExtendedMultiSignature::Standard(MultiSignature::Ecdsa(
            ecdsa::Signature::from_raw([0u8; 65]),
        ));

        // FN-DSA sig can be created but won't serialize/deserialize in standard tests
        let _fn_dsa_sig = ExtendedMultiSignature::FnDsa(FnDsaSignature::new(vec![0u8; 666]));

        // Test encoding/decoding (without FN-DSA due to skip attribute)
        let sr25519_sig = ExtendedMultiSignature::Standard(MultiSignature::Sr25519(
            sr25519::Signature::from_raw([1u8; 64]),
        ));
        let encoded = sr25519_sig.encode();
        let decoded = ExtendedMultiSignature::decode(&mut &encoded[..]).unwrap();
        assert!(matches!(
            decoded,
            ExtendedMultiSignature::Standard(MultiSignature::Sr25519(_))
        ));
    }

    #[cfg(feature = "fn-dsa")]
    #[test]
    fn test_extended_multisigner_variants() {
        // Test that each variant can be created
        let _sr25519_pk = ExtendedMultiSigner::Standard(sp_runtime::MultiSigner::Sr25519(
            sr25519::Public::from_raw([0u8; 32]),
        ));
        let _ed25519_pk = ExtendedMultiSigner::Standard(sp_runtime::MultiSigner::Ed25519(
            ed25519::Public::from_raw([0u8; 32]),
        ));
        let _ecdsa_pk = ExtendedMultiSigner::Standard(sp_runtime::MultiSigner::Ecdsa(
            ecdsa::Public::from_raw([0u8; 33]),
        ));

        // FN-DSA pk can be created but won't serialize/deserialize in standard tests
        let _fn_dsa_pk = ExtendedMultiSigner::FnDsa(FnDsaPublicKey::new(vec![0u8; 897]));

        // Test encoding/decoding (without FN-DSA due to skip attribute)
        let sr25519_pk = ExtendedMultiSigner::Standard(sp_runtime::MultiSigner::Sr25519(
            sr25519::Public::from_raw([1u8; 32]),
        ));
        let encoded = sr25519_pk.encode();
        let decoded = ExtendedMultiSigner::decode(&mut &encoded[..]).unwrap();
        assert!(matches!(
            decoded,
            ExtendedMultiSigner::Standard(sp_runtime::MultiSigner::Sr25519(_))
        ));
    }

    #[cfg(feature = "fn-dsa")]
    #[test]
    fn test_fn_dsa_signer_into_account() {
        let fn_dsa_pk = FnDsaPublicKey::new(vec![1u8; 897]);
        let signer = ExtendedMultiSigner::FnDsa(fn_dsa_pk);

        // Should hash to AccountId32
        let account_id: sp_runtime::AccountId32 = signer.into_account();
        let account_bytes: &[u8] = account_id.as_ref();
        assert_eq!(account_bytes.len(), 32);
    }

    #[test]
    fn test_conversion_from_multisignature() {
        let std_sig = MultiSignature::Sr25519(sr25519::Signature::from_raw([0u8; 64]));
        let ext_sig = ExtendedMultiSignature::from(std_sig);

        assert!(matches!(
            ext_sig,
            ExtendedMultiSignature::Standard(MultiSignature::Sr25519(_))
        ));
    }

    #[cfg(feature = "fn-dsa")]
    #[test]
    fn test_conversion_to_multisignature() {
        // Standard signatures should convert successfully
        let ext_sig = ExtendedMultiSignature::Standard(MultiSignature::Sr25519(
            sr25519::Signature::from_raw([0u8; 64]),
        ));
        let std_sig = MultiSignature::try_from(ext_sig);
        assert!(std_sig.is_ok());

        // FN-DSA should fail to convert
        let fn_dsa_sig = ExtendedMultiSignature::FnDsa(FnDsaSignature::new(vec![0u8; 666]));
        let std_sig = MultiSignature::try_from(fn_dsa_sig);
        assert!(std_sig.is_err());
    }

    #[cfg(feature = "fn-dsa")]
    #[test]
    fn test_verify_mismatched_types() {
        // Create mismatched signature and signer
        let sig = ExtendedMultiSignature::Standard(MultiSignature::Sr25519(
            sr25519::Signature::from_raw([0u8; 64]),
        ));
        let signer = ExtendedMultiSigner::Standard(sp_runtime::MultiSigner::Ed25519(
            ed25519::Public::from_raw([0u8; 32]),
        ));
        // Verification should fail for mismatched types
        let result = sig.verify_with_public_key(&b"test message"[..], &signer);
        assert!(!result);
    }

    #[cfg(all(feature = "fn-dsa", feature = "std"))]
    #[test]
    fn test_fn_dsa_signature_verify() {
        use subspace_core_primitives::fn_dsa::{FnDsaKeyGenerator, FnDsaPrivateKey, FnDsaSigner};

        // Generate a key pair
        let (private_key, public_key) = FnDsaPrivateKey::generate_keypair(9u32).unwrap();

        // Sign a message
        let message = b"test message for FN-DSA verification";
        let signature = FnDsaSignature::sign(message, &private_key).unwrap();

        // Create extended types
        let ext_sig = ExtendedMultiSignature::FnDsa(signature);
        let ext_signer = ExtendedMultiSigner::FnDsa(public_key);

        // Verify should succeed with explicit public key
        let result = ext_sig.verify_with_public_key(&message[..], &ext_signer);
        assert!(result);

        // Verify with wrong message should fail
        let wrong_message = b"wrong message";
        let result = ext_sig.verify_with_public_key(&wrong_message[..], &ext_signer);
        assert!(!result);
    }
}

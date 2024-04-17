use crate::{
    DerVec, SignatureVerificationRequest, SubjectDistinguishedName, TbsCertificate, Validity,
};
use sp_core::U256;
use std::sync::Arc;
use x509_parser::der_parser::asn1_rs::BitString;
use x509_parser::prelude::{AlgorithmIdentifier, FromDer, SubjectPublicKeyInfo};
use x509_parser::verify::verify_signature;

/// Host function trait for Certificate registration
pub trait HostFunctions: Send + Sync {
    fn verify_signature(&self, req: SignatureVerificationRequest) -> Option<()>;
    fn decode_tbs_certificate(&self, certificate: DerVec) -> Option<TbsCertificate>;
}

sp_externalities::decl_extension! {
    pub struct HostFunctionExtension(Arc<dyn HostFunctions>);
}

impl HostFunctionExtension {
    /// Create a new instance of [`HostFunctionExtension`].
    pub fn new(inner: Arc<dyn HostFunctions>) -> Self {
        Self(inner)
    }
}

/// Implementation of host functions for Certificate registry.
#[derive(Default)]
pub struct HostFunctionsImpl;

impl HostFunctions for HostFunctionsImpl {
    fn verify_signature(&self, req: SignatureVerificationRequest) -> Option<()> {
        let SignatureVerificationRequest {
            public_key_info,
            signature_algorithm,
            data,
            signature,
        } = req;

        let (_, public_key_info) = SubjectPublicKeyInfo::from_der(public_key_info.as_ref()).ok()?;
        let (_, signature_algorithm) =
            AlgorithmIdentifier::from_der(signature_algorithm.as_ref()).ok()?;
        let signature = BitString::new(0, &signature);
        verify_signature(&public_key_info, &signature_algorithm, &signature, &data).ok()
    }

    fn decode_tbs_certificate(&self, certificate: DerVec) -> Option<TbsCertificate> {
        let (_, tbs_certificate) =
            x509_parser::certificate::TbsCertificate::from_der(certificate.as_ref()).ok()?;
        let serial = U256::from_big_endian(&tbs_certificate.serial.to_bytes_be());
        let validity = Validity::try_from(tbs_certificate.validity).ok()?;
        let subject_dn = SubjectDistinguishedName::try_from(tbs_certificate.subject).ok()?;

        Some(TbsCertificate {
            serial,
            subject: subject_dn,
            subject_public_key_info: tbs_certificate.subject_pki.raw.to_vec().into(),
            validity,
        })
    }
}

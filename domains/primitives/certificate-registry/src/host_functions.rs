use crate::SignatureVerificationRequest;
use std::sync::Arc;
use x509_parser::der_parser::asn1_rs::BitString;
use x509_parser::prelude::{AlgorithmIdentifier, FromDer, SubjectPublicKeyInfo};
use x509_parser::verify::verify_signature;

/// Host function trait for Certificate registration
pub trait HostFunctions: Send + Sync {
    fn verify_signature(&self, req: SignatureVerificationRequest) -> Option<()>;
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
}

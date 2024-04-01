#[cfg(feature = "std")]
use crate::host_functions::HostFunctionExtension;
use crate::{DerVec, SignatureVerificationRequest, TbsCertificate};
#[cfg(feature = "std")]
use sp_externalities::ExternalitiesExt;
use sp_runtime_interface::runtime_interface;

/// AutoId runtime interface.
#[runtime_interface]
pub trait AutoIdRuntimeInterface {
    fn verify_signature(&mut self, req: SignatureVerificationRequest) -> Option<()> {
        self.extension::<HostFunctionExtension>()
            .expect(
                "No `CertificateRegistryHostFunctionExtension` associated for the current context!",
            )
            .verify_signature(req)
    }

    fn decode_tbs_certificate(&mut self, certificate: DerVec) -> Option<TbsCertificate> {
        self.extension::<HostFunctionExtension>()
            .expect(
                "No `CertificateRegistryHostFunctionExtension` associated for the current context!",
            )
            .decode_tbs_certificate(certificate)
    }
}

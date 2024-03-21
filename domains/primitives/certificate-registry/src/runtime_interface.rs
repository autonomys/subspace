#[cfg(feature = "std")]
use crate::host_functions::HostFunctionExtension;
use crate::SignatureVerificationRequest;
#[cfg(feature = "std")]
use sp_externalities::ExternalitiesExt;
use sp_runtime_interface::runtime_interface;

/// Signature verification runtime interface.
#[runtime_interface]
pub trait SignatureVerificationRuntimeInterface {
    #[allow(dead_code)]
    fn verify_signature(&mut self, req: SignatureVerificationRequest) -> Option<()> {
        self.extension::<HostFunctionExtension>()
            .expect(
                "No `CertificateRegistryHostFunctionExtension` associated for the current context!",
            )
            .verify_signature(req)
    }
}

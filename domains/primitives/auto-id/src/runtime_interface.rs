use crate::{DerVec, SignatureVerificationRequest, TbsCertificate};
use sp_runtime_interface::runtime_interface;

/// AutoId runtime interface.
#[runtime_interface]
pub trait AutoIdRuntimeInterface {
    fn verify_signature(&mut self, req: SignatureVerificationRequest) -> Option<()> {
        // TODO: we need to conditional compile for benchmarks here since
        //  benchmark externalities does not provide custom extensions.
        //  Remove this once the issue is resolved: https://github.com/paritytech/polkadot-sdk/issues/137
        #[cfg(feature = "runtime-benchmarks")]
        {
            use crate::host_functions::verify_signature;
            verify_signature(req)
        }

        #[cfg(not(feature = "runtime-benchmarks"))]
        {
            use crate::host_functions::HostFunctionExtension;
            use sp_externalities::ExternalitiesExt;
            self.extension::<HostFunctionExtension>()
                .expect("No `AutoIdHostFunctionExtension` associated for the current context!")
                .verify_signature(req)
        }
    }

    fn decode_tbs_certificate(&mut self, certificate: DerVec) -> Option<TbsCertificate> {
        // TODO: we need to conditional compile for benchmarks here since
        //  benchmark externalities does not provide custom extensions.
        //  Remove this once the issue is resolved: https://github.com/paritytech/polkadot-sdk/issues/137
        #[cfg(feature = "runtime-benchmarks")]
        {
            use crate::host_functions::decode_tbs_certificate;
            decode_tbs_certificate(certificate)
        }

        #[cfg(not(feature = "runtime-benchmarks"))]
        {
            use crate::host_functions::HostFunctionExtension;
            use sp_externalities::ExternalitiesExt;
            self.extension::<HostFunctionExtension>()
                .expect("No `AutoIdHostFunctionExtension` associated for the current context!")
                .decode_tbs_certificate(certificate)
        }
    }
}

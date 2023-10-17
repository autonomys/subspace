#[cfg(feature = "std")]
use crate::FraudProofExtension;
use crate::{FraudProofVerificationInfoRequest, FraudProofVerificationInfoResponse};
use sp_core::H256;
use sp_domains::DomainId;
#[cfg(feature = "std")]
use sp_externalities::ExternalitiesExt;
use sp_runtime::OpaqueExtrinsic;
use sp_runtime_interface::runtime_interface;
use sp_std::vec::Vec;

/// Domain fraud proof related runtime interface
#[runtime_interface]
pub trait FraudProofRuntimeInterface {
    /// Returns required fraud proof verification information to the runtime through host function.
    fn get_fraud_proof_verification_info(
        &mut self,
        consensus_block_hash: H256,
        fraud_proof_verification_req: FraudProofVerificationInfoRequest,
    ) -> Option<FraudProofVerificationInfoResponse> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .get_fraud_proof_verification_info(consensus_block_hash, fraud_proof_verification_req)
    }

    /// Derive the bundle digest for the given bundle body.
    fn derive_bundle_digest(
        &mut self,
        consensus_block_hash: H256,
        domain_id: DomainId,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<H256> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .derive_bundle_digest(consensus_block_hash, domain_id, bundle_body)
    }
}

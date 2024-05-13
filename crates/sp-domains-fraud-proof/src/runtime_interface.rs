#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
use crate::FraudProofExtension;
use crate::{
    DomainInherentExtrinsic, DomainInherentExtrinsicData, DomainStorageKeyRequest,
    FraudProofVerificationInfoRequest, FraudProofVerificationInfoResponse,
    StatelessDomainRuntimeCall,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use domain_runtime_primitives::BlockNumber;
use sp_core::H256;
use sp_domains::DomainId;
#[cfg(feature = "std")]
use sp_externalities::ExternalitiesExt;
use sp_runtime::OpaqueExtrinsic;
use sp_runtime_interface::runtime_interface;

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
    #[version(1)]
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

    /// Derive the bundle digest for the given bundle body.
    #[version(2)]
    fn derive_bundle_digest(
        &mut self,
        domain_runtime_code: Vec<u8>,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<H256> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .derive_bundle_digest_v2(domain_runtime_code, bundle_body)
    }

    /// Check the execution proof
    // TODO: remove before the new network
    #[version(1)]
    fn execution_proof_check(
        &mut self,
        pre_state_root: H256,
        encoded_proof: Vec<u8>,
        execution_method: &str,
        call_data: &[u8],
        domain_runtime_code: Vec<u8>,
    ) -> Option<Vec<u8>> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .execution_proof_check(
                (Default::default(), Default::default()),
                pre_state_root,
                encoded_proof,
                execution_method,
                call_data,
                domain_runtime_code,
            )
    }

    /// Check the execution proof with also included domain block id.
    #[version(2)]
    fn execution_proof_check(
        &mut self,
        domain_block_id: (BlockNumber, H256),
        pre_state_root: H256,
        encoded_proof: Vec<u8>,
        execution_method: &str,
        call_data: &[u8],
        domain_runtime_code: Vec<u8>,
    ) -> Option<Vec<u8>> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .execution_proof_check(
                domain_block_id,
                pre_state_root,
                encoded_proof,
                execution_method,
                call_data,
                domain_runtime_code,
            )
    }

    #[version(1)]
    fn check_extrinsics_in_single_context(
        &mut self,
        domain_runtime_code: Vec<u8>,
        domain_block_id: (BlockNumber, H256),
        domain_block_state_root: H256,
        bundle_extrinsics: Vec<OpaqueExtrinsic>,
        encoded_proof: Vec<u8>,
    ) -> Option<Option<u32>> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .check_extrinsics_in_single_context(
                domain_runtime_code,
                domain_block_id,
                domain_block_state_root,
                bundle_extrinsics,
                encoded_proof,
            )
    }

    #[version(1)]
    fn construct_domain_inherent_extrinsic(
        &mut self,
        domain_runtime_code: Vec<u8>,
        domain_inherent_extrinsic_data: DomainInherentExtrinsicData,
    ) -> Option<DomainInherentExtrinsic> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .construct_domain_inherent_extrinsic(
                domain_runtime_code,
                domain_inherent_extrinsic_data,
            )
    }

    #[version(1)]
    fn domain_storage_key(
        &mut self,
        domain_runtime_code: Vec<u8>,
        req: DomainStorageKeyRequest,
    ) -> Option<Vec<u8>> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .domain_storage_key(domain_runtime_code, req)
    }

    #[version(1)]
    fn domain_runtime_call(
        &mut self,
        domain_runtime_code: Vec<u8>,
        call: StatelessDomainRuntimeCall,
    ) -> Option<bool> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .domain_runtime_call(domain_runtime_code, call)
    }
}

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
use crate::FraudProofExtension;
use crate::{
    DomainInherentExtrinsic, DomainInherentExtrinsicData, DomainStorageKeyRequest,
    StatelessDomainRuntimeCall,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use domain_runtime_primitives::BlockNumber;
use sp_core::H256;
#[cfg(feature = "std")]
use sp_externalities::ExternalitiesExt;
use sp_runtime::OpaqueExtrinsic;
use sp_runtime_interface::runtime_interface;
use sp_weights::Weight;

/// Domain fraud proof related runtime interface
#[runtime_interface]
pub trait FraudProofRuntimeInterface {
    /// Derive the bundle digest for the given bundle body.
    fn derive_bundle_digest(
        &mut self,
        domain_runtime_code: Vec<u8>,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<H256> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .derive_bundle_digest(domain_runtime_code, bundle_body)
    }

    /// Check the execution proof with also included domain block id.
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

    fn domain_storage_key(
        &mut self,
        domain_runtime_code: Vec<u8>,
        req: DomainStorageKeyRequest,
    ) -> Option<Vec<u8>> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .domain_storage_key(domain_runtime_code, req)
    }

    fn domain_runtime_call(
        &mut self,
        domain_runtime_code: Vec<u8>,
        call: StatelessDomainRuntimeCall,
    ) -> Option<bool> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .domain_runtime_call(domain_runtime_code, call)
    }

    fn bundle_weight(
        &mut self,
        domain_runtime_code: Vec<u8>,
        bundle_body: Vec<OpaqueExtrinsic>,
    ) -> Option<Weight> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .bundle_weight(domain_runtime_code, bundle_body)
    }

    fn extract_xdm_mmr_proof(
        &mut self,
        domain_runtime_code: Vec<u8>,
        opaque_extrinsic: Vec<u8>,
    ) -> Option<Option<Vec<u8>>> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .extract_xdm_mmr_proof(domain_runtime_code, opaque_extrinsic)
    }
}

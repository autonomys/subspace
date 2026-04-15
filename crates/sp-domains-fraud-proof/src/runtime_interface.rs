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
use sp_runtime_interface::pass_by::{
    AllocateAndReturnByCodec, PassFatPointerAndDecode, PassFatPointerAndRead,
    PassPointerAndReadCopy,
};
use sp_runtime_interface::runtime_interface;
use sp_weights::Weight;

/// Domain fraud proof related runtime interface
#[runtime_interface]
pub trait FraudProofRuntimeInterface {
    /// Derive the bundle digest for the given bundle body.
    fn derive_bundle_digest(
        &mut self,
        domain_runtime_code: PassFatPointerAndDecode<Vec<u8>>,
        bundle_body: PassFatPointerAndDecode<Vec<OpaqueExtrinsic>>,
    ) -> AllocateAndReturnByCodec<Option<H256>> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .derive_bundle_digest(domain_runtime_code, bundle_body)
    }

    /// Check the execution proof with also included domain block id.
    fn execution_proof_check(
        &mut self,
        domain_block_id: PassFatPointerAndDecode<(BlockNumber, H256)>,
        pre_state_root: PassPointerAndReadCopy<H256, 32>,
        encoded_proof: PassFatPointerAndDecode<Vec<u8>>,
        execution_method: PassFatPointerAndRead<&str>,
        call_data: PassFatPointerAndRead<&[u8]>,
        domain_runtime_code: PassFatPointerAndDecode<Vec<u8>>,
    ) -> AllocateAndReturnByCodec<Option<Vec<u8>>> {
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
        domain_runtime_code: PassFatPointerAndDecode<Vec<u8>>,
        domain_block_id: PassFatPointerAndDecode<(BlockNumber, H256)>,
        domain_block_state_root: PassPointerAndReadCopy<H256, 32>,
        bundle_extrinsics: PassFatPointerAndDecode<Vec<OpaqueExtrinsic>>,
        encoded_proof: PassFatPointerAndDecode<Vec<u8>>,
    ) -> AllocateAndReturnByCodec<Option<Option<u32>>> {
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
        domain_runtime_code: PassFatPointerAndDecode<Vec<u8>>,
        domain_inherent_extrinsic_data: PassFatPointerAndDecode<DomainInherentExtrinsicData>,
    ) -> AllocateAndReturnByCodec<Option<DomainInherentExtrinsic>> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .construct_domain_inherent_extrinsic(
                domain_runtime_code,
                domain_inherent_extrinsic_data,
            )
    }

    fn domain_storage_key(
        &mut self,
        domain_runtime_code: PassFatPointerAndDecode<Vec<u8>>,
        req: PassFatPointerAndDecode<DomainStorageKeyRequest>,
    ) -> AllocateAndReturnByCodec<Option<Vec<u8>>> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .domain_storage_key(domain_runtime_code, req)
    }

    fn domain_runtime_call(
        &mut self,
        domain_runtime_code: PassFatPointerAndDecode<Vec<u8>>,
        call: PassFatPointerAndDecode<StatelessDomainRuntimeCall>,
    ) -> AllocateAndReturnByCodec<Option<bool>> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .domain_runtime_call(domain_runtime_code, call)
    }

    fn bundle_weight(
        &mut self,
        domain_runtime_code: PassFatPointerAndDecode<Vec<u8>>,
        bundle_body: PassFatPointerAndDecode<Vec<OpaqueExtrinsic>>,
    ) -> AllocateAndReturnByCodec<Option<Weight>> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .bundle_weight(domain_runtime_code, bundle_body)
    }

    fn extract_xdm_mmr_proof(
        &mut self,
        domain_runtime_code: PassFatPointerAndDecode<Vec<u8>>,
        opaque_extrinsic: PassFatPointerAndDecode<Vec<u8>>,
    ) -> AllocateAndReturnByCodec<Option<Option<Vec<u8>>>> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .extract_xdm_mmr_proof(domain_runtime_code, opaque_extrinsic)
    }
}

#[cfg(feature = "std")]
use crate::FraudProofExtension;
use crate::InvalidDomainExtrinsicRootInfo;
use sp_core::H256;
use sp_domains::DomainId;
#[cfg(feature = "std")]
use sp_externalities::ExternalitiesExt;
use sp_runtime_interface::runtime_interface;

/// Domain fraud proof related runtime interface
#[runtime_interface]
pub trait FraudProofRuntimeInterface {
    fn get_invalid_domain_extrinsic_root_info(
        &mut self,
        consensus_block_hash: H256,
        domain_id: DomainId,
    ) -> Option<InvalidDomainExtrinsicRootInfo> {
        self.extension::<FraudProofExtension>()
            .expect("No `FraudProofExtension` associated for the current context!")
            .get_invalid_domain_extrinsic_root_info(consensus_block_hash, domain_id)
    }
}

#[cfg(feature = "std")]
use crate::host_functions::MessengerExtension;
use crate::StorageKeyRequest;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use sp_domains::ChainId;
#[cfg(feature = "std")]
use sp_externalities::ExternalitiesExt;
use sp_runtime_interface::runtime_interface;

/// Messenger related runtime interface
#[runtime_interface]
pub trait MessengerRuntimeInterface {
    /// Returns the storage key.
    fn get_storage_key(&mut self, req: StorageKeyRequest) -> Option<Vec<u8>> {
        self.extension::<MessengerExtension>()
            .expect("No `MessengerExtension` associated for the current context!")
            .get_storage_key(req)
    }

    fn is_src_chain_in_dst_chain_allowlist(
        &mut self,
        src_chain_id: ChainId,
        dst_chain_id: ChainId,
    ) -> bool {
        self.extension::<MessengerExtension>()
            .expect("No `MessengerExtension` associated for the current context!")
            .is_src_chain_in_dst_chain_allowlist(src_chain_id, dst_chain_id)
    }
}

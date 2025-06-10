use crate::StorageKeyRequest;
#[cfg(feature = "std")]
use crate::host_functions::MessengerExtension;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
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
}

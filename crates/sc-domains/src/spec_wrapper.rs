//! Wrappers for ChainSpecs, to modify their properties at runtime.
//!
//! TODO: remove when all the actual chain specs have been updated.

use sc_chain_spec::{ChainSpec, ChainType, GetExtension, Properties};
use sc_network::config::MultiaddrWithPeerId;
use sc_telemetry::TelemetryEndpoints;
use sp_runtime::{BuildStorage, Storage};

/// ChainSpec wrapper which overrides the chain type to Live for consensus and domain chains deployed
/// with `ChainType::Custom(...)`.
pub struct ChainSpecTypeOverride<T: ChainSpec + ?Sized + 'static> {
    pub inner: Box<T>,
}

impl<T: ChainSpec + ?Sized + 'static> ChainSpecTypeOverride<T> {
    pub fn wrap(inner: Box<T>) -> Box<dyn ChainSpec> {
        Box::new(Self { inner })
    }
}

impl<T: ChainSpec + ?Sized + 'static> ChainSpec for ChainSpecTypeOverride<T> {
    fn chain_type(&self) -> ChainType {
        if let ChainType::Custom(custom_type) = self.inner.chain_type() {
            if custom_type == "Autonomys Mainnet" {
                return ChainType::Live;
            } else if custom_type == "SubspaceDomain"
                && (self.inner.id() == "autonomys_evm_domain"
                    || self.inner.id() == "autonomys_auto_id_domain")
            {
                // All domains deployed after this should be set to Live in their chainspec and code.
                return ChainType::Live;
            }
        }

        self.inner.chain_type()
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn id(&self) -> &str {
        self.inner.id()
    }

    fn boot_nodes(&self) -> &[MultiaddrWithPeerId] {
        self.inner.boot_nodes()
    }

    fn telemetry_endpoints(&self) -> &Option<TelemetryEndpoints> {
        self.inner.telemetry_endpoints()
    }

    fn protocol_id(&self) -> Option<&str> {
        self.inner.protocol_id()
    }

    fn fork_id(&self) -> Option<&str> {
        self.inner.fork_id()
    }

    fn properties(&self) -> Properties {
        self.inner.properties()
    }

    fn extensions(&self) -> &dyn GetExtension {
        self.inner.extensions()
    }

    fn extensions_mut(&mut self) -> &mut dyn GetExtension {
        self.inner.extensions_mut()
    }

    fn add_boot_node(&mut self, addr: MultiaddrWithPeerId) {
        self.inner.add_boot_node(addr)
    }

    fn as_json(&self, raw: bool) -> Result<String, String> {
        self.inner.as_json(raw)
    }

    fn as_storage_builder(&self) -> &dyn BuildStorage {
        self.inner.as_storage_builder()
    }

    fn cloned_box(&self) -> Box<dyn ChainSpec> {
        ChainSpecTypeOverride::wrap(self.inner.cloned_box())
    }

    fn set_storage(&mut self, storage: Storage) {
        self.inner.set_storage(storage)
    }

    fn code_substitutes(&self) -> std::collections::BTreeMap<String, Vec<u8>> {
        self.inner.code_substitutes()
    }
}

impl<T: ChainSpec + ?Sized + 'static> BuildStorage for ChainSpecTypeOverride<T> {
    fn build_storage(&self) -> Result<Storage, String> {
        self.inner.build_storage()
    }

    fn assimilate_storage(&self, storage: &mut Storage) -> Result<(), String> {
        self.inner.assimilate_storage(storage)
    }
}

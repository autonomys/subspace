use frame_support::traits::Get;
use sc_chain_spec::{
    ChainSpec, ChainType, GenericChainSpec, GetExtension, NoExtension, RuntimeGenesis,
};
use sc_service::config::MultiaddrWithPeerId;
use sc_service::Properties;
use sc_telemetry::TelemetryEndpoints;
use serde::de::Visitor;
use serde::ser::Error as _;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sp_core::crypto::AccountId32;
use sp_core::storage::Storage;
use sp_core::{sr25519, Pair, Public};
use sp_runtime::traits::IdentifyAccount;
use sp_runtime::{BuildStorage, MultiSigner};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::path::PathBuf;
use subspace_runtime::SS58Prefix;
use subspace_runtime_primitives::DECIMAL_PLACES;

/// Shared chain spec properties related to the coin.
pub(crate) fn chain_spec_properties() -> Properties {
    let mut properties = Properties::new();

    properties.insert("ss58Format".into(), <SS58Prefix as Get<u16>>::get().into());
    properties.insert("tokenDecimals".into(), DECIMAL_PLACES.into());
    properties.insert("tokenSymbol".into(), "tSSC".into());

    properties
}

/// Get public key from keypair seed.
pub(crate) fn get_public_key_from_seed<TPublic: Public>(
    seed: &'static str,
) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{}", seed), None)
        .expect("Static values are valid; qed")
        .public()
}

/// Generate an account ID from seed.
pub(crate) fn get_account_id_from_seed(seed: &'static str) -> AccountId32 {
    MultiSigner::from(get_public_key_from_seed::<sr25519::Public>(seed)).into_account()
}

pub struct SerializableChainSpec<GenesisConfig, Extensions = NoExtension> {
    chain_spec: GenericChainSpec<GenesisConfig, Extensions>,
}

impl<GenesisConfig, Extensions> Clone for SerializableChainSpec<GenesisConfig, Extensions>
where
    Extensions: Clone,
{
    fn clone(&self) -> Self {
        Self {
            chain_spec: self.chain_spec.clone(),
        }
    }
}

impl<GenesisConfig, Extensions> Serialize for SerializableChainSpec<GenesisConfig, Extensions>
where
    GenesisConfig: RuntimeGenesis + 'static,
    Extensions: GetExtension + Serialize + Clone + Send + Sync + 'static,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_json(true).map_err(S::Error::custom)?)
    }
}

impl<'de, GenesisConfig, Extensions> Deserialize<'de>
    for SerializableChainSpec<GenesisConfig, Extensions>
where
    Extensions: de::DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringVisitor<GenesisConfig, Extensions> {
            _phantom_data: PhantomData<(GenesisConfig, Extensions)>,
        }

        impl<'de, GenesisConfig, Extensions> Visitor<'de> for StringVisitor<GenesisConfig, Extensions>
        where
            Extensions: de::DeserializeOwned,
        {
            type Value = SerializableChainSpec<GenesisConfig, Extensions>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("ExecutionChainSpec")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_string(value.to_string())
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Self::Value::from_json_bytes(value.into_bytes()).map_err(E::custom)
            }
        }
        deserializer.deserialize_string(StringVisitor {
            _phantom_data: PhantomData::default(),
        })
    }
}

impl<GenesisConfig, Extensions> BuildStorage for SerializableChainSpec<GenesisConfig, Extensions>
where
    GenesisConfig: RuntimeGenesis,
{
    fn assimilate_storage(&self, storage: &mut Storage) -> Result<(), String> {
        self.chain_spec.assimilate_storage(storage)
    }
}

impl<GenesisConfig, Extensions> ChainSpec for SerializableChainSpec<GenesisConfig, Extensions>
where
    GenesisConfig: RuntimeGenesis + 'static,
    Extensions: GetExtension + Serialize + Clone + Send + Sync + 'static,
{
    fn name(&self) -> &str {
        self.chain_spec.name()
    }

    fn id(&self) -> &str {
        self.chain_spec.id()
    }

    fn chain_type(&self) -> ChainType {
        ChainSpec::chain_type(&self.chain_spec)
    }

    fn boot_nodes(&self) -> &[MultiaddrWithPeerId] {
        self.chain_spec.boot_nodes()
    }

    fn telemetry_endpoints(&self) -> &Option<TelemetryEndpoints> {
        self.chain_spec.telemetry_endpoints()
    }

    fn protocol_id(&self) -> Option<&str> {
        self.chain_spec.protocol_id()
    }

    fn fork_id(&self) -> Option<&str> {
        self.chain_spec.fork_id()
    }

    fn properties(&self) -> Properties {
        self.chain_spec.properties()
    }

    fn extensions(&self) -> &dyn GetExtension {
        self.chain_spec.extensions()
    }

    fn extensions_mut(&mut self) -> &mut dyn GetExtension {
        self.chain_spec.extensions_mut()
    }

    fn add_boot_node(&mut self, addr: MultiaddrWithPeerId) {
        self.chain_spec.add_boot_node(addr)
    }

    fn as_json(&self, raw: bool) -> Result<String, String> {
        self.chain_spec.as_json(raw)
    }

    fn as_storage_builder(&self) -> &dyn BuildStorage {
        self.chain_spec.as_storage_builder()
    }

    fn cloned_box(&self) -> Box<dyn ChainSpec> {
        self.chain_spec.cloned_box()
    }

    fn set_storage(&mut self, storage: Storage) {
        self.chain_spec.set_storage(storage)
    }

    fn code_substitutes(&self) -> BTreeMap<String, Vec<u8>> {
        self.chain_spec.code_substitutes()
    }
}

impl<GenesisConfig, Extensions> SerializableChainSpec<GenesisConfig, Extensions>
where
    GenesisConfig: RuntimeGenesis + 'static,
    Extensions: GetExtension + Serialize + Clone + Send + Sync + 'static,
{
    /// A list of bootnode addresses.
    pub fn boot_nodes(&self) -> &[MultiaddrWithPeerId] {
        self.chain_spec.boot_nodes()
    }

    /// Spec name.
    pub fn name(&self) -> &str {
        self.chain_spec.name()
    }

    /// Spec id.
    pub fn id(&self) -> &str {
        self.chain_spec.id()
    }

    /// Telemetry endpoints (if any)
    pub fn telemetry_endpoints(&self) -> &Option<TelemetryEndpoints> {
        self.chain_spec.telemetry_endpoints()
    }

    /// Network protocol id.
    pub fn protocol_id(&self) -> Option<&str> {
        self.chain_spec.protocol_id()
    }

    /// Optional network fork identifier.
    pub fn fork_id(&self) -> Option<&str> {
        self.chain_spec.fork_id()
    }

    /// Additional loosly-typed properties of the chain.
    ///
    /// Returns an empty JSON object if 'properties' not defined in config
    pub fn properties(&self) -> Properties {
        self.chain_spec.properties()
    }

    /// Add a bootnode to the list.
    pub fn add_boot_node(&mut self, addr: MultiaddrWithPeerId) {
        self.chain_spec.add_boot_node(addr)
    }

    /// Returns a reference to the defined chain spec extensions.
    pub fn extensions(&self) -> &Extensions {
        self.chain_spec.extensions()
    }

    /// Returns a mutable reference to the defined chain spec extensions.
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        self.chain_spec.extensions_mut()
    }

    /// Create hardcoded spec.
    #[allow(clippy::too_many_arguments)]
    pub fn from_genesis<F: Fn() -> GenesisConfig + 'static + Send + Sync>(
        name: &str,
        id: &str,
        chain_type: ChainType,
        constructor: F,
        boot_nodes: Vec<MultiaddrWithPeerId>,
        telemetry_endpoints: Option<TelemetryEndpoints>,
        protocol_id: Option<&str>,
        fork_id: Option<&str>,
        properties: Option<Properties>,
        extensions: Extensions,
    ) -> Self {
        Self {
            chain_spec: GenericChainSpec::from_genesis(
                name,
                id,
                chain_type,
                constructor,
                boot_nodes,
                telemetry_endpoints,
                protocol_id,
                fork_id,
                properties,
                extensions,
            ),
        }
    }
}

impl<GenesisConfig, Extensions> SerializableChainSpec<GenesisConfig, Extensions>
where
    Extensions: de::DeserializeOwned,
{
    /// Parse json content into a `ChainSpec`
    pub fn from_json_bytes(json: impl Into<Cow<'static, [u8]>>) -> Result<Self, String> {
        GenericChainSpec::from_json_bytes(json).map(|chain_spec| Self { chain_spec })
    }

    /// Parse json file into a `ChainSpec`
    pub fn from_json_file(path: PathBuf) -> Result<Self, String> {
        GenericChainSpec::from_json_file(path).map(|chain_spec| Self { chain_spec })
    }
}

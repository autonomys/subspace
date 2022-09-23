use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Custom wrapper so we don't have to write serialization/deserialization code manually
#[derive(Serialize, Deserialize)]
struct Commitment(#[serde(with = "hex::serde")] pub(super) [u8; 48]);

impl Serialize for super::Commitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Commitment(self.to_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for super::Commitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Commitment(bytes) = Commitment::deserialize(deserializer)?;
        Self::try_from_bytes(&bytes).map_err(|error| D::Error::custom(format!("{error:?}")))
    }
}

// Custom wrapper so we don't have to write serialization/deserialization code manually
#[derive(Serialize, Deserialize)]
struct Witness(#[serde(with = "hex::serde")] pub(super) [u8; 48]);

impl Serialize for super::Witness {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Witness(self.to_bytes()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for super::Witness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Witness(bytes) = Witness::deserialize(deserializer)?;
        Self::try_from_bytes(&bytes).map_err(|error| D::Error::custom(format!("{error:?}")))
    }
}

use crate::{FlatPieces, PIECE_SIZE};
use hex::{decode_to_slice, FromHex, FromHexError};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

impl FromHex for FlatPieces {
    type Error = FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let hex = hex.as_ref();
        if hex.len() % 2 != 0 {
            return Err(FromHexError::OddLength);
        }
        if hex.len() % (2 * PIECE_SIZE) != 0 {
            return Err(FromHexError::InvalidStringLength);
        }

        let mut out = FlatPieces::new(hex.len() / 2 / PIECE_SIZE);

        hex.chunks_exact(2 * PIECE_SIZE)
            .zip(out.iter_mut())
            .try_for_each(|(bytes, piece)| decode_to_slice(bytes, piece.as_mut()))?;

        Ok(out)
    }
}

impl Serialize for FlatPieces {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Serializer::serialize_newtype_struct(serializer, "FlatPieces", {
            struct SerializeWith<'a> {
                values: &'a [u8],
            }
            impl<'a> Serialize for SerializeWith<'a> {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: Serializer,
                {
                    hex::serde::serialize(self.values, serializer)
                }
            }
            &SerializeWith {
                values: self.as_ref(),
            }
        })
    }
}

impl<'de> Deserialize<'de> for FlatPieces {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = FlatPieces;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("tuple struct FlatPieces")
            }

            #[inline]
            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                hex::serde::deserialize(deserializer)
            }

            #[inline]
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                struct DeserializeWith {
                    value: FlatPieces,
                }
                impl<'de> Deserialize<'de> for DeserializeWith {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: Deserializer<'de>,
                    {
                        Ok(DeserializeWith {
                            value: hex::serde::deserialize(deserializer)?,
                        })
                    }
                }

                de::SeqAccess::next_element::<DeserializeWith>(&mut seq)?
                    .map(|wrap| wrap.value)
                    .ok_or(de::Error::invalid_length(
                        0usize,
                        &"tuple struct FlatPieces with 1 element",
                    ))
            }
        }
        Deserializer::deserialize_newtype_struct(deserializer, "FlatPieces", Visitor)
    }
}

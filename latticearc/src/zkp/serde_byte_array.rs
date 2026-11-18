//! Serde adapter for fixed-size byte arrays in ZKP wire types.
//!
//! `serde` implements `Serialize`/`Deserialize` for arrays only up to 32
//! elements and encodes them as tuples; compressed curve points are 33
//! bytes. This adapter encodes `[u8; N]` with `serialize_bytes` (a JSON
//! array of numbers, a CBOR/bincode byte string) and accepts either a byte
//! string or a sequence of exactly `N` integers back. That is the same wire
//! form the crate produced with `serde_with::Bytes`, so serialized proofs
//! and commitments from earlier versions still deserialize.

use std::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserializer, Serializer};

/// Serialize `bytes` as a byte string.
///
/// # Errors
/// Propagates the serializer's error.
pub(crate) fn serialize<S: Serializer, const N: usize>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(bytes)
}

/// Deserialize exactly `N` bytes from a byte string or a sequence.
///
/// # Errors
/// Fails when the input is neither, or its length is not `N`.
pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    deserializer.deserialize_bytes(ByteArrayVisitor::<N>)
}

struct ByteArrayVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for ByteArrayVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a byte array of length {N}")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        <[u8; N]>::try_from(v).map_err(|_e| E::invalid_length(v.len(), &self))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = [0u8; N];
        for (filled, slot) in out.iter_mut().enumerate() {
            *slot = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(filled, &self))?;
        }
        if seq.next_element::<u8>()?.is_some() {
            return Err(de::Error::invalid_length(N.saturating_add(1), &self));
        }
        Ok(out)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test scaffolding")]
mod tests {
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Probe {
        #[serde(with = "super")]
        point: [u8; 33],
    }

    fn sample() -> Probe {
        let mut point = [0u8; 33];
        for (i, b) in point.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        Probe { point }
    }

    #[test]
    fn test_byte_array_json_shape_and_roundtrip_succeeds() {
        let json = serde_json::to_string(&sample()).unwrap();
        let expected = format!(
            "{{\"point\":[{}]}}",
            (0..33).map(|i: u8| i.to_string()).collect::<Vec<_>>().join(",")
        );
        assert_eq!(json, expected);
        assert_eq!(serde_json::from_str::<Probe>(&json).unwrap(), sample());
    }

    #[test]
    fn test_byte_array_rejects_wrong_length_fails() {
        let short = format!("{{\"point\":[{}]}}", vec!["0"; 32].join(","));
        assert!(serde_json::from_str::<Probe>(&short).is_err());
        let long = format!("{{\"point\":[{}]}}", vec!["0"; 34].join(","));
        assert!(serde_json::from_str::<Probe>(&long).is_err());
        assert!(serde_json::from_str::<Probe>(r#"{"point":"abc"}"#).is_err());
        let overflow = format!("{{\"point\":[256{}]}}", ",0".repeat(32));
        assert!(serde_json::from_str::<Probe>(&overflow).is_err());
    }
}

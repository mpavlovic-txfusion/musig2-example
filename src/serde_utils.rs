use musig2::{CompactSignature, KeyAggContext, PartialSignature};
use secp256k1::PublicKey;
use std::collections::HashMap;

pub fn serialize_public_key<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(key.serialize()))
}

pub fn deserialize_public_key<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
    PublicKey::from_slice(&bytes).map_err(serde::de::Error::custom)
}

pub fn serialize_pubkey_map<S>(
    map: &HashMap<PublicKey, Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;
    let mut map_ser = serializer.serialize_map(Some(map.len()))?;
    for (k, v) in map {
        map_ser.serialize_entry(&hex::encode(k.serialize()), v)?;
    }
    map_ser.end()
}

pub fn deserialize_pubkey_map<'de, D>(
    deserializer: D,
) -> Result<HashMap<PublicKey, Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let string_map: HashMap<String, Vec<u8>> = serde::Deserialize::deserialize(deserializer)?;
    let mut result = HashMap::new();
    for (k, v) in string_map {
        let bytes = hex::decode(k).map_err(serde::de::Error::custom)?;
        let pubkey = PublicKey::from_slice(&bytes).map_err(serde::de::Error::custom)?;
        result.insert(pubkey, v);
    }
    Ok(result)
}

pub fn serialize_key_agg_ctx<S>(ctx: &KeyAggContext, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let bytes = ctx.serialize();
    serializer.serialize_bytes(&bytes)
}

pub fn deserialize_key_agg_ctx<'de, D>(deserializer: D) -> Result<KeyAggContext, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
    KeyAggContext::from_bytes(&bytes).map_err(serde::de::Error::custom)
}

pub fn serialize_partial_signature<S>(
    sig: &PartialSignature,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_bytes(&sig.serialize())
}

pub fn deserialize_partial_signature<'de, D>(deserializer: D) -> Result<PartialSignature, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
    PartialSignature::from_slice(&bytes).map_err(serde::de::Error::custom)
}

pub fn serialize_compact_signature<S>(
    sig: &CompactSignature,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(sig.serialize()))
}

pub fn deserialize_compact_signature<'de, D>(deserializer: D) -> Result<CompactSignature, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
    CompactSignature::from_bytes(&bytes).map_err(serde::de::Error::custom)
}

pub fn serialize_partial_sig_map<S>(
    map: &HashMap<usize, PartialSignature>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;
    let mut map_ser = serializer.serialize_map(Some(map.len()))?;
    for (k, v) in map {
        map_ser.serialize_entry(k, &v.serialize())?;
    }
    map_ser.end()
}

pub fn deserialize_partial_sig_map<'de, D>(
    deserializer: D,
) -> Result<HashMap<usize, PartialSignature>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let string_map: HashMap<usize, Vec<u8>> = serde::Deserialize::deserialize(deserializer)?;
    let mut result = HashMap::new();
    for (k, v) in string_map {
        let partial_sig = PartialSignature::from_slice(&v).map_err(serde::de::Error::custom)?;
        result.insert(k, partial_sig);
    }
    Ok(result)
}

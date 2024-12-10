use crate::serde_utils::{
    deserialize_compact_signature, deserialize_key_agg_ctx, deserialize_partial_sig_map,
    deserialize_partial_signature, deserialize_pubkey_map, deserialize_public_key,
    serialize_compact_signature, serialize_key_agg_ctx, serialize_partial_sig_map,
    serialize_partial_signature, serialize_pubkey_map, serialize_public_key,
};
use musig2::{CompactSignature, KeyAggContext, PartialSignature};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct NodeRegistration {
    pub address: String,
    #[serde(
        serialize_with = "serialize_public_key",
        deserialize_with = "deserialize_public_key"
    )]
    pub public_key: PublicKey,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigningInitiateRequest {
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigningSession {
    pub session_id: String,
    pub message: String,
    #[serde(
        serialize_with = "serialize_key_agg_ctx",
        deserialize_with = "deserialize_key_agg_ctx"
    )]
    pub key_agg_ctx: KeyAggContext,
    #[serde(
        serialize_with = "serialize_pubkey_map",
        deserialize_with = "deserialize_pubkey_map"
    )]
    pub public_nonces: HashMap<PublicKey, Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GenerateNonceRequest {
    pub session_id: String,
    pub message: String,
    #[serde(
        serialize_with = "serialize_key_agg_ctx",
        deserialize_with = "deserialize_key_agg_ctx"
    )]
    pub key_agg_ctx: KeyAggContext,
    pub signer_index: usize,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigningInitiateResponse {
    pub session_id: String,
    #[serde(
        serialize_with = "serialize_public_key",
        deserialize_with = "deserialize_public_key"
    )]
    pub aggregated_pubkey: PublicKey,
    #[serde(
        serialize_with = "serialize_compact_signature",
        deserialize_with = "deserialize_compact_signature"
    )]
    pub aggregated_signature: CompactSignature,
    pub is_signature_valid: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReceiveNoncesRequest {
    pub session_id: String,
    pub nonces: HashMap<usize, Vec<u8>>, // Maps signer_index to their public nonce
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReceiveNoncesResponse {
    #[serde(
        serialize_with = "serialize_partial_signature",
        deserialize_with = "deserialize_partial_signature"
    )]
    pub partial_signature: PartialSignature,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReceivePartialSignaturesRequest {
    pub session_id: String,
    #[serde(
        serialize_with = "serialize_partial_sig_map",
        deserialize_with = "deserialize_partial_sig_map"
    )]
    pub partial_signatures: HashMap<usize, PartialSignature>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReceivePartialSignaturesResponse {
    #[serde(
        serialize_with = "serialize_compact_signature",
        deserialize_with = "deserialize_compact_signature"
    )]
    pub final_signature: CompactSignature,
}

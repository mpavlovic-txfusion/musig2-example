use serde::{Deserialize, Serialize};

/// Message types for MuSig2 protocol
#[derive(Serialize, Deserialize, Debug)]
pub enum MessageType {
    PublicKey(String),         // Exchange public keys as hex strings
    PublicNonce(Vec<u8>),      // Exchange public nonces (serialized bytes)
    PartialSignature(Vec<u8>), // Exchange partial signatures (serialized bytes)
}

/// Unified message format
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub sender_port: u16,          // Identify the sender
    pub message_type: MessageType, // The type of message being sent
}

use std::{
    io::{Read, Write},
    net::TcpStream,
    str::FromStr,
    sync::{Arc, Mutex},
};

use musig2::{FirstRound, KeyAggContext, PubNonce, SecNonceSpices};
use rand::Rng;
use secp256k1::{PublicKey, SecretKey};

use crate::{
    message::types::{Message, MessageType},
    utils::state::SharedState,
};

pub fn handle_stream(
    mut stream: TcpStream,
    is_initiator: bool,
    own_port: u16,
    shared_state: Arc<Mutex<SharedState>>,
    secret_key: SecretKey,
    message: &[u8],
) {
    // Initiator sends initial message containing its public key
    if is_initiator {
        let public_key = shared_state.lock().unwrap().own_public_key;
        let message = Message {
            sender_port: own_port,
            message_type: MessageType::PublicKey(public_key.to_string()),
        };
        send_message(&mut stream, &message);
    }

    // Loop to read incoming messages
    let mut buffer = [0; 1024];
    while let Ok(bytes_read) = stream.read(&mut buffer) {
        if bytes_read == 0 {
            println!("Connection closed by peer");
            break;
        }

        // Deserialize the received message
        let received: Message =
            serde_json::from_slice(&buffer[..bytes_read]).expect("Failed to deserialize message");
        // println!("📥 Received message: {:?}", received);

        // Handle each message type
        match received.message_type {
            MessageType::PublicKey(key) => {
                handle_public_key(&key, shared_state.clone(), own_port);
            }
            MessageType::PublicNonce(nonce_bytes) => {
                let nonce = PubNonce::from_bytes(&nonce_bytes).expect("Invalid public nonce");
                println!("📤 Received PublicNonce: {:?}", nonce);
            }
            MessageType::PartialSignature(sig) => {
                println!("✍️ Received PartialSignature: {:?}", sig);
                // shared_state.lock().unwrap().add_partial_signature(sig);
            }
        }
    }
}

fn send_message(stream: &mut TcpStream, message: &Message) {
    let serialized = serde_json::to_vec(message).expect("Failed to serialize message");
    stream
        .write_all(&serialized)
        .expect("Failed to send message");
}

/// Handles received public keys and checks if all keys are collected to initialize the first round.
fn handle_public_key(key: &str, shared_state: Arc<Mutex<SharedState>>, own_port: u16) {
    println!("🔑 Received PublicKey: {:?}", key);
    let public_key = PublicKey::from_str(key).expect("Invalid public key format");

    let mut state = shared_state.lock().unwrap();
    state.add_public_key(public_key);

    // Check if all public keys are received
    if state.public_keys_received() {
        println!("✅ All public keys received. Initializing first round...");

        // Collect all public keys including the local key
        let pubkeys = state
            .public_keys
            .iter()
            .cloned()
            .chain(std::iter::once(state.own_public_key))
            .collect::<Vec<_>>();

        println!(
            "🔑 Initializing KeyAggContext with public keys: {:?}",
            pubkeys
        );

        let key_agg_ctx = KeyAggContext::new(pubkeys).expect("Failed to create KeyAggContext");

        // Generate public nonce
        println!("⏳ Generating public nonce...");
        let first_round = FirstRound::new(
            key_agg_ctx,
            rand::thread_rng().gen::<[u8; 32]>(),
            0,
            SecNonceSpices::new(),
        )
        .expect("Failed to initialize FirstRound");
        let public_nonce = first_round.our_public_nonce();

        // Store public nonce in state
        state.nonces.push(public_nonce.clone());

        println!(
            "📤 Broadcasting public nonce to all peers: {:?}",
            public_nonce
        );

        // Broadcast the nonce to all active connections
        let nonce_message = Message {
            sender_port: own_port,
            message_type: MessageType::PublicNonce(public_nonce.serialize().to_vec()),
        };
        let serialized_message =
            serde_json::to_vec(&nonce_message).expect("Failed to serialize message");

        for stream in &state.active_connections {
            stream
                .lock()
                .unwrap()
                .write_all(&serialized_message)
                .expect("Failed to send nonce to peer");
        }
    }
}

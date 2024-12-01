use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use musig2::{FirstRound, PartialSignature, PubNonce};
use secp256k1::PublicKey;

pub struct SharedState {
    pub own_public_key: PublicKey,   // The node's own public key
    pub public_keys: Vec<PublicKey>, // Received peers' public keys
    pub nonces: Vec<PubNonce>,       // All public nonces
    pub partial_signatures: Vec<PartialSignature>, // All partial signatures
    pub num_of_signers: usize,       // Total number of signers participating in the protocol
    pub active_connections: Vec<Arc<Mutex<TcpStream>>>, // Active peer connections
    pub first_round: Option<FirstRound>, // State for the first round of MuSig2
}

impl SharedState {
    pub fn new(own_public_key: PublicKey, num_of_signers: usize) -> Self {
        SharedState {
            own_public_key,
            public_keys: Vec::new(),
            nonces: Vec::new(),
            partial_signatures: Vec::new(),
            num_of_signers,
            active_connections: Vec::new(),
            first_round: None,
        }
    }

    pub fn add_public_key(&mut self, key: PublicKey) {
        self.public_keys.push(key);
    }

    pub fn add_nonce(&mut self, nonce: PubNonce) {
        self.nonces.push(nonce);
    }

    pub fn add_partial_signature(&mut self, sig: PartialSignature) {
        self.partial_signatures.push(sig);
    }

    pub fn add_connection(&mut self, stream: TcpStream) {
        let addr = stream.peer_addr().unwrap();
        // Only add if we don't already have a connection to this address
        if !self
            .active_connections
            .iter()
            .any(|conn| conn.lock().unwrap().peer_addr().unwrap() == addr)
        {
            self.active_connections.push(Arc::new(Mutex::new(stream)));
        }
    }

    pub fn public_keys_received(&self) -> bool {
        self.public_keys.len() == self.num_of_signers - 1
    }

    pub fn nonces_received(&self) -> bool {
        self.nonces.len() == self.num_of_signers - 1
    }

    pub fn partial_signatures_received(&self) -> bool {
        self.partial_signatures.len() == self.num_of_signers - 1
    }
}

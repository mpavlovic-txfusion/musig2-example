use musig2_example::network;

use clap::Parser;
use musig2_example::utils::state::SharedState;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::sync::{Arc, Mutex};

/// Command-line arguments parser
#[derive(Parser, Debug)]
struct Args {
    /// Port for this instance to listen on
    #[clap(long)]
    port: u16,

    /// List of peer ports to connect to
    #[clap(long)]
    peers: Vec<u16>,

    /// Total number of signers participating in the protocol
    #[clap(long)]
    num_of_signers: usize,
}

struct KeyPair {
    secret_key: SecretKey,
    public_key: PublicKey,
}

fn main() {
    let args = Args::parse();

    let message = b"Hello, MuSig2!";

    let port = args.port;
    let peer_ports = args.peers;
    let num_of_signers = args.num_of_signers;

    if num_of_signers != peer_ports.len() + 1 {
        eprintln!("❌ The num_of_signers value must equal the number of peers + 1 (this signer).");
        std::process::exit(1);
    }

    // Generate key pair
    let key_pair = generate_keypair();
    println!("🔑 Secret Key: {:?}", key_pair.secret_key.display_secret());
    println!("📢 Public Key: {:?}", key_pair.public_key);

    println!("🔑 Starting signer node on port: {}", port);
    println!("🔗 Connecting to peers at: {:?}", peer_ports);

    let shared_state = Arc::new(Mutex::new(SharedState::new(
        key_pair.public_key,
        num_of_signers,
    )));

    // Start listener thread
    let listener_thread = {
        let shared_state = Arc::clone(&shared_state);
        std::thread::spawn(move || {
            network::listener::start_listener(port, shared_state, key_pair.secret_key, message);
        })
    };

    // Start connector threads
    let connector_threads: Vec<_> = peer_ports
        .into_iter()
        .map(|peer_port| {
            let shared_state = Arc::clone(&shared_state);
            std::thread::spawn(move || {
                network::connector::try_connect_to_peer(
                    peer_port,
                    shared_state,
                    port,
                    key_pair.secret_key,
                    message,
                );
            })
        })
        .collect();

    // Wait for threads to finish
    listener_thread.join().unwrap();
    for thread in connector_threads {
        thread.join().unwrap();
    }
}

fn generate_keypair() -> KeyPair {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    KeyPair {
        secret_key,
        public_key,
    }
}

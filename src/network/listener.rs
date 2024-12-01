use secp256k1::SecretKey;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use crate::network::handler;
use crate::utils::state::SharedState;

pub fn start_listener(
    port: u16,
    shared_state: Arc<Mutex<SharedState>>,
    secret_key: SecretKey,
    message: &[u8],
) {
    let listener =
        TcpListener::bind(format!("127.0.0.1:{}", port)).expect("❌ Failed to bind to the port");

    println!("👂 Listening on port {}", port);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("🤝 Peer connected: {}", stream.peer_addr().unwrap());

                // Add the connection to SharedState
                shared_state
                    .lock()
                    .unwrap()
                    .add_connection(stream.try_clone().unwrap());

                handler::handle_stream(
                    stream,
                    false,
                    port,
                    Arc::clone(&shared_state),
                    secret_key,
                    message,
                );
            }
            Err(e) => {
                eprintln!("❌ Connection failed: {}", e);
            }
        }
    }
}

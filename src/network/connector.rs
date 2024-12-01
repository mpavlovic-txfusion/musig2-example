use secp256k1::SecretKey;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::network::handler;
use crate::utils::state::SharedState;
pub fn try_connect_to_peer(
    peer_port: u16,
    shared_state: Arc<Mutex<SharedState>>,
    own_port: u16,
    secret_key: SecretKey,
    message: &[u8],
) {
    loop {
        match TcpStream::connect(format!("127.0.0.1:{}", peer_port)) {
            Ok(stream) => {
                println!(
                    "🔗 Connected to peer on port {} from port {}",
                    peer_port, own_port
                );

                // Add the connection to SharedState
                shared_state
                    .lock()
                    .unwrap()
                    .add_connection(stream.try_clone().unwrap());

                handler::handle_stream(stream, true, own_port, shared_state, secret_key, message);
                break;
            }
            Err(_) => {
                println!(
                    "❓ Peer on port {} is not available, retrying...",
                    peer_port
                );
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

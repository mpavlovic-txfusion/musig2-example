use crate::node::*;
use futures::{SinkExt, StreamExt};
use musig2::KeyAggContext;
use secp256k1::PublicKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::WebSocketStream as WsStream;
use tungstenite::Message;

pub async fn handle_connection(
    mut ws_stream: WsStream<TcpStream>,
    peers: Arc<Mutex<HashMap<PublicKey, PeerConnection>>>,
    our_public_key: PublicKey,
    our_signing_session: Arc<Mutex<Option<KeyAggContext>>>,
) {
    let peers_clone = Arc::clone(&peers);
    println!("🔍 Waiting for peer's public key...");

    if let Some(Ok(msg)) = ws_stream.next().await {
        println!("📩 Received message: {:?}", msg);
        if let Message::Text(text) = msg {
            if let Some(key_str) = text.strip_prefix("KEY:") {
                if let Ok(peer_key) = key_str.parse::<PublicKey>() {
                    if send_key_message(&mut ws_stream, our_public_key)
                        .await
                        .is_ok()
                    {
                        let mut peers = peers.lock().await;
                        peers.insert(peer_key, PeerConnection::Server(ws_stream));

                        crate::session::initialize_signing_session(
                            &peers,
                            our_public_key,
                            &our_signing_session,
                        )
                        .await;

                        tokio::spawn(async move {
                            handle_messages(peer_key, peers_clone).await;
                        });
                        return;
                    }
                }
            }
        }
    }
    println!("❌ Peer connection failed");
}

pub async fn handle_messages(
    peer_key: PublicKey,
    peers: Arc<Mutex<HashMap<PublicKey, PeerConnection>>>,
) {
    loop {
        let mut peers = peers.lock().await;
        if let Some(PeerConnection::Server(ws_stream)) = peers.get_mut(&peer_key) {
            if let Some(Ok(msg)) = ws_stream.next().await {
                match msg {
                    Message::Text(text) => {
                        println!("📨 Message from {}: {}", peer_key, text);
                    }
                    Message::Close(_) => {
                        println!("👋 Peer {} disconnected", peer_key);
                        peers.remove(&peer_key);
                        break;
                    }
                    _ => {}
                }
            }
        } else {
            break;
        }
    }
}

pub async fn send_key_message(
    ws_stream: &mut (impl SinkExt<Message, Error = tungstenite::Error> + Unpin),
    public_key: PublicKey,
) -> Result<(), tungstenite::Error> {
    let key_msg = format!("KEY:{}", public_key);
    println!("📤 Sending our public key: {}", key_msg);
    ws_stream.send(Message::Text(key_msg)).await?;
    Ok(())
}

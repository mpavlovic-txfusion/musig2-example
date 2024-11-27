use crate::connection::{handle_connection, handle_messages, send_key_message};
use crate::session::initialize_signing_session;
use futures::StreamExt;
use musig2::KeyAggContext;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::try_join;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream as WsStream};
use tungstenite::Message;

pub enum PeerConnection {
    Server(WsStream<TcpStream>),
    Client(WsStream<MaybeTlsStream<TcpStream>>),
}

pub struct SignerNode {
    pub port: u16,
    pub(crate) _secret_key: SecretKey,
    pub public_key: PublicKey,
    pub(crate) peers: Arc<Mutex<HashMap<PublicKey, PeerConnection>>>,
    pub(crate) discovery_ports: Vec<u16>,
    pub(crate) signing_session: Arc<Mutex<Option<KeyAggContext>>>,
}

impl SignerNode {
    pub fn new(port: u16, discovery_ports: Vec<u16>) -> Self {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        Self {
            port,
            _secret_key: secret_key,
            public_key,
            peers: Arc::new(Mutex::new(HashMap::new())),
            discovery_ports,
            signing_session: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn Error>> {
        let server_task = self.run_server();
        let discovery_task = self.discover_peers();
        try_join!(server_task, discovery_task)?;
        Ok(())
    }

    async fn run_server(&self) -> Result<(), Box<dyn Error>> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        println!("🚀 Signer node listening on: {}", addr);
        println!("📢 Public key: {}", self.public_key);

        while let Ok((stream, addr)) = listener.accept().await {
            println!("📥 Incoming connection from: {}", addr);
            let ws_stream = accept_async(stream).await?;
            let peers = Arc::clone(&self.peers);
            let public_key = self.public_key;
            let signing_session = Arc::clone(&self.signing_session);

            tokio::spawn(async move {
                handle_connection(ws_stream, peers, public_key, signing_session).await;
            });
        }

        Ok(())
    }

    async fn discover_peers(&self) -> Result<(), Box<dyn Error>> {
        for &port in &self.discovery_ports {
            if port == self.port {
                println!("⏭️  Skipping own port {}", port);
                continue;
            }

            let addr = format!("ws://127.0.0.1:{}", port);

            match connect_async(&addr).await {
                Ok((mut ws_stream, _)) => {
                    println!("✅ WebSocket connection established to port {}", port);
                    let peers = Arc::clone(&self.peers);

                    send_key_message(&mut ws_stream, self.public_key).await?;
                    println!("✅ Successfully sent our key");

                    if let Some(Ok(msg)) = ws_stream.next().await {
                        println!("📩 Received response: {:?}", msg);
                        if let Message::Text(text) = msg {
                            if let Some(key_str) = text.strip_prefix("KEY:") {
                                if let Ok(peer_key) = key_str.parse::<PublicKey>() {
                                    let mut peers = peers.lock().await;
                                    peers.insert(peer_key, PeerConnection::Client(ws_stream));
                                    println!(
                                        "✅ Connected to peer at port {} with key {}",
                                        port, peer_key
                                    );

                                    initialize_signing_session(
                                        &peers,
                                        self.public_key,
                                        &self.signing_session,
                                    )
                                    .await;

                                    let peers_clone = Arc::clone(&self.peers);
                                    tokio::spawn(async move {
                                        handle_messages(peer_key, peers_clone).await;
                                    });
                                    continue;
                                }
                            }
                        }
                    }
                    println!("❌ Failed to receive peer's public key");
                }
                Err(e) => {
                    println!("❌ Failed to connect to {}: {}", addr, e);
                }
            }
        }

        Ok(())
    }
}

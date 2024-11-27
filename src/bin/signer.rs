use clap::Parser;
use futures::{SinkExt, StreamExt};
use musig2::secp::Point;
use musig2::KeyAggContext;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::error::Error;
use std::{collections::HashMap, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_tungstenite::{accept_async, connect_async, MaybeTlsStream, WebSocketStream as WsStream};
use tungstenite::Message;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(long)]
    port: u16,

    /// Comma-separated list of peer ports to connect to
    #[arg(long)]
    peers: String,
}

// Define an enum to hold either type of WebSocket connection
enum PeerConnection {
    Server(WsStream<TcpStream>),
    Client(WsStream<MaybeTlsStream<TcpStream>>),
}

struct SignerNode {
    port: u16,
    _secret_key: SecretKey,
    public_key: PublicKey,
    peers: Arc<Mutex<HashMap<PublicKey, PeerConnection>>>,
    discovery_ports: Vec<u16>,
    signing_session: Arc<Mutex<Option<KeyAggContext>>>,
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

    async fn initialize_signing_session(
        peers: &HashMap<PublicKey, PeerConnection>,
        our_public_key: PublicKey,
        our_signing_session: &Mutex<Option<KeyAggContext>>,
    ) {
        // Add debug print to track who's calling this
        println!("🔄 Initializing signing session...");
        println!("📊 Current peers: {:?}", peers.keys().collect::<Vec<_>>());

        // Collect all public keys (including our own)
        let mut pubkeys: Vec<PublicKey> = peers.keys().cloned().collect();
        pubkeys.push(our_public_key);
        pubkeys.sort_by_key(|k| k.serialize());

        println!("🔐 Initializing signing session with {} participants: {:?}", pubkeys.len(), pubkeys);

        // Check if we already have a session
        let existing_session = our_signing_session.lock().await.is_some();
        if existing_session {
            println!("⚠️  Signing session already initialized, skipping...");
            return;
        }

        match KeyAggContext::new(pubkeys) {
            Ok(ctx) => {
                let mut session = our_signing_session.lock().await;
                *session = Some(ctx);
                println!("✅ Signing session initialized successfully");
                if let Some(ref ctx) = *session {
                    let agg_pubkey: Point = ctx.aggregated_pubkey();
                    println!("📢 Aggregated public key: {}", agg_pubkey);
                }
            }
            Err(e) => {
                println!("❌ Failed to initialize signing session: {:?}", e);
            }
        }
    }

    pub async fn start(&self) -> Result<(), Box<dyn Error>> {
        // Start the WebSocket server
        let server_task = self.run_server();

        // Start peer discovery
        let discovery_task = self.discover_peers();

        // Run both tasks concurrently
        tokio::try_join!(server_task, discovery_task)?;

        Ok(())
    }

    async fn run_server(&self) -> Result<(), Box<dyn Error>> {
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr).await?;
        println!("🚀 Signer node listening on: {}", addr);
        println!("📢 Public key: {}", self.public_key);

        // let node = Arc::new(SignerNode::new(self.port, self.discovery_ports.clone()));

        while let Ok((stream, addr)) = listener.accept().await {
            println!("📥 Incoming connection from: {}", addr);
            let ws_stream = accept_async(stream).await?;
            let peers = Arc::clone(&self.peers);
            let public_key = self.public_key;
            let signing_session = Arc::clone(&self.signing_session);

            tokio::spawn(async move {
                Self::handle_connection(ws_stream, peers, public_key, signing_session).await;
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
                Ok((ws_stream, _)) => {
                    println!("✅ WebSocket connection established to port {}", port);
                    let peers = Arc::clone(&self.peers);
                    let mut ws_stream = ws_stream;

                    // Send our public key
                    let key_msg = format!("KEY:{}", self.public_key);
                    println!("📤 Sending our key: {}", key_msg);
                    ws_stream.send(Message::Text(key_msg)).await?;
                    println!("✅ Successfully sent our key");

                    // Wait for peer's public key response
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

                                    // Initialize signing session after connection
                                    println!("🔄 Initializing signing session as client...");
                                    Self::initialize_signing_session(&peers, self.public_key, &self.signing_session).await;

                                    // Spawn message handler
                                    let peers_clone = Arc::clone(&self.peers);
                                    tokio::spawn(async move {
                                        Self::handle_messages(peer_key, peers_clone).await;
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

    async fn handle_connection(
        ws_stream: WsStream<TcpStream>,
        peers: Arc<Mutex<HashMap<PublicKey, PeerConnection>>>,
        our_public_key: PublicKey,
        our_signing_session: Arc<Mutex<Option<KeyAggContext>>>,
    ) {
        let mut ws_stream = ws_stream;
        let peers_clone = Arc::clone(&peers);
        println!("🔍 Waiting for peer's public key...");

        // Wait for the peer's public key
        if let Some(Ok(msg)) = ws_stream.next().await {
            println!("📩 Received message: {:?}", msg);
            if let Message::Text(text) = msg {
                if let Some(key_str) = text.strip_prefix("KEY:") {
                    if let Ok(peer_key) = key_str.parse::<PublicKey>() {
                        println!("✨ Successfully parsed peer key: {}", peer_key);

                        // Send our public key in response
                        let key_msg = format!("KEY:{}", our_public_key);
                        println!("📤 Sending our key: {}", key_msg);

                        if ws_stream.send(Message::Text(key_msg)).await.is_ok() {
                            println!("✅ Successfully sent our key");
                            // Store the connection
                            let mut peers = peers.lock().await;
                            peers.insert(peer_key, PeerConnection::Server(ws_stream));
                            println!("🤝 New peer connected with key: {}", peer_key);

                            // Initialize signing session
                            println!("🔄 Initializing signing session as server...");
                            Self::initialize_signing_session(&peers, our_public_key, &our_signing_session).await;

                            // Spawn message handler
                            tokio::spawn(async move {
                                println!("🚀 Spawning message handler for peer: {}", peer_key);
                                Self::handle_messages(peer_key, peers_clone).await;
                            });
                            return;
                        } else {
                            println!("❌ Failed to send our key response");
                        }
                    } else {
                        println!("❌ Failed to parse peer's public key from bytes");
                    }
                } else {
                    println!("❌ Message didn't start with KEY: prefix");
                }
            } else {
                println!("❌ Received non-text message");
            }
        } else {
            println!("❌ No message received from peer");
        }
        println!("❌ Peer connection failed: no valid public key received");
    }

    async fn handle_messages(
        peer_key: PublicKey,
        peers: Arc<Mutex<HashMap<PublicKey, PeerConnection>>>,
    ) {
        // Example message handling loop
        loop {
            let mut peers = peers.lock().await;
            if let Some(PeerConnection::Server(ws_stream)) = peers.get_mut(&peer_key) {
                if let Some(Ok(msg)) = ws_stream.next().await {
                    match msg {
                        Message::Text(text) => {
                            println!("📨 Message from {}: {}", peer_key, text);
                            // Handle the message here
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Parse peer ports from comma-separated string
    let discovery_ports: Vec<u16> = args
        .peers
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    let signer = SignerNode::new(args.port, discovery_ports);

    println!("🔑 Starting signer node...");
    if let Err(e) = signer.start().await {
        eprintln!("❌ Signer error: {}", e);
    }

    Ok(())
}

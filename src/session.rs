use std::collections::HashMap;

use musig2::{secp::Point, KeyAggContext};
use secp256k1::PublicKey;
use tokio::sync::Mutex;

use crate::PeerConnection;

pub async fn initialize_signing_session(
    peers: &HashMap<PublicKey, PeerConnection>,
    our_public_key: PublicKey,
    our_signing_session: &Mutex<Option<KeyAggContext>>,
) {
    println!("🔄 Initializing signing session...");

    let mut pubkeys: Vec<PublicKey> = peers.keys().cloned().collect();
    pubkeys.push(our_public_key);
    pubkeys.sort_by_key(|k| k.serialize());

    println!("👥 Network participants: {:?}", pubkeys);

    if our_signing_session.lock().await.is_some() {
        println!("⚠️  Signing session already initialized");
        return;
    }

    match KeyAggContext::new(pubkeys) {
        Ok(ctx) => {
            let mut session = our_signing_session.lock().await;
            *session = Some(ctx);
            if let Some(ref ctx) = *session {
                let agg_pubkey: Point = ctx.aggregated_pubkey();
                println!("📢 Aggregated public key: {}", agg_pubkey);
            }
        }
        Err(e) => println!("❌ Failed to initialize signing session: {:?}", e),
    }
}

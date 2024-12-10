use clap::Parser;
use musig2::{FirstRound, PartialSignature, PubNonce, SecNonceSpices, SecondRound};
use musig2_example::types::NodeRegistration;
use musig2_example::types::{
    GenerateNonceRequest, ReceiveNoncesRequest, ReceiveNoncesResponse,
    ReceivePartialSignaturesRequest, ReceivePartialSignaturesResponse, SigningSession,
};
use reqwest::Client;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use warp::Filter;

use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use serde::Serialize;

/// Signer node for responding to signing requests.
#[derive(Parser, Debug)]
struct Cli {
    /// Port for this signer node
    #[arg(long)]
    port: u16,

    /// Operator URL
    #[arg(long, default_value = "http://127.0.0.1:3030")]
    operator_url: String,
}

#[derive(Clone)]
struct SignerState {
    secret_key: SecretKey,
    // public_key: PublicKey,
    sessions: Arc<Mutex<HashMap<String, SigningSession>>>,
    first_rounds: Arc<Mutex<HashMap<String, FirstRound>>>,
    second_rounds: Arc<Mutex<HashMap<String, SecondRound<Vec<u8>>>>>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct SignerError(String);

impl warp::reject::Reject for SignerError {}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let client = Client::new();
    let address = format!("http://127.0.0.1:{}", args.port);

    // Generate secret and public keys
    let secp = Secp256k1::new();
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    println!("🔑 Generated public key: {}", public_key);

    // Submit public key to operator
    let registration = NodeRegistration {
        address: address.clone(),
        public_key,
    };

    let response = client
        .post(format!("{}/register", args.operator_url))
        .json(&registration)
        .send()
        .await
        .expect("Failed to register signer node");

    if response.status().is_success() {
        println!("✅ Signer node registered successfully.");
    } else {
        eprintln!(
            "❌ Failed to register signer node: HTTP {}, Error: {}",
            response.status(),
            response.text().await.unwrap()
        );
    }

    let state = SignerState {
        secret_key,
        // public_key,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        first_rounds: Arc::new(Mutex::new(HashMap::new())),
        second_rounds: Arc::new(Mutex::new(HashMap::new())),
    };

    let state_filter = warp::any().map(move || state.clone());

    // Generate nonce endpoint
    let generate_nonce = warp::post()
        .and(warp::path("nonce"))
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(handle_generate_nonce);

    // Receive nonces endpoint
    let receive_nonces = warp::post()
        .and(warp::path("receive_nonces"))
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(handle_receive_nonces);

    // Receive partial signatures endpoint
    let receive_partial_signatures = warp::post()
        .and(warp::path("receive_partial_signatures"))
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(handle_receive_partial_signatures);

    let routes = generate_nonce
        .or(receive_nonces)
        .or(receive_partial_signatures)
        .recover(handle_rejection);

    println!("Signer running on port {}...", args.port);
    warp::serve(routes).run(([127, 0, 0, 1], args.port)).await;
}

async fn handle_generate_nonce(
    request: GenerateNonceRequest,
    state: SignerState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let first_round = FirstRound::new(
        request.key_agg_ctx.clone(),
        rand::thread_rng().gen::<[u8; 32]>(),
        request.signer_index,
        SecNonceSpices::new()
            .with_seckey(state.secret_key)
            .with_message(&request.message.as_bytes().to_vec()),
    )
    .map_err(|_| warp::reject::custom(SignerError("Failed to generate nonce".to_string())))?;

    let public_nonce = first_round.our_public_nonce();

    // Store session data and FirstRound separately
    let mut sessions = state.sessions.lock().await;
    let mut first_rounds = state.first_rounds.lock().await;

    sessions.insert(
        request.session_id.clone(),
        SigningSession {
            session_id: request.session_id.clone(),
            message: request.message.clone(),
            key_agg_ctx: request.key_agg_ctx,
            public_nonces: HashMap::new(),
        },
    );

    first_rounds.insert(request.session_id, first_round);

    Ok(warp::reply::json(&public_nonce.serialize().to_vec()))
}

async fn handle_receive_nonces(
    request: ReceiveNoncesRequest,
    state: SignerState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let sessions = state.sessions.lock().await;
    let mut first_rounds = state.first_rounds.lock().await;
    let mut second_rounds = state.second_rounds.lock().await;

    let session = sessions
        .get(&request.session_id)
        .ok_or_else(|| warp::reject::custom(SignerError("Session not found".to_string())))?;

    let mut first_round = first_rounds
        .remove(&request.session_id)
        .ok_or_else(|| warp::reject::custom(SignerError("First round not found".to_string())))?;

    // Receive nonces from other signers
    for (index, nonce_bytes) in request.nonces {
        println!("Received nonce for signer index {}", index);
        let other_nonce = PubNonce::from_bytes(&nonce_bytes)
            .map_err(|_| warp::reject::custom(SignerError("Invalid nonce format".to_string())))?;

        first_round.receive_nonce(index, other_nonce).map_err(|e| {
            eprintln!("Failed to receive nonce from index {}: {:?}", index, e);
            warp::reject::custom(SignerError(format!(
                "Failed to receive nonce from index {}",
                index
            )))
        })?;
    }

    // Finalize first round
    let message_bytes = session.message.as_bytes().to_vec();

    let second_round = first_round
        .finalize(state.secret_key, message_bytes.clone())
        .map_err(|_| {
            warp::reject::custom(SignerError("Failed to finalize first round".to_string()))
        })?;

    let partial_signature: PartialSignature = second_round.our_signature();
    second_rounds.insert(request.session_id.clone(), second_round);
    println!("Partial signature: {:?}", partial_signature);

    Ok(warp::reply::json(&ReceiveNoncesResponse {
        partial_signature,
    }))
}

async fn handle_receive_partial_signatures(
    request: ReceivePartialSignaturesRequest,
    state: SignerState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let mut second_rounds = state.second_rounds.lock().await;

    let mut second_round = second_rounds
        .remove(&request.session_id)
        .ok_or_else(|| warp::reject::custom(SignerError("Second round not found".to_string())))?;

    // Receive partial signatures from other signers
    for (index, sig) in request.partial_signatures {
        println!(
            "Processing partial signature for signer index {}: {:?}",
            index, sig
        );
        let our_partial_signature: PartialSignature = second_round.our_signature();
        println!(
            "Our signer's partial signature: {:?}",
            our_partial_signature
        );
        if let Err(e) = second_round.receive_signature(index, sig) {
            eprintln!("Failed to receive signature from index {}: {:?}", index, e);
            return Err(warp::reject::custom(SignerError(format!(
                "Failed to receive partial signature from index {}",
                index
            ))));
        }
    }

    // Finalize to get the final signature
    let final_signature = second_round.finalize().map_err(|e| {
        eprintln!("Failed to finalize signature: {:?}", e);
        warp::reject::custom(SignerError("Failed to finalize signature".to_string()))
    })?;

    Ok(warp::reply::json(&ReceivePartialSignaturesResponse {
        final_signature,
    }))
}

// Add this to handle rejections
async fn handle_rejection(
    err: warp::Rejection,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = warp::http::StatusCode::NOT_FOUND;
        message = "Not Found";
    } else if let Some(e) = err.find::<SignerError>() {
        code = warp::http::StatusCode::BAD_REQUEST;
        message = e.0.as_str();
    } else {
        eprintln!("unhandled error: {:?}", err);
        code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error";
    }

    Ok(warp::reply::with_status(
        warp::reply::json(&ErrorResponse {
            error: message.to_string(),
        }),
        code,
    ))
}

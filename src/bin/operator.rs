use clap::Parser;
use musig2::KeyAggContext;
use musig2_example::types::{
    GenerateNonceRequest, NodeRegistration, ReceiveNoncesRequest, ReceiveNoncesResponse,
    ReceivePartialSignaturesRequest, ReceivePartialSignaturesResponse, SigningInitiateRequest,
    SigningInitiateResponse, SigningSession,
};
use reqwest::Client;
use secp256k1::PublicKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use warp::Filter;

/// Operator node for managing signer nodes and signing sessions.
#[derive(Parser, Debug)]
struct Cli {
    /// Port to run the operator node
    #[arg(long, default_value = "3030")]
    port: u16,
}

#[derive(Clone)]
struct OperatorState {
    signers: Arc<Mutex<HashMap<(usize, PublicKey), String>>>,
    sessions: Arc<Mutex<HashMap<String, SigningSession>>>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct OperatorError(String);

impl warp::reject::Reject for OperatorError {}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let state = OperatorState {
        signers: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        // partial_signatures: Arc::new(Mutex::new(HashMap::new())),
    };

    let state_filter = warp::any().map(move || state.clone());

    // Register signer endpoint
    let register = warp::post()
        .and(warp::path("register"))
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(register_signer);

    // Initiate signing endpoint
    let initiate_signing = warp::post()
        .and(warp::path("sign"))
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(initiate_signing);

    let routes = register.or(initiate_signing);

    println!("Operator running on port {}...", args.port);
    warp::serve(routes).run(([127, 0, 0, 1], args.port)).await;
}

async fn register_signer(
    registration: NodeRegistration,
    state: OperatorState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let mut signers = state.signers.lock().await;
    let index = signers.len();
    signers.insert((index, registration.public_key), registration.address);
    println!(
        "🔑 Signer node with index {} and public key {} registered successfully.",
        index, registration.public_key
    );
    Ok(warp::reply::json(
        &"Registered successfully with public key",
    ))
}

async fn initiate_signing(
    request: SigningInitiateRequest,
    state: OperatorState,
) -> Result<impl warp::Reply, warp::Rejection> {
    println!("Initiating signing of the message: {:?}", request.message);
    let signers = state.signers.lock().await;

    // Create KeyAggContext from registered signers
    let pubkeys: Vec<PublicKey> = signers.iter().map(|((_, pubkey), _)| *pubkey).collect();

    println!("Pubkeys for KeyAggContext: {:?}", pubkeys);

    let key_agg_ctx = KeyAggContext::new(pubkeys).map_err(|_| {
        warp::reject::custom(OperatorError(
            "Failed to create key aggregation context".to_string(),
        ))
    })?;

    // Create new session
    let session_id = Uuid::new_v4().to_string();
    let session = SigningSession {
        session_id: session_id.clone(),
        message: request.message.clone(),
        key_agg_ctx: key_agg_ctx.clone(),
        public_nonces: HashMap::new(),
    };

    // Store session
    let mut sessions = state.sessions.lock().await;
    sessions.insert(session_id.clone(), session);

    // Request nonces from all signers
    let client = Client::new();
    let mut indexed_nonces = HashMap::new();

    for ((i, _), address) in signers.iter() {
        let nonce_request = GenerateNonceRequest {
            session_id: session_id.clone(),
            message: request.message.clone(),
            key_agg_ctx: key_agg_ctx.clone(),
            signer_index: *i,
        };

        let response = client
            .post(format!("{}/nonce", address))
            .json(&nonce_request)
            .send()
            .await
            .map_err(|_| {
                warp::reject::custom(OperatorError("Failed to request nonce".to_string()))
            })?;

        let nonce: Vec<u8> = response.json().await.map_err(|_| {
            warp::reject::custom(OperatorError("Failed to parse nonce response".to_string()))
        })?;

        indexed_nonces.insert(*i, nonce.clone());
    }

    // Distribute nonces to all signers and collect partial signatures
    let client = Client::new();
    let mut indexed_partial_sigs = HashMap::new();

    for ((i, _), address) in signers.iter() {
        let mut other_nonces = indexed_nonces.clone();
        // Remove this signer's own nonce
        other_nonces.remove(&i);

        let receive_request = ReceiveNoncesRequest {
            session_id: session_id.clone(),
            nonces: other_nonces,
        };

        let response: ReceiveNoncesResponse = client
            .post(format!("{}/receive_nonces", address))
            .json(&receive_request)
            .send()
            .await
            .map_err(|_| {
                warp::reject::custom(OperatorError("Failed to distribute nonces".to_string()))
            })?
            .json()
            .await
            .map_err(|_| {
                warp::reject::custom(OperatorError(
                    "Failed to parse response from /receive_nonces".to_string(),
                ))
            })?;

        indexed_partial_sigs.insert(*i, response.partial_signature);
    }

    // Distribute partial signatures to all signers
    let client = Client::new();
    let mut final_signatures = Vec::new();

    for ((i, pubkey), address) in signers.iter() {
        let mut other_sigs = indexed_partial_sigs.clone();
        // Remove this signer's own partial signature
        other_sigs.remove(&i);

        println!(
            "Sending partial signatures to signer {} at {}",
            pubkey, address
        );
        println!(
            "Sending {} partial signatures: {:?}",
            other_sigs.len(),
            other_sigs
        );

        let partial_sigs_request = ReceivePartialSignaturesRequest {
            session_id: session_id.clone(),
            partial_signatures: other_sigs,
        };

        let response = client
            .post(format!("{}/receive_partial_signatures", address))
            .json(&partial_sigs_request)
            .send()
            .await
            .map_err(|e| {
                eprintln!("Failed to send request to {}: {:?}", address, e);
                warp::reject::custom(OperatorError("Failed to send request".to_string()))
            })?;

        // Handle non-success status codes
        if !response.status().is_success() {
            let error_text = response.text().await.map_err(|e| {
                eprintln!("Failed to get error response text: {:?}", e);
                warp::reject::custom(OperatorError("Failed to get error response".to_string()))
            })?;
            eprintln!("Error response from {}: {}", address, error_text);
            return Err(warp::reject::custom(OperatorError(format!(
                "Signer error: {}",
                error_text
            ))));
        }

        // Try to parse the response
        let parsed_response: ReceivePartialSignaturesResponse =
            response.json().await.map_err(|e| {
                eprintln!("Failed to parse response JSON: {:?}", e);
                warp::reject::custom(OperatorError("Failed to parse response".to_string()))
            })?;

        final_signatures.push(parsed_response.final_signature);
    }

    // Verify all signers produced the same final signature
    if !final_signatures.windows(2).all(|w| w[0] == w[1]) {
        return Err(warp::reject::custom(OperatorError(
            "Inconsistent final signatures".to_string(),
        )));
    }

    // Since all signers produced the same final signature, we can use the first one
    let aggregated_signature = final_signatures[0];
    // Get the aggregated pubkey
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();

    // Verify the signature
    let is_signature_valid = musig2::verify_single(
        aggregated_pubkey,
        aggregated_signature,
        request.message.as_bytes(),
    )
    .is_ok();

    let response = SigningInitiateResponse {
        session_id,
        aggregated_pubkey,
        aggregated_signature,
        is_signature_valid,
    };

    Ok(warp::reply::json(&response))
}
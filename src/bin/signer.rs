use clap::Parser;
use musig2::{FirstRound, PartialSignature, PubNonce, SecNonceSpices, SecondRound};
use musig2_example::client::HttpClient;
use musig2_example::error::handle_rejection;
use musig2_example::types::{
    GenerateNonceRequest, NodeRegistration, ReceiveNoncesRequest, ReceiveNoncesResponse,
    ReceivePartialSignaturesRequest, ReceivePartialSignaturesResponse, SigningSession,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use warp::Filter;

use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

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

#[derive(Debug)]
#[allow(dead_code)]
struct SignerError(String);

impl warp::reject::Reject for SignerError {}

#[derive(Clone)]
struct Signer {
    client: HttpClient,
    operator_url: String,
    url: String,
    secret_key: SecretKey,
    public_key: PublicKey,
    session: Arc<Mutex<Option<SigningSession>>>,
    first_rounds: Arc<Mutex<HashMap<String, FirstRound>>>,
    second_rounds: Arc<Mutex<HashMap<String, SecondRound<Vec<u8>>>>>,
}

impl Signer {
    pub fn new(client: HttpClient, operator_url: String, port: u16) -> Self {
        let address = format!("http://127.0.0.1:{}", port);
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        println!("Public key: {:?}", public_key);
        Self {
            client,
            operator_url,
            url: address,
            secret_key,
            public_key,
            session: Arc::new(Mutex::new(None)),
            first_rounds: Arc::new(Mutex::new(HashMap::new())),
            second_rounds: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn register(&self) -> Result<impl warp::Reply, warp::Rejection> {
        // Submit public key to operator
        let registration = NodeRegistration {
            address: self.url.clone(),
            public_key: self.public_key,
        };

        let response = self
            .client
            .inner()
            .post(format!("{}/register", self.operator_url))
            .json(&registration)
            .send()
            .await
            .map_err(|e| warp::reject::custom(SignerError(e.to_string())))?;

        if response.status().is_success() {
            println!("✅ Signer node registered successfully.");
            Ok(warp::reply())
        } else {
            let error = response
                .text()
                .await
                .map_err(|e| warp::reject::custom(SignerError(e.to_string())))?;
            Err(warp::reject::custom(SignerError(error)))
        }
    }

    pub async fn start_server(&self) {
        let state = self.clone();
        let state_filter = warp::any().map(move || state.clone());

        // Generate nonce endpoint
        let generate_nonce = warp::post()
            .and(warp::path("nonce"))
            .and(warp::body::json())
            .and(state_filter.clone())
            .and_then(|req, state: Signer| async move { state.handle_generate_nonce(req).await });

        // Receive nonces endpoint
        let receive_nonces = warp::post()
            .and(warp::path("receive_nonces"))
            .and(warp::body::json())
            .and(state_filter.clone())
            .and_then(|req, state: Signer| async move { state.handle_receive_nonces(req).await });

        // Receive partial signatures endpoint
        let receive_partial_signatures = warp::post()
            .and(warp::path("receive_partial_signatures"))
            .and(warp::body::json())
            .and(state_filter.clone())
            .and_then(|req, state: Signer| async move {
                state.handle_receive_partial_signatures(req).await
            });

        let routes = generate_nonce
            .or(receive_nonces)
            .or(receive_partial_signatures)
            .recover(handle_rejection);

        println!(
            "Signer running on port {}...",
            self.url.split(':').last().unwrap()
        );
        warp::serve(routes)
            .run((
                [127, 0, 0, 1],
                self.url.split(':').last().unwrap().parse().unwrap(),
            ))
            .await;
    }

    async fn handle_generate_nonce(
        self,
        request: GenerateNonceRequest,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let first_round = FirstRound::new(
            request.key_agg_ctx.clone(),
            rand::thread_rng().gen::<[u8; 32]>(),
            request.signer_index,
            SecNonceSpices::new()
                .with_seckey(self.secret_key)
                .with_message(&request.message.as_bytes().to_vec()),
        )
        .map_err(|_| warp::reject::custom(SignerError("Failed to generate nonce".to_string())))?;

        let public_nonce = first_round.our_public_nonce();

        // Store session data and FirstRound separately
        let mut session_guard = self.session.lock().await;
        let mut first_rounds = self.first_rounds.lock().await;

        let session = SigningSession {
            session_id: request.session_id.clone(),
            message: request.message.clone(),
            key_agg_ctx: request.key_agg_ctx,
        };
        *session_guard = Some(session);

        first_rounds.insert(request.session_id, first_round);

        Ok(warp::reply::json(&public_nonce.serialize().to_vec()))
    }

    async fn handle_receive_nonces(
        self,
        request: ReceiveNoncesRequest,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let session_guard = self.session.lock().await;
        let session = session_guard.as_ref().ok_or_else(|| {
            warp::reject::custom(SignerError("No active session found".to_string()))
        })?;

        let mut first_rounds = self.first_rounds.lock().await;
        let mut second_rounds = self.second_rounds.lock().await;

        let mut first_round = first_rounds.remove(&request.session_id).ok_or_else(|| {
            warp::reject::custom(SignerError("First round not found".to_string()))
        })?;

        // Receive nonces from other signers
        for (index, nonce_bytes) in request.nonces {
            // println!("Received nonce for signer index {}", index);
            let other_nonce = PubNonce::from_bytes(&nonce_bytes).map_err(|_| {
                warp::reject::custom(SignerError("Invalid nonce format".to_string()))
            })?;

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
            .finalize(self.secret_key, message_bytes.clone())
            .map_err(|_| {
                warp::reject::custom(SignerError("Failed to finalize first round".to_string()))
            })?;

        let partial_signature: PartialSignature = second_round.our_signature();
        second_rounds.insert(request.session_id.clone(), second_round);
        println!(
            "Partial signature: {:?}",
            hex::encode(partial_signature.serialize())
        );

        Ok(warp::reply::json(&ReceiveNoncesResponse {
            partial_signature,
        }))
    }

    async fn handle_receive_partial_signatures(
        self,
        request: ReceivePartialSignaturesRequest,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let mut second_rounds = self.second_rounds.lock().await;

        let mut second_round = second_rounds.remove(&request.session_id).ok_or_else(|| {
            warp::reject::custom(SignerError("Second round not found".to_string()))
        })?;

        // Receive partial signatures from other signers
        for (index, sig) in request.partial_signatures {
            // println!(
            //     "Processing partial signature for signer index {}: {:?}",
            //     index, sig
            // );
            // let our_partial_signature: PartialSignature = second_round.our_signature();
            // println!(
            //     "Our signer's partial signature: {:?}",
            //     our_partial_signature
            // );
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
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let client = HttpClient::new();
    let signer = Signer::new(client, args.operator_url, args.port);
    // Register signer to the operator
    signer.register().await.unwrap();
    // Start signer server
    signer.start_server().await;
}

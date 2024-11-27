//! MuSig2 Example
//!
//! This example demonstrates how to use MuSig2 for multi-signature creation
//! with three participants, showing the complete workflow from key generation
//! to signature verification.

use musig2::{CompactSignature, FirstRound, KeyAggContext, PartialSignature, SecNonceSpices};
use rand::{rngs::OsRng, Rng};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

fn main() {
    // Create secret and public keys for three participants
    let mut rng = OsRng;
    let secret_key_1 = SecretKey::new(&mut rng);
    let secret_key_2 = SecretKey::new(&mut rng);
    let secret_key_3 = SecretKey::new(&mut rng);

    let secp = Secp256k1::new();
    let public_key_1 = PublicKey::from_secret_key(&secp, &secret_key_1);
    let public_key_2 = PublicKey::from_secret_key(&secp, &secret_key_2);
    let public_key_3 = PublicKey::from_secret_key(&secp, &secret_key_3);

    // Message to sign
    let message = b"Hello, MuSig2!";

    // Create key aggregation context
    let pubkeys = vec![public_key_1, public_key_2, public_key_3];
    let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();

    // First round: Generate and exchange public nonces
    let mut first_round_1 = FirstRound::new(
        key_agg_ctx.clone(),
        rand::thread_rng().gen::<[u8; 32]>(),
        0,
        SecNonceSpices::new()
            .with_seckey(secret_key_1)
            .with_message(message),
    )
    .unwrap();

    let mut first_round_2 = FirstRound::new(
        key_agg_ctx.clone(),
        rand::thread_rng().gen::<[u8; 32]>(),
        1,
        SecNonceSpices::new()
            .with_seckey(secret_key_2)
            .with_message(message),
    )
    .unwrap();

    let mut first_round_3 = FirstRound::new(
        key_agg_ctx.clone(),
        rand::thread_rng().gen::<[u8; 32]>(),
        2,
        SecNonceSpices::new()
            .with_seckey(secret_key_3)
            .with_message(message),
    )
    .unwrap();

    // Get public nonces
    let pub_nonce_1 = first_round_1.our_public_nonce();
    let pub_nonce_2 = first_round_2.our_public_nonce();
    let pub_nonce_3 = first_round_3.our_public_nonce();

    // Exchange nonces between participants
    first_round_1.receive_nonce(1, pub_nonce_2.clone()).unwrap();
    first_round_1.receive_nonce(2, pub_nonce_3.clone()).unwrap();

    first_round_2.receive_nonce(0, pub_nonce_1.clone()).unwrap();
    first_round_2.receive_nonce(2, pub_nonce_3.clone()).unwrap();

    first_round_3.receive_nonce(0, pub_nonce_1.clone()).unwrap();
    first_round_3.receive_nonce(1, pub_nonce_2.clone()).unwrap();

    // Second round: Create partial signatures
    let mut second_round_1 = first_round_1.finalize(secret_key_1, message).unwrap();
    let second_round_2 = first_round_2.finalize(secret_key_2, message).unwrap();
    let second_round_3 = first_round_3.finalize(secret_key_3, message).unwrap();

    // Get partial signatures
    let _partial_sig_1: PartialSignature = second_round_1.our_signature();
    let partial_sig_2: PartialSignature = second_round_2.our_signature();
    let partial_sig_3: PartialSignature = second_round_3.our_signature();

    // One participant receives others' signatures
    second_round_1.receive_signature(1, partial_sig_2).unwrap();
    second_round_1.receive_signature(2, partial_sig_3).unwrap();

    // Get final signature (only need one participant to do this)
    let final_signature: CompactSignature = second_round_1.finalize().unwrap();

    // Verify the signature

    // This is the key which the group has control over.
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    println!(
        "Aggregated public key: {}",
        hex::encode(aggregated_pubkey.serialize())
    );

    let result = musig2::verify_single(aggregated_pubkey, final_signature, message);

    match result {
        Ok(_) => println!("Signature verified successfully!"),
        Err(e) => println!("Signature verification failed: {:?}", e),
    }

    // Print the signature in hex
    println!(
        "Final signature: {}",
        hex::encode(final_signature.serialize())
    );
}

use super::transaction_output::{RangeProof, TransactionOutput};
// The common_types PublicKey and Commitment are already imported in transaction_output.rs
// and used by TransactionOutput. We need the other placeholder types for dummy_transaction_output_for_verification.
use crate::common_types::{Commitment, PublicKey};
use crate::transactions::transaction_components::transaction_output::{
    EncryptedValue, Covenant, OutputFeatures, ComAndPubSignature, MicroMinotari, TariScript
};
use curve25519_dalek::ristretto::CompressedRistretto;

#[test]
fn test_range_proof_from_bytes_empty() {
    let bytes: [u8; 0] = [];
    let result = RangeProof::from_bytes(&bytes);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(e.contains("Invalid proof size"));
    }
}

#[test]
fn test_range_proof_from_bytes_too_short() {
    let bytes = vec![0u8; RangeProof::PROOF_SIZE - 1];
    let result = RangeProof::from_bytes(&bytes);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(e.contains("Invalid proof size"));
    }
}

#[test]
fn test_range_proof_from_bytes_too_long() {
    let bytes = vec![0u8; RangeProof::PROOF_SIZE + 1];
    let result = RangeProof::from_bytes(&bytes);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(e.contains("Invalid proof size"));
    }
}

#[test]
fn test_range_proof_from_bytes_invalid_point_data() {
    let mut bytes = vec![0u8; RangeProof::PROOF_SIZE];
    bytes.iter_mut().for_each(|b| *b = 0xFF);

    let result = RangeProof::from_bytes(&bytes);
    assert!(result.is_err(), "Expected error from invalid point/scalar data, got Ok: {:?}", result.ok());
    // Further checks could inspect the error message if from_bytes becomes more specific
    // e.g. "Failed to convert slice to [u8; 32]" or "Invalid scalar encoding" or "Failed to decompress point"
}

// Helper to create a dummy TransactionOutput for testing verification logic
fn dummy_transaction_output_for_verification() -> TransactionOutput {
    let proof_bytes = vec![0u8; RangeProof::PROOF_SIZE];
    let rp = RangeProof::from_bytes(&proof_bytes).expect("Should parse zeroed proof for dummy");

    TransactionOutput {
        features: OutputFeatures {},
        commitment: Commitment([0u8; 32]),
        proof: rp,
        script: TariScript {},
        sender_offset_public_key: PublicKey([0u8; 32]),
        metadata_signature: ComAndPubSignature {},
        covenant: Covenant {},
        encrypted_value: EncryptedValue {},
        minimum_value_promise: 0,
    }
}

#[test]
fn test_verify_invalid_commitment_point() {
    let mut output = dummy_transaction_output_for_verification();
    output.commitment = Commitment([0xFF; 32]);
    let result = output.verify_range_proof();
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(e.contains("Failed to decompress commitment point C"), "Unexpected error: {}", e);
    }
}

#[test]
fn test_verify_invalid_proof_a_point() {
    let mut output = dummy_transaction_output_for_verification();
    let mut proof_a_invalid_bytes = [0u8; 32];
    proof_a_invalid_bytes.iter_mut().for_each(|b| *b = 0xFF);
    output.proof.a = CompressedRistretto(proof_a_invalid_bytes);

    let result = output.verify_range_proof();
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(e.contains("Failed to decompress proof point A"), "Unexpected error: {}", e);
    }
}

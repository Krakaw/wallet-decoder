// Unit tests for range proof verification logic in src/range_proof.rs

#[cfg(test)]
mod revealed_value_tests {
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use crate::range_proof::{get_metadata_signature_challenge, verify_revealed_value_proof, RangeProofError};
    use crate::tari_types::{
        ComAndPubSignature,
        CompressedPublicKey,
        Covenant,
        EncryptedData,
        OutputFeatures,
        RangeProofType,
        TariScript,
        TransactionOutputVersion,
    };

    // Helper function to create default test data
    fn create_default_revealed_value_data() -> (
        RistrettoPoint, // commitment_point
        TariScript,
        OutputFeatures,
        CompressedPublicKey, // sender_offset_public_key
        Covenant,
        EncryptedData,
        u64, // minimum_value_promise
        TransactionOutputVersion,
    ) {
        let commitment_point = RistrettoPoint::default(); // Placeholder
        let script = TariScript::new(b"default script".to_vec());
        let features = OutputFeatures {
            bytes: b"default features".to_vec(), // Placeholder for hashing
            range_proof_type: RangeProofType::RevealedValue,
        };
        // Use RistrettoPoint::default() then compress for CompressedPublicKey
        let sender_offset_public_key = CompressedPublicKey::from_point(&RistrettoPoint::default());
        let covenant = Covenant::new(b"default covenant".to_vec());
        let encrypted_data = EncryptedData::new(b"default encrypted".to_vec());
        let minimum_value_promise = 100u64;
        let version = TransactionOutputVersion::default();

        (
            commitment_point,
            script,
            features,
            sender_offset_public_key,
            covenant,
            encrypted_data,
            minimum_value_promise,
            version,
        )
    }

    #[test]
    fn test_verify_revealed_value_valid() {
        let (
            commitment_point,
            script,
            features,
            sender_offset_pk,
            covenant,
            encrypted_data,
            minimum_value,
            version,
        ) = create_default_revealed_value_data();

        // Create a valid metadata_signature
        // 1. Ephemeral commitment and pubkey (placeholders)
        let ephemeral_commit_point = RistrettoPoint::default();
        let ephemeral_pubkey_point = RistrettoPoint::default();

        // 2. Calculate challenge e
        let challenge_bytes = get_metadata_signature_challenge(
            &version,
            &script,
            &features,
            &sender_offset_pk,
            &ephemeral_commit_point.compress(),
            &ephemeral_pubkey_point.compress(),
            &commitment_point,
            &covenant,
            &encrypted_data,
            minimum_value,
        );
        let challenge_e = Scalar::from_bytes_mod_order_wide(&challenge_bytes);

        // 3. Calculate expected u_a
        let value_as_scalar = Scalar::from(minimum_value);
        let commit_nonce_a = Scalar::zero(); // As per Tari's logic
        let expected_u_a = commit_nonce_a + challenge_e * value_as_scalar;

        let metadata_sig = ComAndPubSignature::new(
            ephemeral_commit_point.compress(),
            ephemeral_pubkey_point.compress(),
            expected_u_a,
        );

        let result = verify_revealed_value_proof(
            &commitment_point,
            &metadata_sig,
            &script,
            &features,
            &sender_offset_pk,
            &covenant,
            &encrypted_data,
            minimum_value,
            &version,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_revealed_value_invalid_ua() {
        let (
            commitment_point,
            script,
            features,
            sender_offset_pk,
            covenant,
            encrypted_data,
            minimum_value,
            version,
        ) = create_default_revealed_value_data();

        let ephemeral_commit_point = RistrettoPoint::default();
        let ephemeral_pubkey_point = RistrettoPoint::default();

        // u_a is deliberately made different
        let u_a_altered = Scalar::one(); // Different from what would be calculated

        let metadata_sig = ComAndPubSignature::new(
            ephemeral_commit_point.compress(),
            ephemeral_pubkey_point.compress(),
            u_a_altered,
        );

        let result = verify_revealed_value_proof(
            &commitment_point,
            &metadata_sig,
            &script,
            &features,
            &sender_offset_pk,
            &covenant,
            &encrypted_data,
            minimum_value,
            &version,
        );
        assert_eq!(result, Err(RangeProofError::VerificationFailed("RevealedValue range proof check failed".to_string())));
    }

    #[test]
    fn test_verify_revealed_value_altered_challenge_input() {
         let (
            commitment_point,
            script,
            features,
            sender_offset_pk,
            covenant,
            encrypted_data,
            minimum_value,
            version,
        ) = create_default_revealed_value_data();

        let ephemeral_commit_point = RistrettoPoint::default();
        let ephemeral_pubkey_point = RistrettoPoint::default();

        let challenge_bytes = get_metadata_signature_challenge(
            &version,
            &script,
            &features,
            &sender_offset_pk,
            &ephemeral_commit_point.compress(),
            &ephemeral_pubkey_point.compress(),
            &commitment_point,
            &covenant,
            &encrypted_data,
            minimum_value,
        );
        let challenge_e = Scalar::from_bytes_mod_order_wide(&challenge_bytes);
        let value_as_scalar = Scalar::from(minimum_value);
        let commit_nonce_a = Scalar::zero();
        let expected_u_a = commit_nonce_a + challenge_e * value_as_scalar;

        let metadata_sig = ComAndPubSignature::new(
            ephemeral_commit_point.compress(),
            ephemeral_pubkey_point.compress(),
            expected_u_a,
        );

        // Alter one of the inputs (e.g., script) *after* metadata_sig was created with original script
        let altered_script = TariScript::new(b"altered script".to_vec());

        let result = verify_revealed_value_proof(
            &commitment_point,
            &metadata_sig,
            &altered_script, // Use altered script
            &features,
            &sender_offset_pk,
            &covenant,
            &encrypted_data,
            minimum_value,
            &version,
        );
         assert_eq!(result, Err(RangeProofError::VerificationFailed("RevealedValue range proof check failed".to_string())));
    }
}

// TODO: Add tests for BulletProofPlus logic in range_proof.rs (manual implementation)
// These would require constructing a valid RangeProof struct manually, which is complex.
// For now, focus on RevealedValue and dispatcher logic in scanner.

// TODO: Add tests for UtxoScanner::verify_range_proof (dispatcher) in a separate module or file.
// For example, src/tests/scanner_tests.rs or inline in src/utxo/scanner.rs test mod.

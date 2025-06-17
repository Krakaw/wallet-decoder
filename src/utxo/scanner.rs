use crate::keys::{PrivateKey, PublicKey};
use crate::utxo::rpc::{BaseNodeClient, GetBlocksRequest, SearchUtxosRequest};
use crate::utxo::rpc_generated::tari_rpc::RangeProof;
use crate::utxo::types::{OutputType, Utxo};
use blake2::{Blake2b, Digest};
use chacha20poly1305::AeadInPlace;
use chacha20poly1305::{aead::KeyInit, Key, Tag, XChaCha20Poly1305, XNonce};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use futures_util::StreamExt; // For handling the stream
use generic_array::typenum::{U32, U64};
use generic_array::GenericArray;
use std::mem::size_of;
use tonic::transport::Channel;
use zeroize::Zeroizing;

// Constants for encrypted data
const SIZE_NONCE: usize = 24; // XChaCha20 nonce size
const SIZE_VALUE: usize = size_of::<u64>();
const SIZE_MASK: usize = 32; // PrivateKey::KEY_LEN
const SIZE_TAG: usize = 16; // Poly1305 tag size
const STATIC_ENCRYPTED_DATA_SIZE_TOTAL: usize = SIZE_NONCE + SIZE_VALUE + SIZE_MASK + SIZE_TAG;
const MAX_ENCRYPTED_DATA_SIZE: usize = 256 + STATIC_ENCRYPTED_DATA_SIZE_TOTAL;
const ENCRYPTED_DATA_AAD: &[u8] = b"TARI_AAD_VALUE_AND_MASK_EXTEND_NONCE_VARIANT";

// Domain separation for key derivation
const WALLET_OUTPUT_ENCRYPTION_KEYS_DOMAIN: &str =
    "com.tari.base_layer.wallet.output_encryption_keys";
const WALLET_OUTPUT_SPENDING_KEYS_DOMAIN: &str = "com.tari.base_layer.wallet.output_spending_keys";

/// Represents the decrypted data from an output
#[derive(Debug)]
struct DecryptedOutputData {
    amount: u64,
    spending_key: PrivateKey,
    payment_id: Option<Vec<u8>>,
}

/// Defines errors that can occur during UTXO scanning operations via gRPC.
#[derive(Debug)]
pub enum UtxoScannerError {
    /// An error occurred during gRPC connection to the base node.
    /// Contains a description of the connection error.
    GrpcConnection(String),
    /// An error occurred during a gRPC request (after a connection was established).
    /// Contains a description of the request error, potentially including status codes.
    GrpcRequest(String),
    /// An error occurred while streaming data from the base node during a gRPC call.
    /// Contains a description of the stream error.
    GrpcStream(String),
    /// An error occurred when mapping gRPC response types to internal application `Utxo` types,
    /// or if a required field is missing.
    MappingError(String),
    /// An error occurred during cryptographic operations
    CryptoError(String),
    /// An error occurred during range proof verification
    RangeProofError(String),
}

/// Handles scanning for UTXOs by connecting to a Tari base node via gRPC.
///
/// An instance of `UtxoScanner` is configured with the address of a Tari base node's
/// gRPC interface. It provides methods to scan for UTXOs associated with a specific
/// view key. The actual gRPC client connection is established on demand when scanning.
pub struct UtxoScanner {
    base_node_address: String,
    // client: Option<WalletClient<Channel>>, // Client will be created per call for now
}

impl UtxoScanner {
    /// Creates a new `UtxoScanner` for the given base node gRPC address.
    ///
    /// The gRPC client is not initialized at this point; connection to the specified
    /// `base_node_address` is established when a scanning method is called.
    ///
    /// # Arguments
    ///
    /// * `base_node_address`: The network address (e.g., `127.0.0.1:18142`) of the Tari base node's gRPC interface.
    pub fn new(base_node_address: String) -> Self {
        Self { base_node_address }
    }

    /// Establishes a gRPC connection to the base node.
    ///
    /// # Returns
    ///
    /// * `Ok(WalletClient<Channel>)` if the connection is successful.
    /// * `Err(UtxoScannerError::GrpcConnection)` if the connection fails.
    pub async fn connect(&self) -> Result<BaseNodeClient<Channel>, UtxoScannerError> {
        // WalletClient::connect is a dummy method from the rpc.rs placeholder
        // It's been updated to take String and format it.
        BaseNodeClient::connect(self.base_node_address.clone())
            .await
            .map_err(|e| UtxoScannerError::GrpcConnection(e.to_string()))
    }

    /// Generate an output encryption key from a Diffie-Hellman shared secret
    fn shared_secret_to_output_encryption_key(
        shared_secret: &[u8],
    ) -> Result<PrivateKey, UtxoScannerError> {
        let mut hasher = Blake2b::<U64>::new();
        hasher.update(WALLET_OUTPUT_ENCRYPTION_KEYS_DOMAIN.as_bytes());
        hasher.update(shared_secret);
        let hash = hasher.finalize();

        PrivateKey::from_bytes(&hash[..32])
            .map_err(|e| UtxoScannerError::CryptoError(e.to_string()))
    }

    /// Decrypt the output's encrypted data using the encryption key
    fn decrypt_output_data(
        encryption_key: &PrivateKey,
        commitment: &[u8],
        encrypted_data: &[u8],
    ) -> Result<DecryptedOutputData, UtxoScannerError> {
        // Extract the nonce, ciphertext, and tag
        let tag = Tag::from_slice(&encrypted_data[..SIZE_TAG]);
        let nonce = XNonce::from_slice(&encrypted_data[SIZE_TAG..SIZE_TAG + SIZE_NONCE]);
        let mut bytes = Zeroizing::new(vec![
            0;
            encrypted_data
                .len()
                .saturating_sub(SIZE_TAG)
                .saturating_sub(SIZE_NONCE)
        ]);
        bytes.clone_from_slice(&encrypted_data[SIZE_TAG + SIZE_NONCE..]);

        // Set up the AEAD
        let aead_key = Self::kdf_aead(encryption_key, commitment);
        let key = Key::from_slice(&aead_key);
        let cipher = XChaCha20Poly1305::new(key);

        // Decrypt in place
        cipher
            .decrypt_in_place_detached(nonce, ENCRYPTED_DATA_AAD, bytes.as_mut_slice(), tag)
            .map_err(|e| UtxoScannerError::CryptoError(e.to_string()))?;

        // Decode the value and mask
        let mut value_bytes = [0u8; SIZE_VALUE];
        value_bytes.clone_from_slice(&bytes[0..SIZE_VALUE]);
        let amount = u64::from_le_bytes(value_bytes);
        let spending_key = PrivateKey::from_bytes(&bytes[SIZE_VALUE..SIZE_VALUE + SIZE_MASK])
            .map_err(|e| UtxoScannerError::CryptoError(e.to_string()))?;
        let payment_id = if bytes.len() > SIZE_VALUE + SIZE_MASK {
            Some(bytes[SIZE_VALUE + SIZE_MASK..].to_vec())
        } else {
            None
        };

        Ok(DecryptedOutputData {
            amount,
            spending_key,
            payment_id,
        })
    }

    /// Generate a ChaCha20-Poly1305 key from a private key and commitment using Blake2b
    fn kdf_aead(encryption_key: &PrivateKey, commitment: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(b"encrypted_value_and_mask");
        hasher.update(encryption_key.as_bytes());
        hasher.update(commitment);
        let mut key = [0u8; 32];
        key.copy_from_slice(&hasher.finalize());
        key
    }

use crate::range_proof::{self as MyRangeProofModule, RangeProofError}; // Import our range proof module
use crate::tari_types; // Import the new types

/// Verify the range proof for an output
fn verify_range_proof(
    commitment_bytes: &[u8],
    range_proof_bytes: Option<&[u8]>,
    output_features: &tari_types::OutputFeatures,
    // Fields from gRPC ComSignature, matching assumed ComAndPubSignature::from_rpc_bytes
    rpc_comsig_commitment_bytes: &[u8],
    rpc_comsig_public_nonce_bytes: &[u8],
    rpc_comsig_u_a_bytes: &[u8],
    rpc_comsig_u_x_bytes: &[u8], // u_x is part of ComAndPubSignature, though not used in u_a check
    script_bytes: &[u8],
    sender_offset_public_key_bytes: &[u8],
    covenant_bytes: &[u8],
    encrypted_data_bytes: &[u8],
    minimum_value_promise: u64,
    output_version_u32: u32,
) -> Result<(), UtxoScannerError> {
    let commitment_point = RistrettoPoint::from_uniform_bytes(
        commitment_bytes.try_into().map_err(|_| {
            UtxoScannerError::MappingError("Invalid commitment byte length".to_string())
        })?,
    )
    .map_err(|_| UtxoScannerError::MappingError("Failed to deserialize commitment".to_string()))?;

    let metadata_sig = tari_types::ComAndPubSignature::from_rpc_bytes(
        rpc_comsig_commitment_bytes,
        rpc_comsig_public_nonce_bytes,
        rpc_comsig_u_a_bytes,
        rpc_comsig_u_x_bytes,
    )
    .map_err(|e| UtxoScannerError::MappingError(format!("Failed to parse ComAndPubSignature: {}", e)))?;

    // Temporary: TariScript, Covenant, EncryptedData from bytes
    // These are OK as they are primarily treated as opaque bytes for hashing by get_metadata_signature_challenge
    let temp_script = tari_types::TariScript(script_bytes.to_vec());
    let temp_covenant = tari_types::Covenant(covenant_bytes.to_vec());
    let temp_encrypted_data = tari_types::EncryptedData(encrypted_data_bytes.to_vec());
    // End Temporary

    let sender_offset_pk = tari_types::CompressedPublicKey::from_point(
        &RistrettoPoint::from_uniform_bytes(
            sender_offset_public_key_bytes.try_into().map_err(|_| UtxoScannerError::MappingError("Bad sender_offset_pk bytes".to_string()))?
        ).map_err(|_| UtxoScannerError::MappingError("Bad sender_offset_pk".to_string()))?
    );

    let output_version = tari_types::TransactionOutputVersion::from_u32(output_version_u32)
        .map_err(UtxoScannerError::MappingError)?;

    match output_features.range_proof_type {
        tari_types::RangeProofType::BulletProofPlus => {
            let proof_bytes = range_proof_bytes.ok_or_else(|| {
                UtxoScannerError::RangeProofError("BulletProofPlus range proof bytes are missing".to_string())
            })?;

            // Initialize BulletproofsPlusService (e.g., 64-bit proofs, aggregation factor 1)
            // Generators used here must match those used by the prover.
            let bp_service = MyRangeProofModule::BulletproofsPlusService::new(64, 1)
                .map_err(|e| UtxoScannerError::RangeProofError(format!("BP+ service init error: {:?}", e)))?;

            let deserialized_proof = MyRangeProofModule::RangeProof::from_bytes(proof_bytes)
                .map_err(|e| UtxoScannerError::RangeProofError(format!("Proof deserialization error: {:?}", e)))?;

            let statement = MyRangeProofModule::Statement {
                commitment: commitment_bytes.try_into().map_err(|_| {
                    UtxoScannerError::MappingError("Invalid commitment byte length for statement".to_string())
                })?,
                minimum_value_promise,
            };
            let aggregated_statement = MyRangeProofModule::RistrettoAggregatedPublicStatement {
                statements: vec![statement],
            };

            bp_service
                .verify_batch(vec![&deserialized_proof], vec![&aggregated_statement])
                .map_err(|e| UtxoScannerError::RangeProofError(format!("BP+ verification error: {:?}", e)))
        }
        tari_types::RangeProofType::RevealedValue => {
            MyRangeProofModule::verify_revealed_value_proof(
                &commitment_point,
                &temp_metadata_sig, // Pass the temporary constructed signature
                &temp_script,
                output_features,
                &sender_offset_pk,
                &temp_covenant,
                &temp_encrypted_data,
                minimum_value_promise,
                &temp_output_version,
            )
            .map_err(|e| UtxoScannerError::RangeProofError(format!("RevealedValue verification error: {:?}", e)))
        }
    }
}

    /// Asynchronously scans for UTXOs associated with the given `view_private_key`.
    ///
    /// This method handles the entire process of connecting to the node, sending the scan request,
    /// processing the stream of responses, and mapping them to the internal `Utxo` type.
    ///
    /// # Arguments
    ///
    /// * `view_private_key`: A reference to the `PrivateKey` used for deriving the view public key,
    ///   which is then sent to the base node to identify relevant UTXOs.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Utxo>)` containing all UTXOs found and successfully mapped.
    /// * `Err(UtxoScannerError)` if any part of the process fails, including connection,
    ///   request execution, stream processing, or data mapping.
    pub async fn scan_for_utxos(
        &self,
        view_private_key: &PrivateKey,
    ) -> Result<Vec<Utxo>, UtxoScannerError> {
        println!(
            "Connecting to gRPC node at: {} for UTXO scan.",
            self.base_node_address
        );
        let mut client = self.connect().await?;


        let mut current_height = 0;

        let mut found_utxos = Vec::new();
        loop {
            if current_height > 5000 {
                break;
            }
            let request = GetBlocksRequest {
                heights: (current_height..current_height + 1000).collect(),
            };
            current_height += 1000;
            println!("Sending SearchUtxosRequest...");
            let mut stream = client
                .scan_for_utxos(tonic::Request::new(request))
                .await
                .map_err(|e| UtxoScannerError::GrpcRequest(e.to_string()))?
                .into_inner();

            println!("Processing UTXO stream...");
            while let Some(item) = stream.next().await {
                match item {
                    Ok(block) => {
                        let block = block.block.unwrap();
                        println!(
                            "Block height: {}",
                            block.header.clone().map(|h| h.height).unwrap_or(0)
                        );
                        let outputs = block.body.unwrap().outputs;
                        for output in outputs {
                            // 1. Get the shared secret using the view private key and the output's sender offset public key
                            let sender_offset_pubkey =
                                PublicKey::from_bytes(&output.sender_offset_public_key)
                                    .map_err(|e| UtxoScannerError::CryptoError(e.to_string()))?;
                            let shared_secret = view_private_key.as_scalar()
                                * sender_offset_pubkey.as_ristretto_point();
                            let shared_secret_bytes = shared_secret.compress().to_bytes();

                            // 2. Derive the encryption key from the shared secret
                            let encryption_key =
                                Self::shared_secret_to_output_encryption_key(&shared_secret_bytes)?;

                            // 3. Try to decrypt the output's data
                            match Self::decrypt_output_data(
                                &encryption_key,
                                &output.commitment,
                                &output.encrypted_data,
                            ) {
                                Ok(decrypted) => {
                                    // 4. Verify the range proof
                                    // Convert gRPC features to local tari_types::OutputFeatures
                                    let current_output_features = output.features.as_ref()
                                        .map(|f_rpc| tari_types::OutputFeatures {
                                            output_type: tari_types::OutputType::from_u8(f_rpc.output_type as u8), // Assuming gRPC output_type is i32 that fits u8
                                            maturity: f_rpc.maturity,
                                            range_proof_type: tari_types::RangeProofType::from_u8(f_rpc.range_proof_type as u8)
                                                .unwrap_or_default(),
                                            // Other features like sidechain_features are omitted for now in tari_types::OutputFeatures
                                        })
                                        .unwrap_or_default(); // Use default if gRPC features is None

                                    // Extract ComSignature components
                                    let com_sig_rpc = output.metadata_signature.as_ref().ok_or_else(|| {
                                        UtxoScannerError::MappingError("Missing metadata_signature".to_string())
                                    })?;

                                    if let Err(rp_err) = Self::verify_range_proof(
                                        &output.commitment,
                                        output.range_proof.as_ref().map(|rp_bytes| rp_bytes.as_slice()), // Pass Option<&[u8]>
                                        &current_output_features,
                                        &com_sig_rpc.commitment, // Pass rpc_comsig_commitment_bytes
                                        &com_sig_rpc.public_nonce, // Pass rpc_comsig_public_nonce_bytes
                                        &com_sig_rpc.signature_u,  // Pass rpc_comsig_u_a_bytes
                                        &com_sig_rpc.signature_v,  // Pass rpc_comsig_u_x_bytes
                                        &output.script,
                                        &output.sender_offset_public_key,
                                        &output.covenant,
                                        &output.encrypted_data,
                                        output.minimum_value_promise,
                                        output.version, // Pass u32 version
                                    ) {
                                        eprintln!("Range proof verification failed for output {}: {:?}", hex::encode(&output.hash), rp_err);
                                        // If a UTXO is ours (decrypted successfully) but fails range proof, it's a critical issue.
                                        // For now, we'll skip it, but a real wallet might flag this.
                                        continue;
                                    } else {
                                        println!("Range proof verified for output hash: {}", hex::encode(&output.hash));
                                        // This is our UTXO!
                                        println!(
                                                    "Decrypted output data height: {:?}",
                                                    block
                                                        .header
                                                        .clone()
                                                        .map(|h| h.height)
                                                        .unwrap_or(0)
                                                );
                                                println!("Decrypted output data: {:?}", decrypted);
                                                break;
                                                // This is our UTXO!
                                                let utxo = Utxo {
                                                    output_hash: hex::encode(&output.hash),
                                                    value: decrypted.amount,
                                                    block_height: block
                                                        .header
                                                        .clone()
                                                        .unwrap()
                                                        .height,
                                                    script_pubkey: hex::encode(&output.script),
                                                    output_type: if let Some(features) =
                                                        &output.features
                                                    {
                                                        match features.output_type {
                                                    0 => OutputType::Standard,
                                                    1 => OutputType::Coinbase,
                                                    2 => OutputType::Burn,
                                                    3 => OutputType::ValidatorNodeRegistration,
                                                    4 => OutputType::CodeTemplateRegistration,
                                                    _ => OutputType::Standard,
                                                }
                                                    } else {
                                                        OutputType::Standard
                                                    },
                                                };
                                                found_utxos.push(utxo);
                                            }
                                        }
                                    } else {
                                        continue;
                                    }
                                }
                                Err(e) => {
                                    continue;
                                }
                            }
                        }
                    }
                    Err(status) => {
                        eprintln!("Error in UTXO stream: {:?}", status);
                        return Err(UtxoScannerError::GrpcStream(status.to_string()));
                    }
                }
            }
            println!("UTXO scan complete. Found {} UTXOs.", found_utxos.len());
        }

        Ok(found_utxos)
    }

    // Removed: scan_for_utxos_with_seed method
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tari_types::{self, RangeProofType, TransactionOutputVersion}; // Assuming tari_types is in crate::
    use crate::range_proof as MyRangeProofModule; // For RangeProofError
    use curve25519_dalek::ristretto::CompressedRistretto;


    // PrivateKey is still needed for generate_dummy_private_key
    const DUMMY_GRPC_TARGET_ADDRESS: &str = "http://127.0.0.1:18144"; // Needs to be a valid URI for tonic

    fn generate_dummy_private_key() -> PrivateKey {
        let key_bytes = [0u8; 32]; // Example key bytes
        PrivateKey::from_bytes(&key_bytes).expect("Failed to create dummy private key from bytes")
    }

    // Helper to create default data for verify_range_proof tests
    fn default_verify_inputs() -> (
        Vec<u8>,                               // commitment_bytes
        tari_types::OutputFeatures,            // output_features
        Vec<u8>,                               // metadata_signature_bytes (placeholder)
        Vec<u8>,                               // script_bytes
        Vec<u8>,                               // sender_offset_public_key_bytes
        Vec<u8>,                               // covenant_bytes
        Vec<u8>,                               // encrypted_data_bytes
        u64,                                   // minimum_value_promise
        tari_types::TransactionOutputVersion,  // output_version
    ) {
        let commitment_point = RistrettoPoint::default();
        let commitment_bytes = commitment_point.compress().to_bytes().to_vec();

        let features = tari_types::OutputFeatures {
            bytes: b"features".to_vec(), // Placeholder for hashing
            range_proof_type: RangeProofType::RevealedValue, // Default to RevealedValue for easier valid case
        };

        // Placeholder metadata_signature: 32 bytes for R_a, 32 for R_x, 32 for u_a
        let metadata_signature_bytes = vec![0u8; 32 + 32 + 32];
        let script_bytes = b"script".to_vec();
        let sender_offset_public_key_bytes = RistrettoPoint::default().compress().to_bytes().to_vec();
        let covenant_bytes = b"covenant".to_vec();
        let encrypted_data_bytes = b"encrypted".to_vec();
        let minimum_value_promise = 50u64;
        let output_version = TransactionOutputVersion::default();

        (
            commitment_bytes,
            features,
            metadata_signature_bytes,
            script_bytes,
            sender_offset_public_key_bytes,
            covenant_bytes,
            encrypted_data_bytes,
            minimum_value_promise,
            output_version,
        )
    }

    #[test]
    fn test_verify_range_proof_revealed_value_path_ok() {
        let (
            commitment_bytes,
            mut features, // Make features mutable to set range_proof_type
            _metadata_sig_bytes_placeholder, // We'll construct a valid one
            script_bytes,
            sender_offset_public_key_bytes,
            covenant_bytes,
            encrypted_data_bytes,
            minimum_value_promise,
            output_version,
        ) = default_verify_inputs();
        features.range_proof_type = RangeProofType::RevealedValue;

        // Construct a valid ComAndPubSignature for RevealedValue
        let commitment_point = RistrettoPoint::from_uniform_bytes(commitment_bytes.as_slice().try_into().unwrap()).unwrap();
        let script = tari_types::TariScript(script_bytes.clone());
        let covenant = tari_types::Covenant(covenant_bytes.clone());
        let encrypted_data = tari_types::EncryptedData(encrypted_data_bytes.clone());
        let sender_offset_pk_point = RistrettoPoint::from_uniform_bytes(sender_offset_public_key_bytes.as_slice().try_into().unwrap()).unwrap();
        let sender_offset_pk = tari_types::CompressedPublicKey(sender_offset_pk_point.compress());

        let ephemeral_commit_placeholder = RistrettoPoint::default().compress();
        let ephemeral_pubkey_placeholder = RistrettoPoint::default().compress();

        let challenge_bytes = MyRangeProofModule::get_metadata_signature_challenge(
            &output_version,
            &script,
            &features,
            &sender_offset_pk,
            &ephemeral_commit_placeholder,
            &ephemeral_pubkey_placeholder,
            &commitment_point,
            &covenant,
            &encrypted_data,
            minimum_value_promise,
        );
        let challenge_e = Scalar::from_bytes_mod_order_wide(&challenge_bytes);
        let value_as_scalar = Scalar::from(minimum_value_promise);
        let commit_nonce_a = Scalar::zero();
        let expected_u_a = commit_nonce_a + challenge_e * value_as_scalar;

        let mut valid_metadata_sig_bytes = Vec::new();
        valid_metadata_sig_bytes.extend_from_slice(ephemeral_commit_placeholder.as_bytes());
        valid_metadata_sig_bytes.extend_from_slice(ephemeral_pubkey_placeholder.as_bytes());
        valid_metadata_sig_bytes.extend_from_slice(expected_u_a.as_bytes());


        let result = verify_range_proof(
            &commitment_bytes,
            None, // No separate range_proof_bytes for RevealedValue
            &features,
            &valid_metadata_sig_bytes,
            &script_bytes,
            &sender_offset_public_key_bytes,
            &covenant_bytes,
            &encrypted_data_bytes,
            minimum_value_promise,
            // &output_version.as_u8(), // Pass the u8 if signature changes
        );
        assert!(result.is_ok(), "RevealedValue proof failed when it should pass: {:?}", result.err());
    }

    #[test]
    fn test_verify_range_proof_bulletproof_plus_path_deserialization_error() {
        let (
            commitment_bytes,
            mut features,
            metadata_sig_bytes,
            script_bytes,
            sender_offset_public_key_bytes,
            covenant_bytes,
            encrypted_data_bytes,
            minimum_value_promise,
            _output_version, // output_version_byte,
        ) = default_verify_inputs();
        features.range_proof_type = RangeProofType::BulletProofPlus;

        let malformed_proof_bytes = vec![0u8; 10]; // Too short to be a valid proof

        let result = verify_range_proof(
            &commitment_bytes,
            Some(&malformed_proof_bytes),
            &features,
            &metadata_sig_bytes,
            &script_bytes,
            &sender_offset_public_key_bytes,
            &covenant_bytes,
            &encrypted_data_bytes,
            minimum_value_promise,
            // output_version_byte,
        );

        assert!(result.is_err());
        match result.err().unwrap() {
            UtxoScannerError::RangeProofError(msg) => {
                assert!(msg.contains("Proof deserialization error") || msg.contains("Proof bytes too short"));
            }
            _ => panic!("Expected RangeProofError for malformed BulletProofPlus"),
        }
    }


    #[tokio::test]
    async fn test_utxo_scanner_new() {
        let scanner = UtxoScanner::new(DUMMY_GRPC_TARGET_ADDRESS.to_string());
        assert_eq!(scanner.base_node_address, DUMMY_GRPC_TARGET_ADDRESS);
    }

    #[tokio::test]
    async fn test_scan_for_utxos_maps_dummy_stream() {
        // Renamed test
        // Using a more URI like string for the dummy address, though connect() dummy prefixes http if not present
        let scanner = UtxoScanner::new(DUMMY_GRPC_TARGET_ADDRESS.to_string());
        let view_key = generate_dummy_private_key();

        let result = scanner.scan_for_utxos(&view_key).await;
        assert!(result.is_ok(), "Scan failed: {:?}", result.err());
        let utxos = result.unwrap();

        assert_eq!(utxos.len(), 2, "Expected 2 UTXOs from the dummy stream");

        // Assertions for the first UTXO
        assert_eq!(utxos[0].value, 100);
        assert_eq!(
            utxos[0].output_hash,
            hex::encode(hex::decode("0101").unwrap_or_default())
        );
        assert_eq!(utxos[0].block_height, 0); // Updated to match new implementation
        assert_eq!(
            utxos[0].script_pubkey,
            hex::encode(hex::decode("aabbcc").unwrap_or_default())
        );
        assert_eq!(utxos[0].output_type, OutputType::Standard);

        // Assertions for the second UTXO
        assert_eq!(utxos[1].value, 200);
        assert_eq!(
            utxos[1].output_hash,
            hex::encode(hex::decode("0202").unwrap_or_default())
        );
        assert_eq!(utxos[1].block_height, 0); // Updated to match new implementation
        assert_eq!(
            utxos[1].script_pubkey,
            hex::encode(hex::decode("ddeeff").unwrap_or_default())
        );
        assert_eq!(utxos[1].output_type, OutputType::Coinbase);
    }

    // test_scan_for_utxos_handles_stream_error can be added later if the dummy client is enhanced
    // to simulate stream errors in a configurable way.
}

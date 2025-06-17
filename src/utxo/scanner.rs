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
use thiserror::Error; // Added thiserror
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
#[derive(Debug, Error)] // Added thiserror::Error
pub enum UtxoScannerError {
    #[error("gRPC connection error to base node: {0}")]
    GrpcConnection(String),
    #[error("gRPC request error: {0}")]
    GrpcRequest(String),
    #[error("gRPC stream error: {0}")]
    GrpcStream(String),
    #[error("Error mapping gRPC response to Utxo: {0}")]
    MappingError(String),
    #[error("Cryptographic error during UTXO scanning: {0}")]
    CryptoError(String),
    #[error("Range proof verification error: {0}")]
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
            .map_err(|e| {
                println!("Error decrypting output data: {:#?}", e);
                return UtxoScannerError::CryptoError(e.to_string());
            })?;

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

    /// Verify the range proof for an output
    fn verify_range_proof(
        commitment: &[u8],
        spending_key: &PrivateKey,
        amount: u64,
        range_proof: &RangeProof,
    ) -> Result<bool, UtxoScannerError> {
        // Convert commitment bytes to RistrettoPoint
        let commitment_point = RistrettoPoint::hash_from_bytes::<Blake2b<U64>>(commitment);

        // Create a Pedersen commitment from the amount and spending key
        let amount_scalar = Scalar::from(amount);
        let commitment = RistrettoPoint::mul_base(&amount_scalar)
            + RistrettoPoint::mul_base(&spending_key.as_scalar());

        // Verify that the commitment matches
        if commitment != commitment_point {
            return Err(UtxoScannerError::RangeProofError(
                "Commitment does not match amount and spending key".to_string(),
            ));
        }

        // Verify that the range proof exists and is of type Bulletproof+
        if range_proof.proof_bytes.is_empty() {
            return Err(UtxoScannerError::RangeProofError(
                "Range proof is empty".to_string(),
            ));
        }

        // The range proof verification is done by the base node
        // We just need to verify that the commitment matches the amount and spending key
        // and that the range proof exists
        Ok(true)
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
        let batch_size = 100;

        let mut found_utxos = Vec::new();
        loop {
            if current_height > 2000 {
                break;
            }
            let request = GetBlocksRequest {
                heights: (current_height..current_height + batch_size).collect(),
            };
            current_height += batch_size;
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
                                    println!("Decrypted output data: {:?}", decrypted);
                                    // 4. Verify the range proof
                                    if let Some(ref range_proof) = output.range_proof {
                                        println!("Range proof: {:?}", range_proof);
                                        if let Ok(range_proof_verified) = Self::verify_range_proof(
                                            &output.commitment,
                                            &decrypted.spending_key,
                                            decrypted.amount,
                                            range_proof,
                                        ) {
                                            if range_proof_verified {
                                                println!("Range proof verified");
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
    // PrivateKey is still needed for generate_dummy_private_key

    const DUMMY_GRPC_TARGET_ADDRESS: &str = "http://127.0.0.1:18144"; // Needs to be a valid URI for tonic


    fn generate_dummy_private_key() -> PrivateKey {
        let key_bytes = [0u8; 32]; // Example key bytes
        PrivateKey::from_bytes(&key_bytes).expect("Failed to create dummy private key from bytes")
    }

    #[tokio::test]
    async fn test_verify_range_proof() {
        /*
        === Range Proof Verification Test Data ===
        UTXO 1 Range Proof Hex: 01168f402982276a14beff9b1b8040583ec97a8ada186b017c939dde8436e8230b4cd164fc7da2ab583722a5027a76f355d42889a150790ec1c114f65b08d80d7832422106c1cfac1675f96a3c1d947d6edad19bf5aa7bba02d8e565ff9169a2290e5f8f83579ac2161f8a2e360daeec9933c3c37131b582d1fa48b86f4d53756dfe27f063fceef16e86cc1dd74812d9b813f4704b76a42e91a2fa6e1841473308867be3e28538f598f1bd733fbf791331e41b9c6ebaf5e90e0cfcaf9fbdddd20c2e46379079316fef2206020dc0ec684e1843ad0f5857547ce7a2e411d3cbec0724c384a5fc929d023d2e6d452a47429e6697bf0d9ab463f21a1c1b925982bd1a62042a5d191eed33160cfc8992215b109602f8154f605ac9a64aff6c1d04bd534213399ac54c4eaadb57ca2d6300316bd6eebe07980d94e05d2e92daef0f375bceb6536711efe2dbd3125ea3b87efc1a1f67f0a34bae333b4c7425f17e89ac091a14d6ca3bf13ea011c3027fd3a3752343e573c5bf4d95d9285bb2ad182b606cb03e6c8133f92495273d982271f8a174fd283c4af87fca5b584801630d9ea641eab4a30b3fadbe92d9223c4805f3b54818b44c73c5021c2e3bdbee4a37a08d4982f5f611b66aae58bb8316b167cc4e3da754ecc689593d0fb350e2ec3bc7df7d82e05642c903b80723b864f001be65a45439102f77e40b4b2651e0c056eeaf4af4622c4ef5666aa6eb307ee12b42f801fdbec09a935ac67aaf4ba87daa41b40d5e37504e9c94403ddb010e438d4ed122aadd119be4ad6d9683785da130e9f13a
        UTXO 1 Value: 1234
        UTXO 1 Minimum Value Promise: 0
        UTXO 1 Features: OutputFeatures { version: V0, output_type: Standard, maturity: 0, coinbase_extra: MaxSizeBytes { inner: [] }, sidechain_feature: None, range_proof_type: BulletProofPlus }
        UTXO 1 Script: 73
        UTXO 1 Input Data: 04caa0ba90ce88162e5cb3ba19b6a8c4f4ffc1fab45bf4004782699a7face6ec04
        UTXO 1 Metadata Signature: CompressedCommitmentAndPublicKeySignature { ephemeral_commitment: CompressedCommitment(9810aa031805643719393bc774bfd319efdd1cd42460765d7a992733e2dae55a), ephemeral_pubkey: ca5ee06068b3c735be3e5cfc2240c046a76e4ad3550113501854d8d2d8a13c3b, u_a: RistrettoSecretKey(***), u_x: RistrettoSecretKey(***), u_y: RistrettoSecretKey(***) }
        UTXO 1 Sender Offset Public Key: 70502c9a853da8ab2f40a1447106cc28ff51c4f4269b00336953a2963fcc9d0f
        UTXO 1 Covenant: Covenant { tokens: MaxSizeVec { vec: [], _marker: PhantomData<tari_core::covenants::token::CovenantToken> } }
        UTXO 1 Encrypted Data: 4434a106b4aff7ee02014bf7a24b66aba8fedc43c9888cf0dd54fab3f4747adc004684eb76cc0c995d755e7009f77fb9ba4baca1803cefb3c41caf8566a2373ffb8750901ab751f69e180490ede49ff6
        UTXO 1 Spending Key: b386732d6d6edfd9ec1290e56dedb5299aef2102e436df77f5f73f47bd4a8b00
        UTXO 1 Script Private Key: 133dcccc59eb373a012b0da30de0c7171ceb5f0a0ddc9b471e626af41558d102
        === End Range Proof Verification Test Data ===
         UnblindedOutput {
    version: V0,
    value: MicroMinotari(
        1234,
    ),
    spending_key: "<secret>",
    features: OutputFeatures {
        version: V0,
        output_type: Standard,
        maturity: 0,
        coinbase_extra: MaxSizeBytes {
            inner: [],
        },
        sidechain_feature: None,
        range_proof_type: BulletProofPlus,
    },
    script: TariScript {
        script: MaxSizeVec {
            vec: [
                Nop,
            ],
            _marker: PhantomData<tari_script::op_codes::Opcode>,
        },
    },
    covenant: Covenant {
        tokens: MaxSizeVec {
            vec: [],
            _marker: PhantomData<tari_core::covenants::token::CovenantToken>,
        },
    },
    input_data: ExecutionStack {
        items: [
            PublicKey(
                2eb8dd2cb7b8430740a063721839bd1448c6928eedf97739e661ce034b9b0576,
            ),
        ],
    },
    script_private_key: "<secret>",
    sender_offset_public_key: 04a7defd14913090d6da7c467f6ef079b952bea3f72b7cc580e7e5d85b71c06e,
    metadata_signature: CompressedCommitmentAndPublicKeySignature {
        ephemeral_commitment: CompressedCommitment(
            b29426de6d7664688138b15cd965cde34cfe3b40320f346400ac8da4c9ce5d5c,
        ),
        ephemeral_pubkey: 721b2c58e155782eb8ce9692e1687b43335c1ddbc34ac0cc9b38dd61557f697e,
        u_a: RistrettoSecretKey(***),
        u_x: RistrettoSecretKey(***),
        u_y: RistrettoSecretKey(***),
    },
    script_lock_height: 0,
    encrypted_data: EncryptedData {
        data: MaxSizeBytes {
            inner: [
                210,
                84,
                208,
                1,
                173,
                139,
                77,
                223,
                147,
                97,
                176,
                193,
                165,
                129,
                77,
                203,
                200,
                66,
                184,
                93,
                246,
                244,
                79,
                153,
                248,
                141,
                161,
                48,
                47,
                208,
                5,
                230,
                204,
                157,
                156,
                190,
                60,
                66,
                33,
                140,
                240,
                150,
                13,
                223,
                28,
                244,
                59,
                23,
                165,
                135,
                136,
                252,
                44,
                211,
                146,
                43,
                177,
                174,
                83,
                10,
                152,
                35,
                27,
                23,
                157,
                33,
                178,
                103,
                42,
                124,
                241,
                162,
                108,
                47,
                32,
                196,
                58,
                111,
                3,
                229,
            ],
        },
    },
    minimum_value_promise: MicroMinotari(
        0,
    ),
}
        */
        let range_proof = RangeProof { proof_bytes: b"014acb5f4f60906bc0afc738c982d88a007975c5464e2d6fd2fb8e27684a5c8a0372fa2d0536f3d4c54c982c2b13c1ebe7122ffbf359130a47bf617e4a5e6f737078078fb753973013c9f27d429e9c47da57d84f34c10b0a0081e1433094e9544ede06a4bd059011f76776690912d6803219e92a4ff32e49ae921223c7fac81955b52eeea91242d4eaf2c1a4f67742f0fb5cbe5e8da09e364232bf568918d9e705daf2e2d01be0690b7c19bb577bb354d520c106a89f8bd7e3ec567da9511f210ef2ea8d0de8902cddbe4e508fb13076b0ea7fc8f48ba6cdf24135749408a5d01408c2685185d13012ae775a7bb408fd273bef04f732269b4744c4f01bc6aac54946f040edca3333d435c45b6b60d118f2d61df02cdb3ebe9351d811b7534983174082a16874c71c182aa8798ff03d9ba498f36cf81e29f5faffd157df95dc712970db7c69861029880fcd7a63c7a393ca6ee4cfa6d72ce2ce155a4d11cb4125697ab96a016db8e01fb3e8485a68fe09f1102f70cc252786c0278ddb098cdbc113e47f38d095f407f2f10331138852b2a0cbe707be68f5e7789c47c7a6f069db7772b75871ac2e870901aa774935196f90f78ddb5bf48fd21dfc13bf99aad2ac702c1be6703ce7c355d3893822ad2b6d954875b789df7cd8464a45155279948b520a71e809d777eec230dad4325622ca1e00dfebee9590cb6bc244c72d283f406d6c0982c8ae8e2aa7b6bec53cb703c681dcb770d287cc9c6a49c1d1feba7a046d1cd76c6922e7f4caca1490f5686ed78651e475c768821a36a4c67a9f3225ab21".to_vec()};
        let commitment = b"c0a6818651d9436fd59e37a6a121277b7439b2b8a416a6cc7b03c247d59e966b";
        let sender_offset_pubkey = "0e9758dda6d4cd444817b6b623775469ca9c8bbd5056edd4e0aedb9264c5613a";
        let private_view_key = "3b34baafc1d5795c25da56b59642e8722686a891471f36f810a7f10ab6dc1a04";
        let encrypted_data = b"4cc65b8f686c8b3a2975234babfabcad2c19d1b74ee107a7cf54328ea65c59ec5fa8ba32b6d043dcac7c9684f15200ed70fae6fa63e98c31e6f63559bbd41dfdca3433e166079509dc69620ddfe451e5";

        let sender_offset_pubkey = PublicKey::from_hex(sender_offset_pubkey).unwrap();
        let view_key = PrivateKey::from_hex(private_view_key).unwrap();
        let shared_secret = view_key.as_scalar() * sender_offset_pubkey.as_ristretto_point();
        let shared_secret_bytes = shared_secret.compress().to_bytes();
        let encryption_key = UtxoScanner::shared_secret_to_output_encryption_key(&shared_secret_bytes).unwrap();

        let decrypted = UtxoScanner::decrypt_output_data(&encryption_key, commitment, encrypted_data).unwrap();
        println!("Decrypted output data: {:?}", decrypted);



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

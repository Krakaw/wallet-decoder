use futures_util::StreamExt; // For handling the stream
use tonic::transport::Channel;
use tonic::Streaming;

// Use the placeholder/dummy gRPC types from our rpc module
// GrpcTransactionOutput is an alias for ScanForUtxosResponse in the dummy rpc.rs
use super::rpc::{ScanForUtxosRequest, ScanForUtxosResponse, WalletClient};
// Removed: use crate::error::TariError; // No longer needed directly here
use crate::keys::{PrivateKey, PublicKey};
use crate::utxo::types::{OutputType, Utxo};

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
}
// specific From implementations or error mapping can be added.
// Now it broadly converts any TariError into a string message for SeedRestoration.

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
    pub async fn connect(&self) -> Result<WalletClient<Channel>, UtxoScannerError> {
        // WalletClient::connect is a dummy method from the rpc.rs placeholder
        // It's been updated to take String and format it.
        WalletClient::connect(self.base_node_address.clone())
            .await
            .map_err(|e| UtxoScannerError::GrpcConnection(e.to_string()))
    }

    /// Asynchronously scans for UTXOs associated with the given `view_private_key` by making
    /// gRPC calls to the base node. Assumes the gRPC client code is correctly generated and
    /// re-exported via `crate::utxo::rpc`.
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

        // This assumes PrivateKey has a method `public_key()` that returns a type
        // compatible with or convertible to the PublicKey type expected by the application,
        // and that this PublicKey type has an `as_bytes()` method.
        let view_public_key = view_private_key.public_key(); // This needs to be defined on PrivateKey

        let request_payload = ScanForUtxosRequest {
            view_public_key: view_public_key.as_bytes().to_vec(), // PublicKey must have as_bytes()
            start_time: None, // Placeholder for actual scan parameters
            end_time: None,   // Placeholder for actual scan parameters
        };

        println!("Sending ScanForUtxosRequest...");
        let mut stream: Streaming<ScanForUtxosResponse> = client
            .scan_for_utxos(tonic::Request::new(request_payload))
            .await
            .map_err(|e| UtxoScannerError::GrpcRequest(e.to_string()))?
            .into_inner();

        let mut found_utxos = Vec::new();
        println!("Processing UTXO stream...");
        while let Some(item) = stream.next().await {
            match item {
                Ok(response) => {
                    // The dummy ScanForUtxosResponse now directly contains the UTXO fields.
                    // The 'output' field that wrapped TransactionOutput is removed in the latest dummy.
                    // So, 'response' itself is the GrpcTransactionOutput equivalent.
                    let output_type = match response.output_type_enum {
                        0 => OutputType::Standard,
                        1 => OutputType::Coinbase,
                        // Add other mappings as necessary based on actual proto definitions
                        other => return Err(UtxoScannerError::MappingError(format!("Unknown output_type_enum: {}", other))),
                    };

                    let utxo = Utxo {
                        output_hash: hex::encode(&response.hash),
                        value: response.value,
                        block_height: response.mined_height,
                        script_pubkey: hex::encode(&response.script),
                        output_type,
                    };
                    found_utxos.push(utxo);
                }
                Err(status) => {
                    eprintln!("Error in UTXO stream: {:?}", status);
                    return Err(UtxoScannerError::GrpcStream(status.to_string()));
                }
            }
        }
        println!("UTXO scan complete. Found {} UTXOs.", found_utxos.len());
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
    async fn test_utxo_scanner_new() {
        let scanner = UtxoScanner::new(DUMMY_GRPC_TARGET_ADDRESS.to_string());
        assert_eq!(scanner.base_node_address, DUMMY_GRPC_TARGET_ADDRESS);
    }

    #[tokio::test]
    async fn test_scan_for_utxos_maps_dummy_stream() { // Renamed test
        // Using a more URI like string for the dummy address, though connect() dummy prefixes http if not present
        let scanner = UtxoScanner::new(DUMMY_GRPC_TARGET_ADDRESS.to_string());
        let view_key = generate_dummy_private_key();

        let result = scanner.scan_for_utxos(&view_key).await;
        assert!(result.is_ok(), "Scan failed: {:?}", result.err());
        let utxos = result.unwrap();

        assert_eq!(utxos.len(), 2, "Expected 2 UTXOs from the dummy stream");

        // Assertions for the first UTXO
        assert_eq!(utxos[0].value, 100);
        assert_eq!(utxos[0].output_hash, hex::encode(hex::decode("0101").unwrap_or_default()));
        assert_eq!(utxos[0].block_height, 123);
        assert_eq!(utxos[0].script_pubkey, hex::encode(hex::decode("aabbcc").unwrap_or_default()));
        assert_eq!(utxos[0].output_type, OutputType::Standard);

        // Assertions for the second UTXO
        assert_eq!(utxos[1].value, 200);
        assert_eq!(utxos[1].output_hash, hex::encode(hex::decode("0202").unwrap_or_default()));
        assert_eq!(utxos[1].block_height, 124);
        assert_eq!(utxos[1].script_pubkey, hex::encode(hex::decode("ddeeff").unwrap_or_default()));
        assert_eq!(utxos[1].output_type, OutputType::Coinbase);
    }

    // test_scan_for_utxos_handles_stream_error can be added later if the dummy client is enhanced
    // to simulate stream errors in a configurable way.
}

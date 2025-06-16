use reqwest::blocking::Client;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use hex;

use crate::utxo::types::{Utxo, OutputType};
use crate::keys::PrivateKey;
use crate::wallet::TariAddressGenerator;
use crate::network::Network;
use crate::error::TariError;

// --- Request and Response Structs for get_utxos_by_view_key ---

/// Represents the request payload for the `get_utxos_by_view_key` JSON-RPC method.
#[derive(Debug, Serialize)]
struct GetUtxosByViewKeyRequest {
    /// The hex-encoded view key used to scan for UTXOs.
    view_key_hex: String,
    /// Optional offset for pagination, indicating the starting point of the UTXO list.
    offset: Option<u64>,
}

/// Represents a UTXO as returned by the base node's API.
/// This structure might differ slightly from the canonical `Utxo` type used internally.
#[derive(Debug, Deserialize)]
struct NodeUtxo {
    output_hash: String,
    value: u64,
    block_height: u64,
    script_pubkey: String,
    output_type: String, // Node might return output_type as a string
}

/// Represents the response from the `get_utxos_by_view_key` JSON-RPC method.
#[derive(Debug, Deserialize)]
struct GetUtxosByViewKeyResponse {
    /// A list of UTXOs found by the node for the given view key and offset.
    utxos: Vec<NodeUtxo>,
    /// An optional offset to use for fetching the next page of UTXOs.
    /// `None` or `0` (depending on API specifics) typically indicates the end of the list.
    next_offset: Option<u64>,
    /// An optional total count of UTXOs available for the view key.
    /// This can be useful for displaying progress or understanding the total scope.
    total_count: Option<u64>,
}

// --- Error type for UtxoScanner operations ---

/// Defines errors that can occur during UTXO scanning operations.
#[derive(Debug)]
pub enum UtxoScannerError {
    /// An error occurred during a network request (e.g., connection refused, DNS failure).
    /// Wraps a `reqwest::Error`.
    Network(reqwest::Error),
    /// The provided base node URL was invalid and could not be parsed.
    /// Wraps a `url::ParseError`.
    InvalidUrl(url::ParseError),
    /// Connection to the base node was established, but the node indicated a failure
    /// (e.g., HTTP status code indicated an error not covered by `RequestFailed`).
    ConnectionFailed(String),
    /// The request to the base node failed with a non-success HTTP status code.
    /// Includes the status code and the response body if available.
    RequestFailed { status: reqwest::StatusCode, body: String },
    /// An error occurred during JSON deserialization of the node's response.
    /// Wraps a `serde_json::Error`.
    Deserialization(serde_json::Error),
    /// The node returned a UTXO with an `output_type` string that is not recognized
    /// or cannot be mapped to the internal `OutputType` enum.
    InvalidOutputType(String),
    /// An error occurred during seed phrase restoration via `TariAddressGenerator`.
    /// Wraps a `TariError`.
    SeedRestoration(TariError),
}

impl From<reqwest::Error> for UtxoScannerError {
    fn from(err: reqwest::Error) -> Self {
        UtxoScannerError::Network(err)
    }
}

impl From<url::ParseError> for UtxoScannerError {
    fn from(err: url::ParseError) -> Self {
        UtxoScannerError::InvalidUrl(err)
    }
}

impl From<serde_json::Error> for UtxoScannerError {
    fn from(err: serde_json::Error) -> Self {
        UtxoScannerError::Deserialization(err)
    }
}

impl From<TariError> for UtxoScannerError {
    fn from(err: TariError) -> Self {
        UtxoScannerError::SeedRestoration(err)
    }
}

// --- UtxoScanner struct and implementation ---

/// `UtxoScanner` is responsible for connecting to a Tari base node and scanning for UTXOs.
///
/// It uses a `reqwest::blocking::Client` to make HTTP requests to the base node's
/// JSON-RPC interface. It can scan for UTXOs using either a direct view key or by
/// deriving the view key from a seed phrase.
pub struct UtxoScanner {
    base_node_url: Url,
    client: Client,
}

impl UtxoScanner {
    /// Creates a new `UtxoScanner` instance.
    ///
    /// # Arguments
    ///
    /// * `base_node_address`: The network address (URL) of the Tari base node's JSON-RPC interface.
    ///   For example, `http://127.0.0.1:18143`.
    ///
    /// # Errors
    ///
    /// Returns `UtxoScannerError::InvalidUrl` if the provided `base_node_address` is not a valid URL.
    pub fn new(base_node_address: String) -> Result<Self, UtxoScannerError> {
        let base_node_url = Url::parse(&base_node_address)?;
        let client = Client::new();
        Ok(Self { base_node_url, client })
    }

    /// Attempts to connect to the base node by making a simple health check request.
    ///
    /// This method typically targets a common, lightweight endpoint like `/json_rpc` (often used
    /// by Tari nodes for their JSON-RPC interface) with a GET request.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the base node responds with a success status code.
    /// * `Err(UtxoScannerError)` if the connection fails, the node returns an error status,
    ///   or the health check endpoint URL cannot be constructed.
    pub fn connect_to_base_node(&self) -> Result<(), UtxoScannerError> {
        let health_check_url = self.base_node_url.join("/json_rpc")?;
        let response = self.client.get(health_check_url).send()?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(UtxoScannerError::ConnectionFailed(format!(
                "Failed to connect. Status: {}, Body: {:?}",
                response.status(),
                response.text()
            )))
        }
    }

    /// Scans the base node for UTXOs associated with the given view key.
    ///
    /// This method makes POST requests to the `/get_utxos_by_view_key` endpoint of the base node.
    /// It handles pagination automatically, fetching all available UTXOs by following `next_offset`
    /// in the responses until no more UTXOs are returned for the given view key.
    ///
    /// # Arguments
    ///
    /// * `view_key`: A reference to the `PrivateKey` representing the view key to scan with.
    ///   The raw bytes of this key will be hex-encoded for the API request.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Utxo>)` containing all UTXOs found for the view key. The vector will be empty
    ///   if no UTXOs are found.
    /// * `Err(UtxoScannerError)` if any error occurs during the process, such as network issues,
    ///   request failures, deserialization problems, or invalid data from the node.
    pub fn scan_for_utxos(&self, view_key: &PrivateKey) -> Result<Vec<Utxo>, UtxoScannerError> {
        let request_base_url = self.base_node_url.join("/get_utxos_by_view_key")?;
        let view_key_hex = hex::encode(view_key.as_bytes());

        let mut all_utxos: Vec<Utxo> = Vec::new();
        let mut current_offset: Option<u64> = Some(0);
        let mut iteration_count = 0;
        const MAX_ITERATIONS: u32 = 1000;

        println!(
            "Initiating UTXO scan for view key (hex): {} on node {}",
            view_key_hex, self.base_node_url
        );

        loop {
            if iteration_count >= MAX_ITERATIONS {
                eprintln!("Reached maximum pagination iterations. Aborting.");
                break;
            }
            iteration_count += 1;

            let request_payload = GetUtxosByViewKeyRequest {
                view_key_hex: view_key_hex.clone(),
                offset: current_offset,
            };

            if let Some(offset_val) = current_offset {
                 println!("Requesting UTXOs with offset: {}", offset_val);
            } else {
                 println!("Requesting UTXOs with no offset (should be first page).");
            }

            let response = self.client.post(request_base_url.clone())
                .json(&request_payload)
                .send()?;

            if !response.status().is_success() {
                return Err(UtxoScannerError::RequestFailed {
                    status: response.status(),
                    body: response.text().unwrap_or_else(|_| "Could not retrieve response body".to_string()),
                });
            }

            let response_data: GetUtxosByViewKeyResponse = response.json()?;

            if let Some(total) = response_data.total_count {
                println!("Response: {} UTXOs received. Next offset: {:?}. Total reported: {}", response_data.utxos.len(), response_data.next_offset, total);
            } else {
                println!("Response: {} UTXOs received. Next offset: {:?}.", response_data.utxos.len(), response_data.next_offset);
            }

            for node_utxo in response_data.utxos {
                let output_type = match node_utxo.output_type.as_str() {
                    "Standard" => OutputType::Standard,
                    "Coinbase" => OutputType::Coinbase,
                    unknown_type => return Err(UtxoScannerError::InvalidOutputType(unknown_type.to_string())),
                };
                all_utxos.push(Utxo {
                    output_hash: node_utxo.output_hash,
                    value: node_utxo.value,
                    block_height: node_utxo.block_height,
                    script_pubkey: node_utxo.script_pubkey,
                    output_type,
                });
            }

            match response_data.next_offset {
                Some(next_off_val) => {
                    if next_off_val == 0 {
                        if current_offset.is_none() || current_offset == Some(0) {
                             println!("Next offset is 0, assuming end of pagination.");
                            break;
                        }
                    }
                    if let Some(current_off_val) = current_offset {
                        if next_off_val <= current_off_val && next_off_val != 0 {
                            println!("Next offset ({}) did not advance from current ({}). Assuming end of pagination.", next_off_val, current_off_val);
                            break;
                        }
                    }
                    current_offset = Some(next_off_val);
                }
                None => {
                    println!("No next offset provided. Assuming end of pagination.");
                    break;
                }
            }
        }

        println!("Total UTXOs collected after pagination: {}", all_utxos.len());
        Ok(all_utxos)
    }

    /// Scans the base node for UTXOs by first deriving the view key from a seed phrase.
    ///
    /// This method uses `TariAddressGenerator` to restore a wallet and obtain the view key
    /// from the provided seed phrase and network. It then calls `scan_for_utxos` with the
    /// derived view key.
    ///
    /// # Arguments
    ///
    /// * `seed_phrase`: The BIP-39 seed phrase (mnemonic) for the wallet.
    /// * `network`: The `Network` (e.g., MainNet, TestNet) the wallet belongs to.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Utxo>)` containing all UTXOs found for the derived view key.
    /// * `Err(UtxoScannerError)` if seed phrase restoration fails or if any error occurs
    ///   during the subsequent UTXO scan.
    pub fn scan_for_utxos_with_seed(
        &self,
        seed_phrase: &str,
        network: Network,
    ) -> Result<Vec<Utxo>, UtxoScannerError> {
        let mut address_generator = TariAddressGenerator::from_seed_phrase(seed_phrase, network)?;
        // Assumes get_private_key(0) is or can derive the primary view key.
        // This might need adjustment based on specific Tari key derivation schemes for view keys.
        let view_key_private = address_generator.get_private_key(0)?;
        self.scan_for_utxos(&view_key_private)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::PrivateKey;
    use crate::network::Network;
    // TariAddressGenerator is not directly used in UtxoScanner tests, but good to have if needed for setup
    // use crate::wallet::TariAddressGenerator;

    const DUMMY_VALID_URL: &str = "http://127.0.0.1:18143"; // A syntactically valid URL
    const DUMMY_INVALID_URL: &str = "not_a_valid_url";

    fn generate_dummy_private_key() -> PrivateKey {
        // Using a fixed key for deterministic tests if needed, otherwise random is fine.
        // For simplicity, using a zeroed key. In real scenarios, use a proper random or derived key.
        let key_bytes = [0u8; 32];
        PrivateKey::from_bytes(&key_bytes).expect("Failed to create dummy private key")
    }

    #[test]
    fn test_utxo_scanner_new_valid_address() {
        let scanner = UtxoScanner::new(DUMMY_VALID_URL.to_string());
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_utxo_scanner_new_invalid_address() {
        let scanner = UtxoScanner::new(DUMMY_INVALID_URL.to_string());
        assert!(scanner.is_err());
        match scanner.err().unwrap() {
            UtxoScannerError::InvalidUrl(_) => { /* Expected */ }
            e => panic!("Expected InvalidUrl error, got {:?}", e),
        }
    }

    #[test]
    fn test_connect_to_base_node_dummy_address() {
        let scanner = UtxoScanner::new(DUMMY_VALID_URL.to_string()).unwrap();
        let result = scanner.connect_to_base_node();
        assert!(result.is_err());
        // We expect a network error (connection refused, timeout, etc.) or a specific ConnectionFailed
        match result.err().unwrap() {
            UtxoScannerError::Network(_) => { /* Expected due to reqwest failure */ }
            UtxoScannerError::ConnectionFailed(_) => { /* Also possible if the GET itself fails but server responds with error */ }
            e => panic!("Expected Network or ConnectionFailed error, got {:?}", e),
        }
    }

    #[test]
    fn test_scan_for_utxos_dummy_address() {
        let scanner = UtxoScanner::new(DUMMY_VALID_URL.to_string()).unwrap();
        let view_key = generate_dummy_private_key();
        let result = scanner.scan_for_utxos(&view_key);
        assert!(result.is_err());
        match result.err().unwrap() {
            UtxoScannerError::Network(_) => { /* Expected */ }
            UtxoScannerError::RequestFailed { .. } => { /* Expected if server responds with non-200 */ }
            e => panic!("Expected Network or RequestFailed error, got {:?}", e),
        }
    }

    #[test]
    fn test_scan_for_utxos_with_seed_dummy_address() {
        let scanner = UtxoScanner::new(DUMMY_VALID_URL.to_string()).unwrap();
        // A valid seed phrase (replace with an actual one if specific derivation is tested, otherwise any valid format)
        let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"; // Example 12-word phrase
        let result = scanner.scan_for_utxos_with_seed(seed_phrase, Network::MainNet);
        assert!(result.is_err());
        // This error should propagate from the inner scan_for_utxos call
        match result.err().unwrap() {
            UtxoScannerError::Network(_) => { /* Expected */ }
            UtxoScannerError::RequestFailed { .. } => { /* Expected */ }
            e => panic!("Expected Network or RequestFailed error from underlying scan, got {:?}", e),
        }
    }

    #[test]
    fn test_scan_for_utxos_with_seed_invalid_seed() {
        let scanner = UtxoScanner::new(DUMMY_VALID_URL.to_string()).unwrap();
        let invalid_seed_phrase = "this is not a valid seed phrase";
        let result = scanner.scan_for_utxos_with_seed(invalid_seed_phrase, Network::MainNet);
        assert!(result.is_err());
        match result.err().unwrap() {
            UtxoScannerError::SeedRestoration(_) => { /* Expected */ }
            e => panic!("Expected SeedRestoration error, got {:?}", e),
        }
    }
}

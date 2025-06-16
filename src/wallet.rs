use crate::address::TariAddress;
// use crate::cipher_seed::{CipherSeed}; // CipherSeed not directly used in TariWallet struct/new after refactor
use crate::error::{TariError, Result as TariResult}; // Renamed Result to TariResult to avoid conflict
use crate::keys::{KeyManager, PrivateKey, PublicKey};
use crate::network::Network;
// UtxoScanner is now imported directly in the refresh_utxos method or where needed
use crate::utxo::types::Utxo;
use crate::utxo::scanner::UtxoScannerError; // Still needed for TariWalletError
use crate::utxo::scanner::UtxoScanner; // Added for UtxoScanner::new
use std::collections::HashSet;


/// Custom error type for `TariWallet` operations, encompassing general Tari errors,
/// errors from the UTXO scanning process, and key-related errors.
#[derive(Debug)]
pub enum TariWalletError {
    /// A general error originating from the Tari library components.
    Tari(TariError),
    /// An error that occurred during UTXO scanning operations via `UtxoScanner`.
    Scanner(UtxoScannerError),
    /// An error related to cryptographic key operations (e.g., invalid key format).
    Key(crate::keys::KeyError),
}

impl From<TariError> for TariWalletError {
    fn from(err: TariError) -> Self {
        TariWalletError::Tari(err)
    }
}

impl From<UtxoScannerError> for TariWalletError {
    fn from(err: UtxoScannerError) -> Self {
        TariWalletError::Scanner(err)
    }
}

impl From<crate::keys::KeyError> for TariWalletError {
    fn from(err: crate::keys::KeyError) -> Self {
        TariWalletError::Key(err)
    }
}

/// A complete Tari wallet, encapsulating cryptographic keys, the wallet address,
/// seed phrase, network information, and UTXO management capabilities.
///
/// The wallet can connect to a Tari base node via gRPC to scan for and manage its UTXOs.
/// It stores the base node's address and uses an on-demand `UtxoScanner` for these operations.
#[derive(Clone)]
pub struct TariWallet {
    network: Network,
    view_private_key: PrivateKey,
    spend_private_key: PrivateKey,
    view_public_key: PublicKey,
    spend_public_key: PublicKey,
    address: TariAddress,
    seed_phrase: String,
    /// The network address (e.g., `127.0.0.1:18142`) of the Tari base node's gRPC interface.
    /// This address is used by `refresh_utxos` to connect and scan for UTXOs.
    base_node_address: String,
    /// A list of Unspent Transaction Outputs (UTXOs) currently known to be associated with this wallet.
    /// This list is populated by `refresh_utxos()` and represents the wallet's current view of its spendable funds.
    utxos: Vec<Utxo>,
    // Removed: utxo_scanner: UtxoScanner,
}

impl TariWallet {
    /// Creates a new `TariWallet` instance.
    ///
    /// # Arguments
    ///
    /// * `network`: The Tari `Network` this wallet operates on.
    /// * `view_private_key`: The wallet's private view key.
    /// * `spend_private_key`: The wallet's private spend key.
    /// * `seed_phrase`: The BIP-39 mnemonic seed phrase.
    /// * `base_node_address`: The network address (e.g., `http://127.0.0.1:18142`) of the Tari base node's gRPC interface.
    ///   This address is stored and used by `refresh_utxos` for UTXO scanning.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` if the wallet is successfully created.
    /// * `Err(TariWalletError)` if `UtxoScanner::new` (called internally by `refresh_utxos`) were to fail,
    ///   though `UtxoScanner::new` is currently simple and unlikely to error. The `Result` type is
    ///   kept for future flexibility.
    pub fn new(
        network: Network,
        view_private_key: PrivateKey,
        spend_private_key: PrivateKey,
        seed_phrase: String,
        base_node_address: String,
    ) -> Result<Self, TariWalletError> { // UtxoScanner::new can still return Err, so keep Result
        let view_public_key = view_private_key.public_key();
        let spend_public_key = spend_private_key.public_key();
        
        let address = TariAddress::new(
            network,
            view_public_key.clone(),
            spend_public_key.clone(),
            None,
        );

        // UtxoScanner is no longer stored in Self.
        // base_node_address is stored directly.
        let utxos = Vec::new();

        Ok(Self {
            network,
            view_private_key,
            spend_private_key,
            view_public_key,
            spend_public_key,
            address,
            seed_phrase,
            base_node_address, // Store the address
            utxos,
        })
    }

    /// Get the network
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get the view private key
    pub fn view_private_key(&self) -> &PrivateKey {
        &self.view_private_key
    }

    /// Get the spend private key  
    pub fn spend_private_key(&self) -> &PrivateKey {
        &self.spend_private_key
    }

    /// Get the view public key
    pub fn view_public_key(&self) -> &PublicKey {
        &self.view_public_key
    }

    /// Get the spend public key
    pub fn spend_public_key(&self) -> &PublicKey {
        &self.spend_public_key
    }

    /// Get the base address (without payment ID)
    pub fn address(&self) -> &TariAddress {
        &self.address
    }

    /// Get the address in Base58 format
    pub fn address_base58(&self) -> String {
        self.address.to_base58()
    }

    /// Get the address in emoji format
    pub fn address_emoji(&self) -> String {
        self.address.to_emoji()
    }

    /// Get the seed phrase
    pub fn seed_phrase(&self) -> &str {
        &self.seed_phrase
    }

    /// Create an integrated address with payment ID
    pub fn create_integrated_address(&self, payment_id: Vec<u8>) -> TariResult<TariAddress> {
        self.address.with_payment_id(payment_id)
    }

    /// Refreshes the wallet's UTXO list by scanning the configured base node.
    ///
    /// This method contacts the base node using the wallet's view key and fetches all
    /// associated UTXOs. It then compares this list with the UTXOs already known to the
    /// wallet (stored in `self.utxos`).
    ///
    /// The wallet's internal `self.utxos` list is updated to reflect the complete set of
    /// UTXOs returned by the base node from the latest scan.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Utxo>)` containing only the UTXOs that were newly found during this scan.
    /// * `Err(TariWalletError)` if an error occurs during the gRPC scanning process.
    ///   If an error occurs, `self.utxos` (the wallet's list of known UTXOs) remains unchanged.
    pub async fn refresh_utxos(&mut self) -> Result<Vec<Utxo>, TariWalletError> {
        println!("Refreshing UTXOs for wallet: {} using node at {}", self.address_base58(), self.base_node_address);

        // Create UtxoScanner instance on-the-fly for this scan operation.
        let scanner = UtxoScanner::new(self.base_node_address.clone());

        let known_utxos_set: HashSet<Utxo> = self.utxos.iter().cloned().collect();

        // Call the async scan_for_utxos method
        let all_scanned_utxos = scanner
            .scan_for_utxos(&self.view_private_key)
            .await
            .map_err(TariWalletError::Scanner)?; // Map UtxoScannerError to TariWalletError

        // Update the wallet's list of UTXOs to the full list retrieved
        self.utxos = all_scanned_utxos.clone();

        println!("Total UTXOs after scan: {}. Previously known: {}", self.utxos.len(), known_utxos_set.len());

        // Determine newly found UTXOs
        let mut newly_found_utxos = Vec::new();
        for scanned_utxo in &all_scanned_utxos {
            if !known_utxos_set.contains(scanned_utxo) {
                newly_found_utxos.push(scanned_utxo.clone());
            }
        }

        if !newly_found_utxos.is_empty() {
            println!("Newly found {} UTXOs.", newly_found_utxos.len());
        } else {
            println!("No new UTXOs found.");
        }

        Ok(newly_found_utxos)
    }

    /// Returns a reference to the wallet's current list of known UTXOs.
    ///
    /// This list reflects the state after the last successful call to `refresh_utxos()`.
    /// It may be empty if no UTXOs are known or if `refresh_utxos()` has not yet been called.
    pub fn get_utxos(&self) -> &Vec<Utxo> {
        &self.utxos
    }

    /// Get view private key as hex string
    pub fn view_private_key_hex(&self) -> String {
        hex::encode(self.view_private_key.as_bytes())
    }

    /// Get view public key as hex string
    pub fn view_public_key_hex(&self) -> String {
        self.view_public_key.to_hex()
    }

    /// Get spend public key as hex string
    pub fn spend_public_key_hex(&self) -> String {
        self.spend_public_key.to_hex()
    }

    /// Get spend private key as hex string
    pub fn spend_private_key_hex(&self) -> String {
        hex::encode(self.spend_private_key.as_bytes())
    }
}

impl std::fmt::Debug for TariWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TariWallet")
            .field("network", &self.network)
            .field("view_private_key", &self.view_private_key_hex())
            .field("spend_private_key", &self.spend_private_key_hex())
            .field("view_public_key", &self.view_public_key_hex())
            .field("spend_public_key", &self.spend_public_key_hex())
            .field("address", &self.address_base58())
            .field("address_emoji", &self.address_emoji())
            .field("seed_phrase", &self.seed_phrase)
            .field("utxos_count", &self.utxos.len())
            .finish()
    }
}

/// `TariAddressGenerator` is the main interface for creating new Tari wallets
/// or restoring existing ones from seed phrases or entropy.
///
/// It handles the generation of cryptographic keys and the construction of `TariWallet` instances.
pub struct TariAddressGenerator {
    passphrase: Option<String>,
}

impl TariAddressGenerator {
    /// Create a new generator with default (no) passphrase.
    pub fn new() -> Self {
        Self {
            passphrase: None,
        }
    }

    /// Create a new generator with a custom passphrase.
    /// The passphrase, if provided, is used during the conversion of `CipherSeed` to/from mnemonic.
    pub fn with_passphrase(passphrase: Option<String>) -> Self {
        Self { passphrase }
    }

    /// Generates a new `TariWallet`.
    ///
    /// # Arguments
    /// * `network`: The Tari `Network` for the new wallet.
    /// * `base_node_address`: The network address (e.g., `http://127.0.0.1:18142`) of the Tari base node's gRPC interface,
    ///   which will be stored in the `TariWallet` for UTXO scanning.
    ///
    /// # Returns
    /// A `Result` containing the new `TariWallet` or a `TariWalletError`.
    pub fn generate_new_wallet(&self, network: Network, base_node_address: String) -> Result<TariWallet, TariWalletError> {
        let cipher_seed = crate::cipher_seed::CipherSeed::new().map_err(TariError::from)?;
        let seed_phrase = cipher_seed.to_mnemonic(self.passphrase.clone()).map_err(TariError::from)?;
        let master_key = cipher_seed.master_key();
        let key_manager = KeyManager::new(master_key);
        let spend_private_key = key_manager.derive_key("comms", 0).map_err(TariError::from)?;
        let view_private_key = key_manager.derive_key("data encryption", 0).map_err(TariError::from)?;
        TariWallet::new(
            network,
            view_private_key,
            spend_private_key,
            seed_phrase,
            base_node_address,
        )
    }

    /// Restores a `TariWallet` from a BIP-39 seed phrase.
    ///
    /// # Arguments
    /// * `seed_phrase`: The mnemonic seed phrase.
    /// * `network`: The Tari `Network` for the wallet.
    /// * `base_node_address`: The network address of the Tari base node's gRPC interface for UTXO scanning.
    ///
    /// # Returns
    /// A `Result` containing the restored `TariWallet` or a `TariWalletError`.
    pub fn restore_from_seed_phrase(&self, seed_phrase: &str, network: Network, base_node_address: String) -> Result<TariWallet, TariWalletError> {
        let cipher_seed = crate::cipher_seed::CipherSeed::from_mnemonic(seed_phrase, self.passphrase.clone()).map_err(TariError::from)?;
        let master_key = cipher_seed.master_key();
        let key_manager = KeyManager::new(master_key);
        let spend_private_key = key_manager.derive_key("comms", 0).map_err(TariError::from)?;
        let view_private_key = key_manager.derive_key("data encryption", 0).map_err(TariError::from)?;
        TariWallet::new(
            network,
            view_private_key,
            spend_private_key,
            seed_phrase.to_string(),
            base_node_address,
        )
    }

    /// Restores a `TariWallet` directly from entropy (master key).
    ///
    /// # Arguments
    /// * `entropy`: A 16-byte slice representing the master key.
    /// * `network`: The Tari `Network` for the wallet.
    /// * `base_node_address`: The network address of the Tari base node's gRPC interface for UTXO scanning.
    ///
    /// # Returns
    /// A `Result` containing the restored `TariWallet` or a `TariWalletError`.
    /// Returns `TariWalletError::Tari(TariError::InvalidKeyLength)` if entropy is not 16 bytes.
    pub fn restore_from_entropy(&self, entropy: &[u8], network: Network, base_node_address: String) -> Result<TariWallet, TariWalletError> {
        if entropy.len() != 16 {
            return Err(TariWalletError::Tari(TariError::InvalidKeyLength {
                expected: 16,
                actual: entropy.len(),
            }));
        }
        let mut master_key = [0u8; 16];
        master_key.copy_from_slice(entropy);
        let key_manager = KeyManager::new(master_key);
        let spend_private_key = key_manager.derive_key("comms", 0).map_err(TariError::from)?;
        let view_private_key = key_manager.derive_key("data encryption", 0).map_err(TariError::from)?;
        let cipher_seed = crate::cipher_seed::CipherSeed::from_components(0x02, 0, master_key, [0u8; 5]);
        let seed_phrase = cipher_seed.to_mnemonic(self.passphrase.clone()).map_err(TariError::from)?;
        TariWallet::new(
            network,
            view_private_key,
            spend_private_key,
            seed_phrase,
            base_node_address,
        )
    }

    /// Generates multiple `TariWallet` instances at once.
    ///
    /// # Arguments
    /// * `network`: The Tari `Network` for all generated wallets.
    /// * `count`: The number of wallets to generate.
    /// * `base_node_address`: The network address of the Tari base node's gRPC interface, which will be
    ///   cloned and stored in each generated `TariWallet`.
    ///
    /// # Returns
    /// A `Result` containing a `Vec<TariWallet>` or a `TariWalletError`.
    pub fn generate_multiple_wallets(&self, network: Network, count: usize, base_node_address: String) -> Result<Vec<TariWallet>, TariWalletError> {
        let mut wallets = Vec::with_capacity(count);
        
        for _ in 0..count {
            wallets.push(self.generate_new_wallet(network, base_node_address.clone())?);
        }
        
        Ok(wallets)
    }

    /// Validate a seed phrase
    pub fn validate_seed_phrase(&self, seed_phrase: &str) -> bool {
        crate::cipher_seed::CipherSeed::from_mnemonic(seed_phrase, self.passphrase.clone()).is_ok()
    }

    /// Parse address from string (auto-detect format)
    pub fn parse_address(&self, address_str: &str) -> TariResult<TariAddress> {

        // Try emoji first (contains Unicode)
        if address_str.trim().chars().any(|c| !c.is_ascii()) {
            TariAddress::from_emoji(address_str)
        } else {
            // Try Base58 if that fails, try hex
            if let Ok(address) = TariAddress::from_base58(address_str) {
                Ok(address)
            } else {
                TariAddress::from_hex(address_str)
            }
        }
    }
}

impl Default for TariAddressGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const DUMMY_NODE_ADDRESS: &str = "http://127.0.0.1:18143"; // Dummy address for tests

    #[test]
    fn test_wallet_generation() {
        let generator = TariAddressGenerator::new();
        let wallet = generator.generate_new_wallet(Network::MainNet, DUMMY_NODE_ADDRESS.to_string()).unwrap();
        
        assert_eq!(wallet.network(), Network::MainNet);
        assert!(!wallet.seed_phrase().is_empty());
        assert!(!wallet.address_base58().is_empty());
        assert!(!wallet.address_emoji().is_empty());
        assert_eq!(wallet.get_utxos().len(), 0); // Should start with no UTXOs
    }

    #[test]
    fn test_wallet_restoration() {
        let generator = TariAddressGenerator::new();
        
        // Generate a wallet
        let original = generator.generate_new_wallet(Network::MainNet, DUMMY_NODE_ADDRESS.to_string()).unwrap();
        let seed_phrase = original.seed_phrase().to_string();
        
        // Restore from seed phrase
        let restored = generator
            .restore_from_seed_phrase(&seed_phrase, Network::MainNet, DUMMY_NODE_ADDRESS.to_string())
            .unwrap();
        
        // Should have same keys and address
        assert_eq!(original.view_private_key().as_bytes(), restored.view_private_key().as_bytes());
        assert_eq!(original.spend_private_key().as_bytes(), restored.spend_private_key().as_bytes());
        assert_eq!(original.address_base58(), restored.address_base58());
        assert_eq!(restored.get_utxos().len(), 0);
    }

    #[test]
    fn test_integrated_address() {
        let generator = TariAddressGenerator::new();
        let wallet = generator.generate_new_wallet(Network::MainNet, DUMMY_NODE_ADDRESS.to_string()).unwrap();
        
        let payment_id = b"test_payment_123".to_vec();
        let integrated_address = wallet.create_integrated_address(payment_id.clone()).unwrap();
        
        assert!(integrated_address.features().has_payment_id());
        assert_eq!(integrated_address.payment_id(), Some(payment_id.as_slice()));
    }

    #[test]
    fn test_multiple_wallets() {
        let generator = TariAddressGenerator::new();
        let wallets = generator.generate_multiple_wallets(Network::MainNet, 3, DUMMY_NODE_ADDRESS.to_string()).unwrap();
        
        assert_eq!(wallets.len(), 3);
        
        // All wallets should be unique
        for i in 0..wallets.len() {
            for j in (i + 1)..wallets.len() {
                assert_ne!(wallets[i].address_base58(), wallets[j].address_base58());
                assert_ne!(wallets[i].seed_phrase(), wallets[j].seed_phrase());
            }
            assert_eq!(wallets[i].get_utxos().len(), 0);
        }
    }

    #[test]
    fn test_seed_phrase_validation() {
        let generator = TariAddressGenerator::new();
        let wallet = generator.generate_new_wallet(Network::MainNet, DUMMY_NODE_ADDRESS.to_string()).unwrap();
        
        assert!(generator.validate_seed_phrase(wallet.seed_phrase()));
        assert!(!generator.validate_seed_phrase("invalid seed phrase"));
    }

    #[test]
    fn test_custom_passphrase() {
        let custom_passphrase = "my_custom_passphrase".to_string();
        let generator = TariAddressGenerator::with_passphrase(Some(custom_passphrase));
        
        let wallet = generator.generate_new_wallet(Network::MainNet, DUMMY_NODE_ADDRESS.to_string()).unwrap();
        assert!(!wallet.seed_phrase().is_empty());
    }

    #[test]
    fn test_entropy_restoration() {
        let generator = TariAddressGenerator::new();
        let entropy = [42u8; 16];
        
        let wallet1 = generator.restore_from_entropy(&entropy, Network::MainNet, DUMMY_NODE_ADDRESS.to_string()).unwrap();
        let wallet2 = generator.restore_from_entropy(&entropy, Network::MainNet, DUMMY_NODE_ADDRESS.to_string()).unwrap();
        
        // Same entropy should produce same wallet
        assert_eq!(wallet1.address_base58(), wallet2.address_base58());
        assert_eq!(wallet1.view_private_key().as_bytes(), wallet2.view_private_key().as_bytes());
    }

    #[test]
    fn test_wallet_roundtrip_all_fields() {
        let generator = TariAddressGenerator::new();
        
        // Generate a wallet
        let original = generator.generate_new_wallet(Network::MainNet, DUMMY_NODE_ADDRESS.to_string()).unwrap();
        
        // Extract all fields
        let original_network = original.network();
        let original_view_private_key = original.view_private_key().as_bytes().to_vec();
        let original_spend_private_key = original.spend_private_key().as_bytes().to_vec();
        let original_view_public_key = original.view_public_key().to_hex();
        let original_spend_public_key = original.spend_public_key().to_hex();
        let original_address_base58 = original.address_base58();
        let original_address_emoji = original.address_emoji();
        let original_seed_phrase = original.seed_phrase().to_string();
        
        // Restore from seed phrase
        let restored = generator
            .restore_from_seed_phrase(&original_seed_phrase, original_network, DUMMY_NODE_ADDRESS.to_string())
            .unwrap();
        
        // Verify all fields match
        assert_eq!(restored.network(), original_network);
        assert_eq!(restored.view_private_key().as_bytes(), original_view_private_key.as_slice());
        assert_eq!(restored.spend_private_key().as_bytes(), original_spend_private_key.as_slice());
        assert_eq!(restored.view_public_key().to_hex(), original_view_public_key);
        assert_eq!(restored.spend_public_key().to_hex(), original_spend_public_key);
        assert_eq!(restored.address_base58(), original_address_base58);
        assert_eq!(restored.address_emoji(), original_address_emoji);
        assert_eq!(restored.seed_phrase(), original_seed_phrase);
    }

    #[test]
    fn test_specific_seed_phrase_known_values() {
        let test_cases = vec![
            (
                "scare prepare endorse call sword gym combine wide volume wide crouch real spirit scale patch guilt another flag silly age inmate firm jump chimney",
                Network::MainNet,
                "1222568e27857aa29efa4f7e7c65cdd3a279e265e8acb43326c29208334dd40f", // expected_view_private_key
                "2870b3b5088b21622820bad5e8eeaee3414a895b72555b3a34774a9aad9a1978", // expected_view_public_key
                "2c83d350616dc2a859358bdebbfb91451e6b4f9d2637e8a013d339d0b1389516", // expected_spend_public_key
                "124Zz45Bio6Y6k6a5DQBRwMti5UZynHpyYtAG1nJNHGw7JMv2AP6wgwAoHuA1Uh3HSwoKwVHdhdzSUtuBjspDfRm18N", // expected base58 address
                "🐢📟🍞🦁💎💔🌕🐶🍑🏁🍞🍐💤🔥😷🚂💉😈🤖🎤🐴🎺🐑🎲🎺🍾🍳🐙🎤👖💈👖🍈🐚🍦🐭🔑🎬🏀🐊💵👽🎸🥄🐶🔮💦🚫🐽🎓🍍🐀🎪👙🍗🍶😷👞🍀🔑🍸🔋👂🍷👑🥑🎥", // expected emoji address

            )
        ];

        for (seed_phrase, network, expected_view_private_key, expected_view_public_key, expected_spend_public_key, expected_base58_address, expected_emoji_address) in test_cases {
            test_wallet_from_seed_phrase(
                seed_phrase,
                network,
                expected_view_private_key,
                expected_view_public_key,
                expected_spend_public_key,
                expected_base58_address,
                expected_emoji_address,
            );
        }
    }

    fn test_wallet_from_seed_phrase(
        seed_phrase: &str,
        network: Network,
        expected_view_private_key: &str,
        expected_view_public_key: &str,
        expected_spend_public_key: &str,
        expected_base58_address: &str,
        expected_emoji_address: &str,
    ) {
        let generator = TariAddressGenerator::new();

        // First, let's check if this is a valid BIP39 mnemonic
        // println!("Testing seed phrase: {}", seed_phrase); // Original had a println, can be removed later

        // Restore wallet from the specific seed phrase
        let wallet = generator
            .restore_from_seed_phrase(seed_phrase, network, DUMMY_NODE_ADDRESS.to_string())
            .unwrap(); // Original test used unwrap

        // Verify expected values
        assert_eq!(wallet.network(), network);
        assert_eq!(wallet.seed_phrase(), seed_phrase);

        // Check private view key
        // println!("Expected view private key: {}", expected_view_private_key);
        // println!("Actual view private key:   {}", wallet.view_private_key_hex());
        assert_eq!(wallet.view_private_key_hex(), expected_view_private_key);

        // Check public view key
        // println!("Expected view public key: {}", expected_view_public_key);
        // println!("Actual view public key:   {}", wallet.view_public_key_hex());
        assert_eq!(wallet.view_public_key_hex(), expected_view_public_key);

        // Check spend key
        // println!("Expected spend public key: {}", expected_spend_public_key);
        // println!("Actual spend public key:   {}", wallet.spend_public_key_hex());
        assert_eq!(wallet.spend_public_key_hex(), expected_spend_public_key);

        // Check base58 address
        assert_eq!(wallet.address_base58(), expected_base58_address);

        // Check emoji address
        assert_eq!(wallet.address_emoji(), expected_emoji_address);
    }

    #[test]
    #[tokio::test] // Mark test as async
    async fn test_refresh_utxos_logic() { // Make test function async
        let generator = TariAddressGenerator::new();
        let mut wallet = generator.generate_new_wallet(Network::MainNet, DUMMY_NODE_ADDRESS.to_string()).unwrap();

        // Manually add some initial UTXOs to simulate a previous state
        let initial_utxo1 = Utxo {
            output_hash: "hash1".to_string(),
            value: 100,
            block_height: 1,
            script_pubkey: "script1".to_string(),
            output_type: crate::utxo::types::OutputType::Standard,
        };
        let initial_utxo2 = Utxo {
            output_hash: "hash2".to_string(),
            value: 200,
            block_height: 2,
            script_pubkey: "script2".to_string(),
            output_type: crate::utxo::types::OutputType::Coinbase,
        };
        wallet.utxos.push(initial_utxo1.clone());
        wallet.utxos.push(initial_utxo2.clone());
        assert_eq!(wallet.get_utxos().len(), 2);

        // --- This is where mocking would be essential ---
        // In a real test, we would mock UtxoScanner::scan_for_utxos
        // to return a predefined set of UTXOs, e.g., initial_utxo1 and a new_utxo3.
        // For now, we know this call will likely fail or return empty due to DUMMY_NODE_ADDRESS.
        // The test demonstrates the logic assuming the scanner could be controlled.
        // Since the dummy UtxoScanner::scan_for_utxos now returns Ok(Vec::new()),
        // we expect refresh_utxos to succeed, find 0 new UTXOs, and clear existing ones.

        match wallet.refresh_utxos().await { // Await the async call
            Ok(newly_found) => {
                // The dummy scanner returns Ok(Vec::new()), so:
                // 1. `all_scanned_utxos` will be empty.
                // 2. `self.utxos` will be updated to this empty list.
                // 3. `newly_found` will be empty.
                assert_eq!(wallet.get_utxos().len(), 0, "After scan with empty result, wallet should have 0 UTXOs");
                assert!(newly_found.is_empty(), "No new UTXOs should be found if scanner returns empty");
                println!("Refresh UTXOs completed. Newly found: 0. Wallet UTXOs: 0.");
            }
            // Remove specific error checks for Network/ConnectionFailed as ClientNotReady is more general now
            // for the placeholder gRPC client. If the dummy client actually tried to connect and failed,
            // it would be GrpcConnection.
            Err(TariWalletError::Scanner(UtxoScannerError::GrpcConnection(s))) => {
                 // This might happen if the dummy connect in rpc.rs fails for some reason
                println!("Refresh UTXOs failed due to GrpcConnection (dummy client): {}", s);
                assert_eq!(wallet.get_utxos().len(), 2); // State should be unchanged on error
            }
            Err(e) => {
                // Other errors from scanner (like GrpcRequest, GrpcStream, MappingError)
                // are less likely with the current dummy scanner but possible if it were more complex.
                panic!("refresh_utxos failed with unexpected error: {:?}", e);
            }
        }
    }
}
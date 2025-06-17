use crate::address::TariAddress;
use crate::error::{TariError, Result as TariResult};
use crate::keys::{KeyManager, PrivateKey, PublicKey};
use crate::network::Network;
use crate::utxo::scanner::UtxoScannerError;
use thiserror::Error; // Added thiserror

/// Custom error type for `TariWallet` operations, encompassing general Tari errors,
/// errors from the UTXO scanning process, and key-related errors.
#[derive(Debug, Error)] // Added thiserror::Error
pub enum TariWalletError {
    #[error("Tari general error: {0}")]
    Tari(#[from] TariError), // TariError from src/error.rs already uses thiserror

    #[error("UTXO scanner error: {0}")]
    Scanner(#[from] UtxoScannerError), // Now UtxoScannerError will also use thiserror

    #[error("Cryptographic key error: {0}")]
    Key(#[from] crate::keys::KeyError), // KeyError from src/keys.rs already uses thiserror
}

// Manual From implementations are now removed as #[from] handles them.

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
    ) -> Result<Self, TariWalletError> {
        let view_public_key = view_private_key.public_key();
        let spend_public_key = spend_private_key.public_key();
        
        let address = TariAddress::new(
            network,
            view_public_key.clone(),
            spend_public_key.clone(),
            None,
        );

        Ok(Self {
            network,
            view_private_key,
            spend_private_key,
            view_public_key,
            spend_public_key,
            address,
            seed_phrase,
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
    ///
    /// # Returns
    /// A `Result` containing the new `TariWallet` or a `TariWalletError`.
    pub fn generate_new_wallet(&self, network: Network) -> Result<TariWallet, TariWalletError> {
        let cipher_seed = crate::cipher_seed::CipherSeed::new()?; // Updated to use ? directly
        let seed_phrase = cipher_seed.to_mnemonic(self.passphrase.clone())?;
        let master_key = cipher_seed.master_key();
        let key_manager = KeyManager::new(master_key);
        let spend_private_key = key_manager.derive_key("comms", 0)?;
        let view_private_key = key_manager.derive_key("data encryption", 0)?;
        TariWallet::new(
            network,
            view_private_key,
            spend_private_key,
            seed_phrase,
        )
    }

    /// Restores a `TariWallet` from a BIP-39 seed phrase.
    ///
    /// # Arguments
    /// * `seed_phrase`: The mnemonic seed phrase.
    /// * `network`: The Tari `Network` for the wallet.
    ///
    /// # Returns
    /// A `Result` containing the restored `TariWallet` or a `TariWalletError`.
    pub fn restore_from_seed_phrase(&self, seed_phrase: &str, network: Network) -> Result<TariWallet, TariWalletError> {
        let cipher_seed = crate::cipher_seed::CipherSeed::from_mnemonic(seed_phrase, self.passphrase.clone())?;
        let master_key = cipher_seed.master_key();
        let key_manager = KeyManager::new(master_key);
        let spend_private_key = key_manager.derive_key("comms", 0)?;
        let view_private_key = key_manager.derive_key("data encryption", 0)?;
        TariWallet::new(
            network,
            view_private_key,
            spend_private_key,
            seed_phrase.to_string(),
        )
    }

    /// Restores a `TariWallet` directly from entropy (master key).
    ///
    /// # Arguments
    /// * `entropy`: A 16-byte slice representing the master key.
    /// * `network`: The Tari `Network` for the wallet.
    ///
    /// # Returns
    /// A `Result` containing the restored `TariWallet` or a `TariWalletError`.
    /// Returns `TariWalletError::Tari(TariError::InvalidKeyLength)` if entropy is not 16 bytes.
    pub fn restore_from_entropy(&self, entropy: &[u8], network: Network) -> Result<TariWallet, TariWalletError> {
        if entropy.len() != 16 {
            // This explicit error mapping will be handled by #[from] if TariError::InvalidKeyLength becomes part of TariWalletError::Tari
            // However, since TariError itself is an enum, the #[from] applies to TariError as a whole.
            // This specific variant mapping might still be preferred if we want to retain this exact error structure.
            // For now, converting to TariError first, then letting #[from] handle TariError into TariWalletError.
            return Err(TariError::InvalidKeyLength {
                expected: 16,
                actual: entropy.len(),
            }.into()); // .into() converts TariError to TariWalletError via #[from]
        }
        let mut master_key = [0u8; 16];
        master_key.copy_from_slice(entropy);
        let key_manager = KeyManager::new(master_key);
        let spend_private_key = key_manager.derive_key("comms", 0)?;
        let view_private_key = key_manager.derive_key("data encryption", 0)?;
        let cipher_seed = crate::cipher_seed::CipherSeed::from_components(0x02, 0, master_key, [0u8; 5]);
        let seed_phrase = cipher_seed.to_mnemonic(self.passphrase.clone())?;
        TariWallet::new(
            network,
            view_private_key,
            spend_private_key,
            seed_phrase,
        )
    }

    /// Generates multiple `TariWallet` instances at once.
    ///
    /// # Arguments
    /// * `network`: The Tari `Network` for all generated wallets.
    /// * `count`: The number of wallets to generate.
    ///
    /// # Returns
    /// A `Result` containing a `Vec<TariWallet>` or a `TariWalletError`.
    pub fn generate_multiple_wallets(&self, network: Network, count: usize) -> Result<Vec<TariWallet>, TariWalletError> {
        let mut wallets = Vec::with_capacity(count);
        
        for _ in 0..count {
            wallets.push(self.generate_new_wallet(network)?);
        }
        
        Ok(wallets)
    }

    /// Validate a seed phrase
    pub fn validate_seed_phrase(&self, seed_phrase: &str) -> bool {
        crate::cipher_seed::CipherSeed::from_mnemonic(seed_phrase, self.passphrase.clone()).is_ok()
    }

    /// Parse address from string (auto-detect format)
    pub fn parse_address(&self, address_str: &str) -> TariResult<TariAddress> { // Returns TariResult

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
    // const DUMMY_NODE_ADDRESS: &str = "http://127.0.0.1:18143"; // Dummy address for tests, warning if unused

    #[test]
    fn test_wallet_generation() {
        let generator = TariAddressGenerator::new();
        let wallet = generator.generate_new_wallet(Network::MainNet).unwrap();
        
        assert_eq!(wallet.network(), Network::MainNet);
        assert!(!wallet.seed_phrase().is_empty());
        assert!(!wallet.address_base58().is_empty());
        assert!(!wallet.address_emoji().is_empty());
    }

    #[test]
    fn test_wallet_restoration() {
        let generator = TariAddressGenerator::new();
        
        // Generate a wallet
        let original = generator.generate_new_wallet(Network::MainNet).unwrap();
        let seed_phrase = original.seed_phrase().to_string();
        
        // Restore from seed phrase
        let restored = generator
            .restore_from_seed_phrase(&seed_phrase, Network::MainNet)
            .unwrap();
        
        // Should have same keys and address
        assert_eq!(original.view_private_key().as_bytes(), restored.view_private_key().as_bytes());
        assert_eq!(original.spend_private_key().as_bytes(), restored.spend_private_key().as_bytes());
        assert_eq!(original.address_base58(), restored.address_base58());
    }

    #[test]
    fn test_integrated_address() {
        let generator = TariAddressGenerator::new();
        let wallet = generator.generate_new_wallet(Network::MainNet).unwrap();
        
        let payment_id = b"test_payment_123".to_vec();
        let integrated_address = wallet.create_integrated_address(payment_id.clone()).unwrap();
        
        assert!(integrated_address.features().has_payment_id());
        assert_eq!(integrated_address.payment_id(), Some(payment_id.as_slice()));
    }

    #[test]
    fn test_multiple_wallets() {
        let generator = TariAddressGenerator::new();
        let wallets = generator.generate_multiple_wallets(Network::MainNet, 3).unwrap();
        
        assert_eq!(wallets.len(), 3);
        
        // All wallets should be unique
        for i in 0..wallets.len() {
            for j in (i + 1)..wallets.len() {
                assert_ne!(wallets[i].address_base58(), wallets[j].address_base58());
                assert_ne!(wallets[i].seed_phrase(), wallets[j].seed_phrase());
            }
        }
    }

    #[test]
    fn test_seed_phrase_validation() {
        let generator = TariAddressGenerator::new();
        let wallet = generator.generate_new_wallet(Network::MainNet).unwrap();
        
        assert!(generator.validate_seed_phrase(wallet.seed_phrase()));
        assert!(!generator.validate_seed_phrase("invalid seed phrase"));
    }

    #[test]
    fn test_custom_passphrase() {
        let custom_passphrase = "my_custom_passphrase".to_string();
        let generator = TariAddressGenerator::with_passphrase(Some(custom_passphrase));
        
        let wallet = generator.generate_new_wallet(Network::MainNet).unwrap();
        assert!(!wallet.seed_phrase().is_empty());
    }

    #[test]
    fn test_entropy_restoration() {
        let generator = TariAddressGenerator::new();
        let entropy = [42u8; 16];
        
        let wallet1 = generator.restore_from_entropy(&entropy, Network::MainNet).unwrap();
        let wallet2 = generator.restore_from_entropy(&entropy, Network::MainNet).unwrap();
        
        // Same entropy should produce same wallet
        assert_eq!(wallet1.address_base58(), wallet2.address_base58());
        assert_eq!(wallet1.view_private_key().as_bytes(), wallet2.view_private_key().as_bytes());
    }

    #[test]
    fn test_wallet_roundtrip_all_fields() {
        let generator = TariAddressGenerator::new();
        
        // Generate a wallet
        let original = generator.generate_new_wallet(Network::MainNet).unwrap();
        
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
            .restore_from_seed_phrase(&original_seed_phrase, original_network)
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
}
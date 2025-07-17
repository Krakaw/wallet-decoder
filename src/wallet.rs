use crate::address::TariAddress;
use crate::cipher_seed::{CipherSeed};
use crate::error::{TariError, Result};
use crate::keys::{KeyManager, PrivateKey, PublicKey};
use crate::network::Network;


/// A complete Tari wallet containing keys and address information
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
    /// Create a new wallet from keys and seed phrase
    pub fn new(
        network: Network,
        view_private_key: PrivateKey,
        spend_private_key: PrivateKey,
        seed_phrase: String,
    ) -> Self {
        let view_public_key = view_private_key.public_key();
        let spend_public_key = spend_private_key.public_key();
        
        let address = TariAddress::new(
            network,
            Some(view_public_key.clone()),
            spend_public_key.clone(),
            None,
        );

        Self {
            network,
            view_private_key,
            spend_private_key,
            view_public_key,
            spend_public_key,
            address,
            seed_phrase,
        }
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
    pub fn create_integrated_address(&self, payment_id: Vec<u8>) -> Result<TariAddress> {
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

/// Tari address generator - main interface for creating and restoring wallets
pub struct TariAddressGenerator {
    passphrase: Option<String>,
}

impl TariAddressGenerator {
    /// Create a new generator with default passphrase
    pub fn new() -> Self {
        Self {
            passphrase: None,
        }
    }

    /// Create a new generator with custom passphrase
    pub fn with_passphrase(passphrase: Option<String>) -> Self {
        Self { passphrase }
    }

    /// Generate a new wallet
    pub fn generate_new_wallet(&self, network: Network) -> Result<TariWallet> {
        // Generate new cipher seed
        let cipher_seed = CipherSeed::new()?;
        // Convert to mnemonic
        let seed_phrase = cipher_seed.to_mnemonic(self.passphrase.clone())?;
        // Create key manager with entropy as master key
        let master_key = cipher_seed.master_key();
        let key_manager = KeyManager::new(master_key);
        // Derive keys
        let spend_private_key = key_manager.derive_key("comms", 0)?;
        let view_private_key = key_manager.derive_key("data encryption", 0)?;
        Ok(TariWallet::new(
            network,
            view_private_key,
            spend_private_key,
            seed_phrase,
        ))
    }

    /// Restore wallet from seed phrase
    pub fn restore_from_seed_phrase(&self, seed_phrase: &str, network: Network) -> Result<TariWallet> {
        // Convert back to cipher seed
        let cipher_seed = CipherSeed::from_mnemonic(seed_phrase, self.passphrase.clone())?;
        // Create key manager with entropy as master key
        let master_key = cipher_seed.master_key();
        let key_manager = KeyManager::new(master_key);
        // Derive keys (same as generation)
        let spend_private_key = key_manager.derive_key("comms", 0)?;
        let view_private_key = key_manager.derive_key("data encryption", 0)?;
        Ok(TariWallet::new(
            network,
            view_private_key,
            spend_private_key,
            seed_phrase.to_string(),
        ))
    }

    /// Restore wallet from entropy directly
    pub fn restore_from_entropy(&self, entropy: &[u8], network: Network) -> Result<TariWallet> {
        if entropy.len() != 16 {
            return Err(TariError::InvalidKeyLength {
                expected: 16,
                actual: entropy.len(),
            });
        }
        let mut master_key = [0u8; 16];
        master_key.copy_from_slice(entropy);
        let key_manager = KeyManager::new(master_key);
        // Derive keys
        let spend_private_key = key_manager.derive_key("comms", 0)?;
        let view_private_key = key_manager.derive_key("data encryption", 0)?;
        // Create a cipher seed for mnemonic generation
        let cipher_seed = CipherSeed::from_components(0x02, 0, master_key, [0u8; 5]);
        let seed_phrase = cipher_seed.to_mnemonic(self.passphrase.clone())?;
        Ok(TariWallet::new(
            network,
            view_private_key,
            spend_private_key,
            seed_phrase,
        ))
    }

    /// Generate multiple wallets at once
    pub fn generate_multiple_wallets(&self, network: Network, count: usize) -> Result<Vec<TariWallet>> {
        let mut wallets = Vec::with_capacity(count);
        
        for _ in 0..count {
            wallets.push(self.generate_new_wallet(network)?);
        }
        
        Ok(wallets)
    }

    /// Validate a seed phrase
    pub fn validate_seed_phrase(&self, seed_phrase: &str) -> bool {
        CipherSeed::from_mnemonic(seed_phrase, self.passphrase.clone()).is_ok()
    }

    /// Parse address from string (auto-detect format) with detailed error reporting
    pub fn parse_address(&self, address_str: &str) -> Result<TariAddress> {
        TariAddress::parse_with_detailed_errors(address_str)
    }

    /// Parse address with comprehensive component breakdown showing each part and hex data
    pub fn parse_address_with_breakdown(&self, address_str: &str) -> Result<TariAddress> {
        TariAddress::parse_with_component_breakdown(address_str)
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
            .restore_from_seed_phrase(seed_phrase, network)
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
}
use std::str::FromStr;

use serde::Serialize;
use tari_common::configuration::Network;
use tari_common_types::tari_address::TariAddress;
use tari_core::transactions::transaction_key_manager::key_manager::{
    DerivedPublicKey, TariKeyManager,
};
use tari_key_manager::{
    SeedWords,
    cipher_seed::CipherSeed,
    key_manager_service::{KeyDigest, KeyManagerBranch},
    mnemonic::{Mnemonic, MnemonicLanguage},
};
use tari_utilities::SafePassword;

#[derive(Serialize)]
pub struct WalletInfo {
    pub seed_words: String,
    pub view_key: String,
    pub spend_key: String,
    pub address: TariAddress,
    pub network: String,
    pub emoji: String,
}

fn generate_public_key_pair(seed: CipherSeed) -> (DerivedPublicKey, DerivedPublicKey) {
    // Create key managers for view and spend keys
    let view_key_manager = TariKeyManager::<KeyDigest>::from(
        seed.clone(),
        "data encryption".to_string(), // Extracted this from "tari/base_layer/common_types/src/lib.rs" @TODO Fix the base_layer/key_manager/src/key_manager_service/interface.rs in the tari repo.
        0,
    );
    let spend_key_manager =
        TariKeyManager::<KeyDigest>::from(seed, KeyManagerBranch::Comms.get_branch_key(), 0);

    // Derive the view and spend keys
    let view_key = view_key_manager
        .derive_public_key(0)
        .expect("Failed to derive view key");
    let spend_key = spend_key_manager
        .derive_public_key(0)
        .expect("Failed to derive spend key");

    (view_key, spend_key)
}

pub fn generate_wallet(
    password: Option<SafePassword>,
    network: String,
) -> Result<WalletInfo, anyhow::Error> {
    // Create a new cipher seed
    let seed = CipherSeed::new();

    // Get seed words in English
    let seed_words = seed
        .to_mnemonic(MnemonicLanguage::English, password.clone())
        .expect("Failed to generate seed words")
        .join(" ");
    let seed_words = seed_words.reveal().clone();

    let (view_key, spend_key) = generate_public_key_pair(seed);

    let network_type = Network::from_str(&network).unwrap_or(Network::MainNet);

    // Create the Tari address

    let tari_address = TariAddress::new_dual_address_with_default_features(
        view_key.key.clone(),
        spend_key.key.clone(),
        network_type,
    )
    .expect("Failed to create Tari address");

    Ok(WalletInfo {
        seed_words,
        view_key: view_key.key.to_string(),
        spend_key: spend_key.key.to_string(),
        address: tari_address.clone(),
        network,
        emoji: tari_address.to_emoji_string(),
    })
}

pub fn load_wallet_from_seed_phrase(
    seed_phrase: &str,
    network: String,
    password: Option<SafePassword>,
) -> Result<WalletInfo, anyhow::Error> {
    // Parse the seed phrase into words
    let seed_words = SeedWords::from_str(seed_phrase)
        .map_err(|e| anyhow::anyhow!("Invalid seed phrase: {}", e))?;

    // Create a mnemonic from the words
    let seed = CipherSeed::from_mnemonic(&seed_words, password)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher seed: {}", e))?;

    let (view_key, spend_key) = generate_public_key_pair(seed);

    let network_type = Network::from_str(&network).unwrap_or(Network::MainNet);

    let address = TariAddress::new_dual_address_with_default_features(
        view_key.key.clone(),
        spend_key.key.clone(),
        network_type,
    )?;

    Ok(WalletInfo {
        seed_words: seed_phrase.to_string(),
        view_key: view_key.key.to_string(),
        spend_key: spend_key.key.to_string(),
        address: address.clone(),
        network,
        emoji: address.to_emoji_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_wallet_mainnet() {
        let result = generate_wallet(None, "mainnet".to_string()).unwrap();
        assert!(!result.seed_words.is_empty());
        assert!(!result.view_key.is_empty());
        assert!(!result.spend_key.is_empty());
        assert_eq!(result.network, "mainnet");
        assert!(!result.emoji.is_empty());
        assert_eq!(result.address.network(), Network::MainNet);
    }

    #[test]
    fn test_generate_wallet_with_password() {
        let password = SafePassword::from("test_password");
        let result = generate_wallet(Some(password), "mainnet".to_string()).unwrap();
        assert!(!result.seed_words.is_empty());
        assert!(!result.view_key.is_empty());
        assert!(!result.spend_key.is_empty());
    }

    #[test]
    fn test_generate_wallet_different_networks() {
        let networks = vec!["mainnet", "nextnet", "esmeralda"];
        for network in networks {
            let result = generate_wallet(None, network.to_string()).unwrap();
            assert_eq!(result.network, network);
            match network {
                "mainnet" => assert_eq!(result.address.network(), Network::MainNet),
                "nextnet" => assert_eq!(result.address.network(), Network::NextNet),
                "esmeralda" => assert_eq!(result.address.network(), Network::Esmeralda),
                _ => panic!("Unexpected network"),
            }
        }
    }

    #[test]
    fn test_load_wallet_from_seed_phrase() {
        // First generate a wallet to get a valid seed phrase
        let generated = generate_wallet(None, "mainnet".to_string()).unwrap();

        // Now try to load it
        let loaded =
            load_wallet_from_seed_phrase(&generated.seed_words, "mainnet".to_string(), None)
                .unwrap();

        // Verify the loaded wallet matches the generated one
        assert_eq!(loaded.seed_words, generated.seed_words);
        assert_eq!(loaded.view_key, generated.view_key);
        assert_eq!(loaded.spend_key, generated.spend_key);
        assert_eq!(loaded.network, generated.network);
        assert_eq!(loaded.emoji, generated.emoji);
    }

    #[test]
    fn test_load_wallet_with_password() {
        // Generate a wallet with password
        let password = SafePassword::from("test_password");
        let generated = generate_wallet(Some(password.clone()), "mainnet".to_string()).unwrap();

        // Load it with the same password
        let loaded = load_wallet_from_seed_phrase(
            &generated.seed_words,
            "mainnet".to_string(),
            Some(password),
        )
        .unwrap();

        // Verify the loaded wallet matches the generated one
        assert_eq!(loaded.seed_words, generated.seed_words);
        assert_eq!(loaded.view_key, generated.view_key);
        assert_eq!(loaded.spend_key, generated.spend_key);
    }

    #[test]
    fn test_load_wallet_invalid_seed_phrase() {
        let result =
            load_wallet_from_seed_phrase("invalid seed phrase", "mainnet".to_string(), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_wallet_wrong_password() {
        // Generate a wallet with password
        let password = SafePassword::from("correct_password");
        let generated = generate_wallet(Some(password), "mainnet".to_string()).unwrap();

        // Try to load it with wrong password
        let wrong_password = SafePassword::from("wrong_password");
        let result = load_wallet_from_seed_phrase(
            &generated.seed_words,
            "mainnet".to_string(),
            Some(wrong_password),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_load_wallet_different_networks() {
        // Generate a wallet
        let generated = generate_wallet(None, "mainnet".to_string()).unwrap();

        // Try loading it with different networks
        let networks = vec!["mainnet", "nextnet", "esmeralda"];
        for network in networks {
            let loaded =
                load_wallet_from_seed_phrase(&generated.seed_words, network.to_string(), None)
                    .unwrap();
            assert_eq!(loaded.network, network);
            match network {
                "mainnet" => assert_eq!(loaded.address.network(), Network::MainNet),
                "nextnet" => assert_eq!(loaded.address.network(), Network::NextNet),
                "esmeralda" => assert_eq!(loaded.address.network(), Network::Esmeralda),
                _ => panic!("Unexpected network"),
            }
        }
    }

    #[test]
    fn test_wallet_with_known_values() {
        let seed_phrase = "gate egg ticket brisk steel chef more mean blouse busy always slow oppose leaf possible lottery cruel penalty sheriff acid media extend train enable";
        let expected_view_key = "375ce00ddadcfde47128858730a12a2e7ef33a4ce5ceafd3dd689324b1c7a10c";
        let expected_spend_key = "2ab1c61a811588a3fa346a6deda0df936e5a17db0ab8b0d96638e81552c3877d";
        let expected_interactive_address = "347ZTThqvfgmwidceBgNbLcP6AAjQPWxtjAExfBFrLcWRf8KSWtP8BGWEZ8UQWtpSQQNBijpfJMXEByTRTV38f7JMND";
        let expected_interactive_emoji = "🌈🌊🎤🎲🎡🍐🔭🌸😷💼🐯🔱💐👃🐍🌹🍋💰🍣🐾🐵🐾💤🍗💎👙⭐🌹🎪💎🐴🏥🎮🌸🥝👂📈🍉🐪🍄🦂🥊🚪🍳🏰🐊🚁👞🔱👀🐌🎹🍆🔫🎋💡💋🔩🏠🍷😷🍄🎮💺🦆🦋🍗";

        // Test loading the wallet from seed phrase
        let loaded =
            load_wallet_from_seed_phrase(seed_phrase, "nextnet".to_string(), None).unwrap();

        // Verify the loaded wallet matches the expected values
        assert_eq!(loaded.seed_words, seed_phrase);
        assert_eq!(loaded.view_key, expected_view_key);
        assert_eq!(loaded.spend_key, expected_spend_key);
        assert_eq!(loaded.address.to_base58(), expected_interactive_address);
        assert_eq!(loaded.emoji, expected_interactive_emoji);
    }
}

use tari_key_manager::{
    cipher_seed::CipherSeed,
    mnemonic::{Mnemonic, MnemonicLanguage},
    key_manager_service::{KeyManagerBranch, KeyDigest},
};
use tari_utilities::SafePassword;
use tari_core::transactions::transaction_key_manager::key_manager::TariKeyManager;
use tari_common_types::tari_address::TariAddress;
use tari_common::configuration::Network;
use serde::Serialize;

#[derive(Serialize)]
pub struct WalletInfo {
    pub seed_words: String,
    pub view_key: String,
    pub spend_key: String,
    pub address: TariAddress,
    pub network: String,
    pub emoji: String,
}

pub fn generate_wallet(password: Option<SafePassword>, network: String) -> Result<WalletInfo, anyhow::Error> {
    // Create a new cipher seed
    let seed = CipherSeed::new();
    
    // Get seed words in English
    let seed_words = seed
        .to_mnemonic(MnemonicLanguage::English, password.clone())
        .expect("Failed to generate seed words").join(" ");
    let seed_words = seed_words.reveal().clone();

    // Create key managers for view and spend keys
    let view_key_manager = TariKeyManager::<KeyDigest>::from(
        seed.clone(),
        KeyManagerBranch::Comms.get_branch_key(),
        0
    );
    let spend_key_manager = TariKeyManager::<KeyDigest>::from(
        seed,
        KeyManagerBranch::Comms.get_branch_key(),
        0
    );

    // Derive the view and spend keys
    let view_key = view_key_manager.derive_public_key(0).expect("Failed to derive view key");
    let spend_key = spend_key_manager.derive_public_key(1).expect("Failed to derive spend key");

    // Create the Tari address
    let network_type = match network.to_lowercase().as_str() {
        "mainnet" => Network::MainNet,
        "nextnet" => Network::NextNet,
        "esmeralda" => Network::Esmeralda,
        _ => Network::MainNet,
    };

    let tari_address = TariAddress::new_dual_address_with_default_features(
        view_key.key.clone(),
        spend_key.key.clone(),
        network_type,
    ).expect("Failed to create Tari address");

    Ok(WalletInfo {
        seed_words,
        view_key: view_key.key.to_string(),
        spend_key: spend_key.key.to_string(),
        address: tari_address.clone(),
        network,
        emoji: tari_address.to_emoji_string(),
    })
} 
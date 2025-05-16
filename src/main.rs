use std::env;
use std::str::FromStr;
use tari_common_types::tari_address::{TariAddress, TariAddressFeatures};
use tari_key_manager::cipher_seed::CipherSeed;
use tari_utilities::hex::Hex;
use tari_key_manager::{SeedWords, mnemonic::Mnemonic};
use tari_key_manager::key_manager::KeyManager;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: decode-address <tari_address>");
        return;
    }

    let address_str = &args[1].trim();

    let seed_words = SeedWords::from_str(address_str).unwrap();
    let cipher_seed = CipherSeed::from_mnemonic(&seed_words, None).unwrap();
    let master_key = cipher_seed.derive_master_key()?;
    let address = TariAddress::from_public_key(&master_key.public_key())?;

    println!("Seed words: {:?}", address);
    

    match TariAddress::from_str(address_str) {
        Ok(address) => {
            println!("=== Tari Address Details ===");
            println!("Base58: {}", address.to_base58());
            println!("Emoji: {}", address.to_emoji_string());
            println!("Hex: {}", address.to_hex());
            println!("\n=== Binary Representation ===");
            let bytes = address.to_vec();
            println!("Raw bytes: {:02x?}", bytes);
            println!("Length: {} bytes", bytes.len());

            println!("\n=== Network Information ===");
            println!("Network: {:?}", address.network());
            println!("Network byte: 0x{:02x}", address.network().as_byte());

            println!("\n=== Features ===");
            let features = address.features();
            println!("Features byte: 0x{:02x}", features.as_u8());
            println!(
                "One-sided: {}",
                features.contains(TariAddressFeatures::ONE_SIDED)
            );
            println!(
                "Interactive: {}",
                features.contains(TariAddressFeatures::INTERACTIVE)
            );
            println!(
                "Payment ID: {}",
                features.contains(TariAddressFeatures::PAYMENT_ID)
            );

            println!("\n=== Key Information ===");
            println!("Public Spend Key: {}", address.public_spend_key().to_hex());
            if let Some(view_key) = address.public_view_key() {
                println!("Public View Key: {}", view_key.to_hex());
            }

            println!("\n=== Address Type ===");
            match address {
                TariAddress::Single(_) => println!("Type: Single Address"),
                TariAddress::Dual(_) => println!("Type: Dual Address"),
            }

            let payment_id = address.get_payment_id_user_data_bytes();
            if !payment_id.is_empty() {
                println!("\n=== Payment ID Data ===");
                println!("Payment ID: {}", payment_id.to_hex());
            }
        }
        Err(e) => println!("Error decoding address: {:#?}", e),
    }
}

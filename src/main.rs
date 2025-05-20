mod cli;
mod wallet;
mod address;

use clap::Parser;
use cli::{Args, Command};

fn main() {
    let args = Args::parse();

    match args.command {
        Command::GenerateWallet { password, network } => {
            match wallet::generate_wallet(password, network.clone()) {
                Ok(wallet_info) => {
                    println!("Wallet created successfully!");
                    println!("\nSeed Words (SAVE THESE SECURELY):");
                    println!("{}", wallet_info.seed_words);
                    println!("\nView Key:");
                    println!("{}", wallet_info.view_key);
                    println!("\nSpend Key:");
                    println!("{}", wallet_info.spend_key);
                    println!("\nTari Address:");
                    println!("{}", wallet_info.address.to_emoji_string());
                    println!("\nTari Address (Base58):");
                    println!("{}", wallet_info.address.to_base58());
                    println!("\nNetwork: {}", wallet_info.network);
                }
                Err(e) => println!("Error generating wallet: {:#?}", e),
            }
        }
        Command::DecodeAddress { address } => {
            match address::decode_address(&address) {
                Ok(address) => address::print_address_details(&address),
                Err(e) => println!("Error decoding address: {:#?}", e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // Test data - replace with actual valid Tari addresses for your test cases
    const TEST_ADDRESS: &str = "14EfzYEcTVKG3oMQ7vjEATC8t6xHxEvqXHRjCwcKTmuWWL4y8sEsMbdDsG4kPrH4G3BfKk7Wbh9CoyjAwRNdbHk8V9s";
    const INVALID_ADDRESS: &str = "invalid_address";

    #[test]
    fn test_valid_address_parsing() {
        let address = TariAddress::from_str(TEST_ADDRESS);
        assert!(address.is_ok());
        
        let address = address.unwrap();
        assert_eq!(address.to_base58(), TEST_ADDRESS);
        assert!(!address.to_emoji_string().is_empty());
        assert!(!address.to_hex().is_empty());
        assert!(!address.to_vec().is_empty());
    }

    #[test]
    fn test_invalid_address_parsing() {
        let address = TariAddress::from_str(INVALID_ADDRESS);
        assert!(address.is_err());
    }

    #[test]
    fn test_address_features() {
        let address = TariAddress::from_str(TEST_ADDRESS).unwrap();
        let features = address.features();
        
        // Test that features are properly decoded
        assert!(features.as_u8() > 0);
        // Add more specific feature tests based on your test address
    }

    #[test]
    fn test_address_network() {
        let address = TariAddress::from_str(TEST_ADDRESS).unwrap();
        let network = address.network();
        
        // Test that network is properly decoded
        assert_eq!(network.as_byte() , 0x00);
    }

    #[test]
    fn test_address_keys() {
        let address = TariAddress::from_str(TEST_ADDRESS).unwrap();
        
        // Test that spend key is present
        assert!(!address.public_spend_key().to_hex().is_empty());
        
        // Test view key (may or may not be present depending on address type)
        let view_key = address.public_view_key();
        // Add assertions based on your test address type
    }
}

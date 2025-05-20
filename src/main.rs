use std::env;
use std::str::FromStr;
use tari_common_types::tari_address::{TariAddress, TariAddressFeatures};
use tari_utilities::hex::Hex;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: decode-address <tari_address>");
        return;
    }

    let address_str = &args[1].trim();

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

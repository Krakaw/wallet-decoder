use std::str::FromStr;
use tari_common_types::tari_address::{TariAddress, TariAddressFeatures};
use crate::{utils};

pub fn decode_address(address_str: &str) -> Result<TariAddress, anyhow::Error> {
    let address = TariAddress::from_str(address_str)?;
    Ok(address)
}

pub fn print_address_details(address: &TariAddress) {
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
    println!("Public Spend Key: {}", address.public_spend_key());
    if let Some(view_key) = address.public_view_key() {
        println!("Public View Key: {}", view_key);
    }

    println!("\n=== Address Type ===");
    match address {
        TariAddress::Single(_) => println!("Type: Single Address"),
        TariAddress::Dual(_) => println!("Type: Dual Address"),
    }

    let payment_id = address.get_payment_id_user_data_bytes();
    if !payment_id.is_empty() {
        println!("\n=== Payment ID Data ===");
        println!("Payment ID (raw bytes): {:?}", payment_id);
        let payment_string = utils::bytes_to_ascii_string(&payment_id);
        println!("Payment ID: {:?}", payment_string);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_common_types::tari_address::TariAddressFeatures;

    const TEST_ADDRESS: &str = "18AFWJbqQtbZ5o5vDK5821RLqoJHYF1vC2aFf1gXfWaABhXGY3G6Ap8fucfDEFEYAQLQgGDD5rYBw6JVMneGiAzY2g6GB28URp3yz8SyyMi8BQM";
    const INVALID_ADDRESS: &str = "invalid_address";

    #[test]
    fn test_valid_address_parsing() {
        let address = TariAddress::from_str(TEST_ADDRESS);
        assert!(address.is_ok());

        let address = address.unwrap();
        assert_eq!(address.to_base58(), TEST_ADDRESS);
        assert_eq!(address.to_hex(), "00070ea2b9f4420ed83984fc5dc8834d7ce577848b0a366fc2385b4071a5eb253e234a3e7597c19e4dd9a9d31e490d1282174aa09a3428f4b30e657b75c6a9b9494e54657374205061796d656e74204944da");
        assert_eq!(address.to_vec().len(), 82);
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

        assert_eq!(features.as_u8(), 0x07);
        assert!(features.contains(TariAddressFeatures::ONE_SIDED));
        assert!(features.contains(TariAddressFeatures::INTERACTIVE));
        assert!(features.contains(TariAddressFeatures::PAYMENT_ID));
    }

    #[test]
    fn test_address_network() {
        let address = TariAddress::from_str(TEST_ADDRESS).unwrap();
        let network = address.network();

        assert_eq!(network.as_byte(), 0x00);
        assert_eq!(format!("{:?}", network), "MainNet");
    }

    #[test]
    fn test_address_keys() {
        let address = TariAddress::from_str(TEST_ADDRESS).unwrap();

        assert_eq!(
            address.public_spend_key().to_string(),
            "4a3e7597c19e4dd9a9d31e490d1282174aa09a3428f4b30e657b75c6a9b9494e"
        );

        let view_key = address.public_view_key();
        assert!(view_key.is_some());
        assert_eq!(
            view_key.unwrap().to_string(),
            "0ea2b9f4420ed83984fc5dc8834d7ce577848b0a366fc2385b4071a5eb253e23"
        );
    }

    #[test]
    fn test_address_type_and_payment_id() {
        let address = TariAddress::from_str(TEST_ADDRESS).unwrap();
        
        // Test address type
        match address {
            TariAddress::Dual(_) => assert!(true),
            _ => assert!(false, "Expected Dual address type"),
        }

        // Test payment ID
        let payment_id = address.get_payment_id_user_data_bytes();
        println!("Payment ID: {:?}", utils::bytes_to_ascii_string(&payment_id));
        assert!(!payment_id.is_empty());
        assert_eq!(
            utils::bytes_to_ascii_string(&payment_id),
            "Test Payment ID"
        );
    }
}
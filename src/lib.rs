use std::str::FromStr;
use tari_common_types::tari_address::{TariAddress, TariAddressFeatures};
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct AddressInfo {
    base58: String,
    emoji: String,
    hex: String,
    raw_bytes: Vec<u8>,
    network: String,
    network_byte: u8,
    features: FeaturesInfo,
    public_spend_key: String,
    public_view_key: Option<String>,
    address_type: String,
    payment_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct FeaturesInfo {
    features_byte: u8,
    one_sided: bool,
    interactive: bool,
    payment_id: bool,
}

#[wasm_bindgen]
pub fn decode_tari_address(address_str: &str) -> Result<JsValue, JsError> {
    let address = TariAddress::from_str(address_str.trim())
        .map_err(|e| JsError::new(&format!("Error decoding address: {:#?}", e)))?;

    let features = address.features();
    let features_info = FeaturesInfo {
        features_byte: features.as_u8(),
        one_sided: features.contains(TariAddressFeatures::ONE_SIDED),
        interactive: features.contains(TariAddressFeatures::INTERACTIVE),
        payment_id: features.contains(TariAddressFeatures::PAYMENT_ID),
    };

    let info = AddressInfo {
        base58: address.to_base58(),
        emoji: address.to_emoji_string(),
        hex: address.to_hex(),
        raw_bytes: address.to_vec(),
        network: format!("{:?}", address.network()),
        network_byte: address.network().as_byte(),
        features: features_info,
        public_spend_key: address.public_spend_key().to_hex(),
        public_view_key: address.public_view_key().map(|k| k.to_hex()),
        address_type: match address {
            TariAddress::Single(_) => "Single Address".to_string(),
            TariAddress::Dual(_) => "Dual Address".to_string(),
        },
        payment_id: {
            let payment_id = address.get_payment_id_user_data_bytes();
            if payment_id.is_empty() {
                None
            } else {
                Some(payment_id.to_hex())
            }
        },
    };

    Ok(serde_wasm_bindgen::to_value(&info)?)
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
        assert_eq!(network.as_byte(), 0x00);
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

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn test_wasm_decode_valid_address() {
        let result = decode_tari_address(TEST_ADDRESS);
        assert!(result.is_ok());
        
        let info: AddressInfo = serde_wasm_bindgen::from_value(result.unwrap()).unwrap();
        assert_eq!(info.base58, TEST_ADDRESS);
    }

    #[wasm_bindgen_test]
    fn test_wasm_decode_invalid_address() {
        let result = decode_tari_address(INVALID_ADDRESS);
        assert!(result.is_err());
    }
} 
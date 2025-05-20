use std::str::FromStr;
use tari_common_types::tari_address::{TariAddress, TariAddressFeatures};
use tari_utilities::{hex::Hex};
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

// #[wasm_bindgen]
// pub fn generate_wallet(password: Option<String>, network: String) -> Result<JsValue, JsError> {
//     let info = wallet::generate_wallet(password.map(SafePassword::from), network)
//         .map_err(|e| JsError::new(&format!("Error generating wallet: {:#?}", e)))?;
//     Ok(serde_wasm_bindgen::to_value(&info)?)
// }

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
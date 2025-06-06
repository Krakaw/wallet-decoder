use crate::checksum::{compute_checksum, verify_data_with_checksum};
use crate::emoji::{bytes_to_emoji, emoji_to_bytes};
use crate::error::{Result, TariError};
use crate::keys::PublicKey;
use crate::network::Network;
use crate::utils;

const TARI_ADDRESS_INTERNAL_SINGLE_SIZE: usize = 35;
const TARI_ADDRESS_INTERNAL_DUAL_SIZE: usize = 67;
const MAX_ENCRYPTED_DATA_SIZE: usize = 256; // Maximum size for payment ID

/// Address feature flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFeatures {
    /// One-sided address (standard)
    OneSided = 0x01,
    /// Interactive address
    Interactive = 0x02,
    /// Payment ID integrated address
    PaymentId = 0x04,
    /// Combined features
    OneSidedWithPaymentId = 0x05,
}

impl AddressFeatures {
    /// Create features from byte value
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => AddressFeatures::OneSided,
            0x02 => AddressFeatures::Interactive,
            0x04 => AddressFeatures::PaymentId,
            0x05 => AddressFeatures::OneSidedWithPaymentId,
            _ => AddressFeatures::OneSided, // Default to one-sided
        }
    }

    /// Get byte value of features
    pub fn as_byte(&self) -> u8 {
        *self as u8
    }

    /// Check if payment ID is included
    pub fn has_payment_id(&self) -> bool {
        (self.as_byte() & AddressFeatures::PaymentId as u8) != 0
    }
}

/// Represents a Tari address with various encoding formats
#[derive(Clone, PartialEq, Eq)]
pub struct TariAddress {
    network: Network,
    features: AddressFeatures,
    view_key: PublicKey,
    spend_key: PublicKey,
    payment_id: Option<Vec<u8>>,
}

impl TariAddress {
    /// Create a new Tari address
    pub fn new(
        network: Network,
        view_key: PublicKey,
        spend_key: PublicKey,
        payment_id: Option<Vec<u8>>,
    ) -> Self {
        let features = if payment_id.is_some() {
            AddressFeatures::OneSidedWithPaymentId
        } else {
            AddressFeatures::OneSided
        };

        Self {
            network,
            features,
            view_key,
            spend_key,
            payment_id,
        }
    }

    /// Create address from components
    pub fn from_components(
        network: Network,
        features: AddressFeatures,
        view_key: PublicKey,
        spend_key: PublicKey,
        payment_id: Option<Vec<u8>>,
    ) -> Self {
        Self {
            network,
            features,
            view_key,
            spend_key,
            payment_id,
        }
    }

    /// Get the network
    pub fn network(&self) -> Network {
        self.network
    }

    /// Get the features
    pub fn features(&self) -> AddressFeatures {
        self.features
    }

    /// Get the view key
    pub fn view_key(&self) -> &PublicKey {
        &self.view_key
    }

    /// Get the spend key
    pub fn spend_key(&self) -> &PublicKey {
        &self.spend_key
    }

    /// Get the payment ID
    pub fn payment_id(&self) -> Option<&[u8]> {
        self.payment_id.as_deref()
    }

    /// Get the payment ID ASCII
    pub fn payment_id_ascii(&self) -> Option<String> {
        self.payment_id
            .as_ref()
            .map(|pid| utils::bytes_to_ascii_string(pid))
    }

    /// Convert to raw bytes (without checksum)
    pub fn to_bytes(&self) -> Vec<u8> {
        let payment_id_len = self.payment_id.as_ref().map_or(0, |pid| pid.len());
        let length = TARI_ADDRESS_INTERNAL_DUAL_SIZE + payment_id_len; // 67 for network, features, view key, spend key + payment_id
        let mut buf = vec![0; length];
        buf[0] = self.network.as_byte();
        buf[1] = self.features.as_byte();
        buf[2..34].copy_from_slice(&self.view_key.as_bytes());
        buf[34..66].copy_from_slice(&self.spend_key.as_bytes());
        if let Some(payment_id) = &self.payment_id {
            buf[66..(length - 1)].copy_from_slice(payment_id);
        }
        let checksum = compute_checksum(&buf[0..(length - 1)]);
        buf[length - 1] = checksum;
        buf
    }

    /// Convert to bytes with checksum
    pub fn to_bytes_with_checksum(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Convert to Base58 format
    pub fn to_base58(&self) -> String {
        let bytes = self.to_bytes();

        let mut base58 = "".to_string();
        let network = bs58::encode(&bytes[0..1]).into_string();
        let features = bs58::encode(&bytes[1..2].to_vec()).into_string();

        let rest = bs58::encode(&bytes[2..]).into_string();

        base58.push_str(&network);
        base58.push_str(&features);
        base58.push_str(&rest);
        base58
    }

    /// Convert to emoji format
    pub fn to_emoji(&self) -> String {
        let final_bytes = self.to_bytes_with_checksum();
        bytes_to_emoji(&final_bytes)
    }

    /// Parse address from Base58 string
    pub fn from_base58(s: &str) -> Result<Self> {
        if s.len() < 2 {
            return Err(TariError::InvalidAddress("Address too short".to_string()));
        }

        let (first, rest) = s.split_at(2);
        let (network, features) = first.split_at(1);

        let mut result = bs58::decode(network)
            .into_vec()
            .map_err(|_| TariError::InvalidAddress("Cannot recover network".to_string()))?;
        let mut features = bs58::decode(features)
            .into_vec()
            .map_err(|_| TariError::InvalidAddress("Cannot recover features".to_string()))?;
        let mut rest = bs58::decode(rest)
            .into_vec()
            .map_err(|_| TariError::InvalidAddress("Cannot recover public key".to_string()))?;

        result.append(&mut features);
        result.append(&mut rest);

        Self::from_bytes(&result)
    }

    /// Parse address from emoji string
    pub fn from_emoji(emoji: &str) -> Result<Self> {
        let bytes = emoji_to_bytes(emoji)
            .ok_or_else(|| TariError::InvalidAddress("Invalid emoji sequence".to_string()))?;
        Self::from_bytes_with_checksum(&bytes)
    }

    /// Parse address from bytes with checksum
    pub fn from_bytes_with_checksum(bytes: &[u8]) -> Result<Self> {
        if !verify_data_with_checksum(bytes) {
            return Err(TariError::InvalidChecksum);
        }

        Self::from_bytes(&bytes)
    }

    /// Parse address from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| TariError::InvalidAddress("Invalid hex string".to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Parse address from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let length = bytes.len();

        if length != TARI_ADDRESS_INTERNAL_SINGLE_SIZE
            && !(TARI_ADDRESS_INTERNAL_DUAL_SIZE
                ..=TARI_ADDRESS_INTERNAL_DUAL_SIZE + MAX_ENCRYPTED_DATA_SIZE)
                .contains(&length)
        {
            return Err(TariError::InvalidAddress(
                "Invalid address size".to_string(),
            ));
        }

        if bytes.len() == TARI_ADDRESS_INTERNAL_SINGLE_SIZE {
            // Handle single address (without payment ID)
            let network = Network::from_byte(bytes[0])?;
            let features = AddressFeatures::from_byte(bytes[1]);
            let view_key = PublicKey::from_bytes(&bytes[2..34])?;
            let spend_key = PublicKey::from_bytes(&bytes[34..66])?;

            Ok(Self::from_components(
                network, features, view_key, spend_key, None,
            ))
        } else {
            // Handle dual address (with payment ID)
            let network = Network::from_byte(bytes[0])?;
            let features = AddressFeatures::from_byte(bytes[1]);
            let view_key = PublicKey::from_bytes(&bytes[2..34])?;
            let spend_key = PublicKey::from_bytes(&bytes[34..66])?;

            let payment_id = if bytes.len() > TARI_ADDRESS_INTERNAL_DUAL_SIZE {
                Some(bytes[66..(bytes.len() - 1)].to_vec())
            } else {
                None
            };

            Ok(Self::from_components(
                network, features, view_key, spend_key, payment_id,
            ))
        }
    }

    /// Validate payment ID
    pub fn validate_payment_id(payment_id: &[u8]) -> Result<()> {
        if payment_id.len() > 256 {
            return Err(TariError::InvalidPaymentId(
                "Payment ID too long (max 256 bytes)".to_string(),
            ));
        }
        Ok(())
    }

    /// Create address with payment ID
    pub fn with_payment_id(&self, payment_id: Vec<u8>) -> Result<Self> {
        Self::validate_payment_id(&payment_id)?;

        Ok(Self::new(
            self.network,
            self.view_key.clone(),
            self.spend_key.clone(),
            Some(payment_id),
        ))
    }

    /// Remove payment ID from address
    pub fn without_payment_id(&self) -> Self {
        Self::new(
            self.network,
            self.view_key.clone(),
            self.spend_key.clone(),
            None,
        )
    }
}

impl std::fmt::Debug for TariAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TariAddress")
            .field("network", &self.network())
            .field("features", &self.features())
            .field("view_key", &self.view_key().to_hex())
            .field("spend_key", &self.spend_key().to_hex())
            .field("payment_id", &self.payment_id().map(|id| hex::encode(id)))
            .field("base58", &self.to_base58())
            .field("emoji", &self.to_emoji())
            .finish()
    }
}

impl std::fmt::Display for TariAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::PrivateKey;

    fn create_test_keys() -> (PublicKey, PublicKey) {
        let view_private = PrivateKey::random();
        let spend_private = PrivateKey::random();
        (view_private.public_key(), spend_private.public_key())
    }

    #[test]
    fn test_address_creation() {
        let (view_key, spend_key) = create_test_keys();
        let address = TariAddress::new(Network::MainNet, view_key, spend_key, None);

        assert_eq!(address.network(), Network::MainNet);
        assert_eq!(address.features(), AddressFeatures::OneSided);
        assert!(address.payment_id().is_none());
    }

    #[test]
    fn test_address_with_payment_id() {
        let (view_key, spend_key) = create_test_keys();
        let payment_id = b"test_payment_id".to_vec();
        let address = TariAddress::new(
            Network::MainNet,
            view_key,
            spend_key,
            Some(payment_id.clone()),
        );

        assert_eq!(address.features(), AddressFeatures::OneSidedWithPaymentId);
        assert_eq!(address.payment_id(), Some(payment_id.as_slice()));
        assert_eq!(
            address.payment_id_ascii(),
            Some("test_payment_id".to_string())
        );
    }

    #[test]
    fn test_address_encoding() {
        let (view_key, spend_key) = create_test_keys();
        let address = TariAddress::new(Network::MainNet, view_key, spend_key, None);

        let base58 = address.to_base58();
        let emoji = address.to_emoji();

        assert!(!base58.is_empty());
        assert!(!emoji.is_empty());
        assert_ne!(base58, emoji);
    }

    #[test]
    fn test_address_roundtrip() {
        let (view_key, spend_key) = create_test_keys();
        let original = TariAddress::new(Network::MainNet, view_key, spend_key, None);

        let bytes = original.to_bytes_with_checksum();
        let recovered = TariAddress::from_bytes_with_checksum(&bytes).unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_address_from_emoji() {
        let (view_key, spend_key) = create_test_keys();
        // let original = TariAddress::new(Network::MainNet, view_key, spend_key, None).with_payment_id(vec![1, 2, 3, 4, 5]).unwrap();
        let original = TariAddress::new(Network::MainNet, view_key, spend_key, None);
        let emoji = original.to_emoji();
        let recovered = TariAddress::from_emoji(&emoji).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_address_from_base58() {
        let (view_key, spend_key) = create_test_keys();
        let original = TariAddress::new(Network::MainNet, view_key, spend_key, None);
        let base58 = original.to_base58();
        let recovered = TariAddress::from_base58(&base58).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_address_from_hex() {
        let (view_key, spend_key) = create_test_keys();
        let original = TariAddress::new(Network::MainNet, view_key, spend_key, None);
        let bytes = original.to_bytes_with_checksum();
        let hex = hex::encode(bytes);
        let recovered = TariAddress::from_hex(&hex).unwrap();
        assert_eq!(original, recovered);
        let recovered = TariAddress::from_hex("0001fc9e9cb2bd8f1e4cf70c1104545622cb84a9b2dd19735d20575d761d6ba9936280dd789fee2ae68aa63f09a78ccc2938cdaec33ecc909c1f86a9f654bdf15538d5").unwrap();
        assert_eq!(recovered.to_base58(), "12PHyR5CePL5jyoevS6BbSjV2WnNgVcmaqgZA9NqPJd3894YFzCCSHn9Auvpai1LT4LKJxH2c7yyiwuxqdkxYjACrPn");
    }

    #[test]
    fn test_address_from_emoji_with_payment_id() {
        let (view_key, spend_key) = create_test_keys();
        let original = TariAddress::new(Network::MainNet, view_key, spend_key, None)
            .with_payment_id(vec![1, 2, 3, 4, 5])
            .unwrap();
        let emoji = original.to_emoji();
        let recovered = TariAddress::from_emoji(&emoji).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_payment_id_validation() {
        let valid_payment_id = vec![1u8; 100];
        let invalid_payment_id = vec![1u8; 300]; // Too long

        assert!(TariAddress::validate_payment_id(&valid_payment_id).is_ok());
        assert!(TariAddress::validate_payment_id(&invalid_payment_id).is_err());
    }

    #[test]
    fn test_address_features() {
        assert_eq!(AddressFeatures::OneSided.as_byte(), 0x01);
        assert_eq!(AddressFeatures::PaymentId.as_byte(), 0x04);
        assert_eq!(AddressFeatures::OneSidedWithPaymentId.as_byte(), 0x05);

        assert!(!AddressFeatures::OneSided.has_payment_id());
        assert!(AddressFeatures::PaymentId.has_payment_id());
        assert!(AddressFeatures::OneSidedWithPaymentId.has_payment_id());
    }
}

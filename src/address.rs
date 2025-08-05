use crate::checksum::{compute_checksum, verify_data_with_checksum};
use crate::emoji::{bytes_to_emoji, emoji_to_bytes};
use crate::error::{Result, TariError, AddressParsingStage, AddressParsingAttempt, AddressComponentBreakdown, ComponentValidation};
use crate::keys::PublicKey;
use crate::network::Network;
use crate::utils;

const TARI_ADDRESS_INTERNAL_SINGLE_SIZE: usize = 35;
const TARI_ADDRESS_INTERNAL_DUAL_SIZE: usize = 67;
const MAX_ENCRYPTED_DATA_SIZE: usize = 256; // Maximum size for payment ID

/// Address feature flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressFeatures(pub u8);

impl AddressFeatures {
    pub const ONE_SIDED: AddressFeatures = AddressFeatures(0x01);
    pub const INTERACTIVE: AddressFeatures = AddressFeatures(0x02);
    pub const PAYMENT_ID: AddressFeatures = AddressFeatures(0x04);

    /// Create features from byte value
    pub fn from_byte(byte: u8) -> Self {
        AddressFeatures(byte)
    }

    /// Get byte value of features
    pub fn as_byte(&self) -> u8 {
        self.0
    }

    /// Check if payment ID is included
    pub fn has_payment_id(&self) -> bool {
        self.contains(AddressFeatures::PAYMENT_ID)
    }

    /// Check if interactive is included
    pub fn has_interactive(&self) -> bool {
        self.contains(AddressFeatures::INTERACTIVE)
    }

    /// Check if one-sided is included
    pub fn has_one_sided(&self) -> bool {
        self.contains(AddressFeatures::ONE_SIDED)
    }

    /// Check if features contains a specific feature
    pub fn contains(&self, feature: AddressFeatures) -> bool {
        (self.0 & feature.0) != 0
    }

    /// Combine features
    pub fn combine(&self, other: AddressFeatures) -> AddressFeatures {
        AddressFeatures(self.0 | other.0)
    }

    /// Create interactive only features
    pub fn create_interactive_only() -> Self {
        AddressFeatures::INTERACTIVE
    }

    /// Create one-sided only features
    pub fn create_one_sided_only() -> Self {
        AddressFeatures::ONE_SIDED
    }

    /// Create interactive and one-sided features
    pub fn create_interactive_and_one_sided() -> Self {
        AddressFeatures::INTERACTIVE | AddressFeatures::ONE_SIDED
    }
}

impl std::ops::BitOr for AddressFeatures {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.combine(rhs)
    }
}

impl std::fmt::Display for AddressFeatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.has_interactive() {
            write!(f, "Interactive,")?;
        }
        if self.has_one_sided() {
            write!(f, "One-sided,")?;
        }
        if self.has_payment_id() {
            write!(f, "Payment-id,")?;
        }
        Ok(())
    }
}

impl Default for AddressFeatures {
    fn default() -> Self {
        AddressFeatures::ONE_SIDED
    }
}

/// Represents a Tari address with various encoding formats
#[derive(Clone, PartialEq, Eq)]
pub struct TariAddress {
    network: Network,
    features: AddressFeatures,
    view_key: Option<PublicKey>,
    spend_key: PublicKey,
    payment_id: Option<Vec<u8>>,
}

impl TariAddress {
    /// Create a new Tari address
    pub fn new(
        network: Network,
        view_key: Option<PublicKey>,
        spend_key: PublicKey,
        payment_id: Option<Vec<u8>>,
    ) -> Self {
        let features = if payment_id.is_some() {
            AddressFeatures::ONE_SIDED | AddressFeatures::PAYMENT_ID
        } else {
            AddressFeatures::ONE_SIDED
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
        view_key: Option<PublicKey>,
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
    pub fn view_key(&self) -> Option<&PublicKey> {
        self.view_key.as_ref()
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

    /// Get the address type
    pub fn address_type(&self) -> String {
        if self.view_key().is_some() {
            "Dual Address".to_string()
        } else {
            "Single Address".to_string()
        }
    }

    /// Convert to bytes for a single address
    pub fn to_bytes_single(&self) -> Vec<u8> {
        let mut buf = vec![0; TARI_ADDRESS_INTERNAL_SINGLE_SIZE];
        buf[0] = self.network.as_byte();
        buf[1] = self.features.as_byte();
        buf[2..34].copy_from_slice(&self.spend_key.as_bytes());
        let checksum = compute_checksum(&buf[0..(TARI_ADDRESS_INTERNAL_SINGLE_SIZE - 1)]);
        buf[TARI_ADDRESS_INTERNAL_SINGLE_SIZE - 1] = checksum;
        buf
    }

    /// Convert to raw bytes (without checksum)
    pub fn to_bytes(&self) -> Vec<u8> {
        // Check if the address is a single address
        if self.view_key().is_none() {
            return self.to_bytes_single();
        }

        let payment_id_len = self.payment_id.as_ref().map_or(0, |pid| pid.len());
        let length = TARI_ADDRESS_INTERNAL_DUAL_SIZE + payment_id_len; // 67 for network, features, view key, spend key + payment_id
        let mut buf = vec![0; length];
        buf[0] = self.network.as_byte();
        buf[1] = self.features.as_byte();
        if let Some(view_key) = &self.view_key {
            buf[2..34].copy_from_slice(&view_key.as_bytes());
        }
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
            println!("Single address");
            // Handle single address (without payment ID)
            let network = Network::from_byte(bytes[0])?;
            let features = AddressFeatures::from_byte(bytes[1]);
            let spend_key = PublicKey::from_bytes(&bytes[2..34])?;

            Ok(Self::from_components(
                network, features, None, spend_key, None,
            ))
        } else {
            // Handle dual address (with payment ID)
            let network = Network::from_byte(bytes[0])?;
            let features = AddressFeatures::from_byte(bytes[1]);
            let view_key = if bytes.len() > TARI_ADDRESS_INTERNAL_SINGLE_SIZE {
                Some(PublicKey::from_bytes(&bytes[2..34])?)
            } else {
                None
            };
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
            self.view_key.clone()   ,
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

    /// Parse address from Base58 string with detailed error tracking
    pub fn from_base58_detailed(s: &str) -> std::result::Result<Self, AddressParsingAttempt> {
        if s.len() < 2 {
            return Err(AddressParsingAttempt {
                format: "Base58".to_string(),
                stage: AddressParsingStage::SizeValidation,
                error: format!("Address too short: {} characters (minimum 2)", s.len()),
            });
        }

        let (first, rest) = s.split_at(2);
        let (network, features) = first.split_at(1);

        let network_bytes = bs58::decode(network)
            .into_vec()
            .map_err(|e| AddressParsingAttempt {
                format: "Base58".to_string(),
                stage: AddressParsingStage::Base58NetworkDecoding,
                error: format!("Cannot decode network byte '{}': {}", network, e),
            })?;

        let features_bytes = bs58::decode(features)
            .into_vec()
            .map_err(|e| AddressParsingAttempt {
                format: "Base58".to_string(),
                stage: AddressParsingStage::Base58FeaturesDecoding,
                error: format!("Cannot decode features byte '{}': {}", features, e),
            })?;

        let rest_bytes = bs58::decode(rest)
            .into_vec()
            .map_err(|e| AddressParsingAttempt {
                format: "Base58".to_string(),
                stage: AddressParsingStage::Base58PublicKeyDecoding,
                error: format!("Cannot decode public key data '{}': {}", rest, e),
            })?;

        let mut result = network_bytes;
        result.extend(features_bytes);
        result.extend(rest_bytes);

        Self::from_bytes_detailed(&result, "Base58")
    }

    /// Parse address from emoji string with detailed error tracking
    pub fn from_emoji_detailed(emoji: &str) -> std::result::Result<Self, AddressParsingAttempt> {
        let bytes = emoji_to_bytes(emoji)
            .ok_or_else(|| AddressParsingAttempt {
                format: "Emoji".to_string(),
                stage: AddressParsingStage::EmojiDecoding,
                error: format!("Invalid emoji sequence - contains invalid or unsupported emoji characters"),
            })?;

        Self::from_bytes_with_checksum_detailed(&bytes, "Emoji")
    }

    /// Parse address from hex string with detailed error tracking
    pub fn from_hex_detailed(hex_str: &str) -> std::result::Result<Self, AddressParsingAttempt> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| AddressParsingAttempt {
                format: "Hex".to_string(),
                stage: AddressParsingStage::HexDecoding,
                error: format!("Invalid hex string '{}': {}", hex_str, e),
            })?;

        Self::from_bytes_detailed(&bytes, "Hex")
    }

    /// Parse address from bytes with checksum validation and detailed error tracking
    pub fn from_bytes_with_checksum_detailed(bytes: &[u8], format: &str) -> std::result::Result<Self, AddressParsingAttempt> {
        if !verify_data_with_checksum(bytes) {
            return Err(AddressParsingAttempt {
                format: format.to_string(),
                stage: AddressParsingStage::ChecksumValidation,
                error: format!("Invalid checksum - computed checksum doesn't match expected value"),
            });
        }

        Self::from_bytes_detailed(&bytes, format)
    }

    /// Parse address from raw bytes with detailed error tracking
    pub fn from_bytes_detailed(bytes: &[u8], format: &str) -> std::result::Result<Self, AddressParsingAttempt> {
        let length = bytes.len();

        // Validate size
        if length != TARI_ADDRESS_INTERNAL_SINGLE_SIZE
            && !(TARI_ADDRESS_INTERNAL_DUAL_SIZE
                ..=TARI_ADDRESS_INTERNAL_DUAL_SIZE + MAX_ENCRYPTED_DATA_SIZE)
                .contains(&length)
        {
            return Err(AddressParsingAttempt {
                format: format.to_string(),
                stage: AddressParsingStage::SizeValidation,
                error: format!(
                    "Invalid address size: {} bytes (expected {} for single address or {}-{} for dual address)",
                    length,
                    TARI_ADDRESS_INTERNAL_SINGLE_SIZE,
                    TARI_ADDRESS_INTERNAL_DUAL_SIZE,
                    TARI_ADDRESS_INTERNAL_DUAL_SIZE + MAX_ENCRYPTED_DATA_SIZE
                ),
            });
        }

        // Validate network
        let network = Network::from_byte(bytes[0]).map_err(|_| AddressParsingAttempt {
            format: format.to_string(),
            stage: AddressParsingStage::NetworkValidation,
            error: format!(
                "Invalid network byte: 0x{:02x} (valid values: 0x00=MainNet, 0x02=NextNet, 0x26=Esmeralda)",
                bytes[0]
            ),
        })?;

        let features = AddressFeatures::from_byte(bytes[1]);

        if bytes.len() == TARI_ADDRESS_INTERNAL_SINGLE_SIZE {
            // Handle single address (without payment ID)
            let spend_key = PublicKey::from_bytes(&bytes[2..34]).map_err(|e| AddressParsingAttempt {
                format: format.to_string(),
                stage: AddressParsingStage::PublicKeyValidation,
                error: format!("Invalid spend public key: {}", e),
            })?;

            Ok(Self::from_components(
                network, features, None, spend_key, None,
            ))
        } else {
            // Handle dual address (with payment ID)
            let view_key = if bytes.len() > TARI_ADDRESS_INTERNAL_SINGLE_SIZE {
                Some(PublicKey::from_bytes(&bytes[2..34]).map_err(|e| AddressParsingAttempt {
                    format: format.to_string(),
                    stage: AddressParsingStage::PublicKeyValidation,
                    error: format!("Invalid view public key: {}", e),
                })?)
            } else {
                None
            };

            let spend_key = PublicKey::from_bytes(&bytes[34..66]).map_err(|e| AddressParsingAttempt {
                format: format.to_string(),
                stage: AddressParsingStage::PublicKeyValidation,
                error: format!("Invalid spend public key: {}", e),
            })?;

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

    /// Parse address with comprehensive error reporting for all formats
    pub fn parse_with_detailed_errors(address_str: &str) -> Result<Self> {
        let mut attempts = Vec::new();

        // Try emoji first (contains Unicode)
        if address_str.trim().chars().any(|c| !c.is_ascii()) {
            match Self::from_emoji_detailed(address_str) {
                Ok(address) => return Ok(address),
                Err(attempt) => attempts.push(attempt),
            }
        } else {
            // Try Base58 first (most common format)
            match Self::from_base58_detailed(address_str) {
                Ok(address) => return Ok(address),
                Err(attempt) => attempts.push(attempt),
            }

            // Try hex as fallback
            match Self::from_hex_detailed(address_str) {
                Ok(address) => return Ok(address),
                Err(attempt) => attempts.push(attempt),
            }
        }

        // All formats failed - create detailed error
        let summary = format!(
            "Unable to parse address '{}' in any supported format",
            if address_str.chars().count() > 50 {
                format!("{}...", address_str.chars().take(50).collect::<String>())
            } else {
                address_str.to_string()
            }
        );

        let attempts_text = attempts
            .iter()
            .map(|attempt| {
                format!(
                    "  {} format: Failed at {} - {}",
                    attempt.format, attempt.stage, attempt.error
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        Err(TariError::DetailedAddressParsingError {
            summary,
            attempts: attempts_text,
        })
    }

    /// Parse address with comprehensive component-level breakdown
    pub fn parse_with_component_breakdown(address_str: &str) -> Result<Self> {
        // First try normal parsing
        match Self::parse_with_detailed_errors(address_str) {
            Ok(address) => Ok(address),
            Err(_) => {
                // Create detailed component breakdown
                let breakdown = Self::create_component_breakdown(address_str);
                Err(TariError::AddressComponentError { breakdown })
            }
        }
    }

    /// Create a detailed breakdown of address components
    fn create_component_breakdown(address_str: &str) -> AddressComponentBreakdown {
        let mut breakdown = AddressComponentBreakdown {
            original_input: address_str.to_string(),
            detected_format: "Unknown".to_string(),
            total_bytes: 0,
            network_byte: None,
            network_validation: ComponentValidation::NotPresent,
            features_byte: None,
            features_validation: ComponentValidation::NotPresent,
            view_public_key: None,
            view_key_validation: ComponentValidation::NotPresent,
            spend_public_key: None,
            spend_key_validation: ComponentValidation::NotPresent,
            payment_id: None,
            payment_id_validation: ComponentValidation::NotPresent,
            checksum_byte: None,
            checksum_validation: ComponentValidation::NotPresent,
            size_validation: ComponentValidation::NotPresent,
            raw_bytes: "Unable to decode".to_string(),
        };

        // Detect format and try to decode
        if address_str.trim().chars().any(|c| !c.is_ascii()) {
            breakdown.detected_format = "Emoji".to_string();
            Self::analyze_emoji_components(address_str, &mut breakdown);
        } else if address_str.chars().all(|c| c.is_ascii_hexdigit()) {
            breakdown.detected_format = "Hex".to_string();
            Self::analyze_hex_components(address_str, &mut breakdown);
        } else {
            breakdown.detected_format = "Base58".to_string();
            Self::analyze_base58_components(address_str, &mut breakdown);
        }

        breakdown
    }

    fn analyze_base58_components(address_str: &str, breakdown: &mut AddressComponentBreakdown) {
        // Try to decode Base58
        if address_str.len() < 2 {
            breakdown.size_validation = ComponentValidation::Invalid { 
                error: format!("Address too short: {} characters (minimum 2)", address_str.len()) 
            };
            return;
        }

        let (first, rest) = address_str.split_at(2);
        let (network, features) = first.split_at(1);

        // Decode network
        match bs58::decode(network).into_vec() {
            Ok(network_bytes) => {
                if !network_bytes.is_empty() {
                    breakdown.network_byte = Some(format!("0x{:02x}", network_bytes[0]));
                    breakdown.network_validation = match Network::from_byte(network_bytes[0]) {
                        Ok(net) => ComponentValidation::Valid,
                        Err(_) => ComponentValidation::Invalid { 
                            error: format!("Invalid network: 0x{:02x} (valid: 0x00=MainNet, 0x02=NextNet, 0x26=Esmeralda)", network_bytes[0])
                        },
                    };
                }
            }
            Err(e) => {
                breakdown.network_validation = ComponentValidation::Invalid { 
                    error: format!("Base58 decode error: {}", e) 
                };
            }
        }

        // Decode features
        match bs58::decode(features).into_vec() {
            Ok(features_bytes) => {
                if !features_bytes.is_empty() {
                    breakdown.features_byte = Some(format!("0x{:02x}", features_bytes[0]));
                    breakdown.features_validation = ComponentValidation::Valid;
                }
            }
            Err(e) => {
                breakdown.features_validation = ComponentValidation::Invalid { 
                    error: format!("Base58 decode error: {}", e) 
                };
            }
        }

        // Try to decode the full address
        let full_decode_result = Self::decode_full_base58(address_str);
        match full_decode_result {
            Ok(bytes) => {
                breakdown.total_bytes = bytes.len();
                breakdown.raw_bytes = hex::encode(&bytes);
                Self::analyze_decoded_bytes(&bytes, breakdown);
            }
            Err(e) => {
                breakdown.size_validation = ComponentValidation::Invalid { error: e };
            }
        }
    }

    fn analyze_hex_components(address_str: &str, breakdown: &mut AddressComponentBreakdown) {
        match hex::decode(address_str) {
            Ok(bytes) => {
                breakdown.total_bytes = bytes.len();
                breakdown.raw_bytes = hex::encode(&bytes);
                Self::analyze_decoded_bytes(&bytes, breakdown);
            }
            Err(e) => {
                breakdown.size_validation = ComponentValidation::Invalid { 
                    error: format!("Hex decode error: {}", e) 
                };
            }
        }
    }

    fn analyze_emoji_components(address_str: &str, breakdown: &mut AddressComponentBreakdown) {
        match emoji_to_bytes(address_str) {
            Some(bytes) => {
                breakdown.total_bytes = bytes.len();
                breakdown.raw_bytes = hex::encode(&bytes);
                Self::analyze_decoded_bytes(&bytes, breakdown);
            }
            None => {
                breakdown.size_validation = ComponentValidation::Invalid { 
                    error: "Invalid emoji sequence".to_string() 
                };
            }
        }
    }

    fn analyze_decoded_bytes(bytes: &[u8], breakdown: &mut AddressComponentBreakdown) {
        let length = bytes.len();

        // Size validation
        if length == TARI_ADDRESS_INTERNAL_SINGLE_SIZE || 
           (TARI_ADDRESS_INTERNAL_DUAL_SIZE..=TARI_ADDRESS_INTERNAL_DUAL_SIZE + MAX_ENCRYPTED_DATA_SIZE).contains(&length) {
            breakdown.size_validation = ComponentValidation::Valid;
        } else {
            breakdown.size_validation = ComponentValidation::Invalid { 
                error: format!(
                    "Invalid size: {} bytes (expected {} for single or {}-{} for dual)",
                    length, TARI_ADDRESS_INTERNAL_SINGLE_SIZE, 
                    TARI_ADDRESS_INTERNAL_DUAL_SIZE, 
                    TARI_ADDRESS_INTERNAL_DUAL_SIZE + MAX_ENCRYPTED_DATA_SIZE
                )
            };
        }

        if bytes.is_empty() {
            return;
        }

        // Network byte
        breakdown.network_byte = Some(format!("0x{:02x}", bytes[0]));
        breakdown.network_validation = match Network::from_byte(bytes[0]) {
            Ok(_) => ComponentValidation::Valid,
            Err(_) => ComponentValidation::Invalid { 
                error: format!("Invalid network: 0x{:02x} (valid: 0x00=MainNet, 0x02=NextNet, 0x26=Esmeralda)", bytes[0])
            },
        };

        if bytes.len() < 2 {
            return;
        }

        // Features byte
        breakdown.features_byte = Some(format!("0x{:02x}", bytes[1]));
        breakdown.features_validation = ComponentValidation::Valid;

        // For single address (35 bytes)
        if length == TARI_ADDRESS_INTERNAL_SINGLE_SIZE {
            if bytes.len() >= 34 {
                breakdown.spend_public_key = Some(hex::encode(&bytes[2..34]));
                breakdown.spend_key_validation = match PublicKey::from_bytes(&bytes[2..34]) {
                    Ok(_) => ComponentValidation::Valid,
                    Err(e) => ComponentValidation::Invalid { error: format!("Invalid spend key: {}", e) },
                };
            }

            if bytes.len() >= 35 {
                breakdown.checksum_byte = Some(format!("0x{:02x}", bytes[34]));
                breakdown.checksum_validation = if verify_data_with_checksum(bytes) {
                    ComponentValidation::Valid
                } else {
                    ComponentValidation::Invalid { error: "Checksum mismatch".to_string() }
                };
            }
        } 
        // For dual address (67+ bytes)
        else if length >= TARI_ADDRESS_INTERNAL_DUAL_SIZE {
            if bytes.len() >= 34 {
                breakdown.view_public_key = Some(hex::encode(&bytes[2..34]));
                breakdown.view_key_validation = match PublicKey::from_bytes(&bytes[2..34]) {
                    Ok(_) => ComponentValidation::Valid,
                    Err(e) => ComponentValidation::Invalid { error: format!("Invalid view key: {}", e) },
                };
            }

            if bytes.len() >= 66 {
                breakdown.spend_public_key = Some(hex::encode(&bytes[34..66]));
                breakdown.spend_key_validation = match PublicKey::from_bytes(&bytes[34..66]) {
                    Ok(_) => ComponentValidation::Valid,
                    Err(e) => ComponentValidation::Invalid { error: format!("Invalid spend key: {}", e) },
                };
            }

            if bytes.len() > TARI_ADDRESS_INTERNAL_DUAL_SIZE {
                let payment_id_end = bytes.len() - 1;
                breakdown.payment_id = Some(hex::encode(&bytes[66..payment_id_end]));
                breakdown.payment_id_validation = ComponentValidation::Valid;
            }

            if bytes.len() > 0 {
                let checksum_idx = bytes.len() - 1;
                breakdown.checksum_byte = Some(format!("0x{:02x}", bytes[checksum_idx]));
                breakdown.checksum_validation = if verify_data_with_checksum(bytes) {
                    ComponentValidation::Valid
                } else {
                    ComponentValidation::Invalid { error: "Checksum mismatch".to_string() }
                };
            }
        }
    }

    fn decode_full_base58(address_str: &str) -> std::result::Result<Vec<u8>, String> {
        if address_str.len() < 2 {
            return Err("Address too short".to_string());
        }

        let (first, rest) = address_str.split_at(2);
        let (network, features) = first.split_at(1);

        let mut result = bs58::decode(network)
            .into_vec()
            .map_err(|e| format!("Cannot decode network: {}", e))?;
        let mut features_bytes = bs58::decode(features)
            .into_vec()
            .map_err(|e| format!("Cannot decode features: {}", e))?;
        let mut rest_bytes = bs58::decode(rest)
            .into_vec()
            .map_err(|e| format!("Cannot decode rest: {}", e))?;

        result.append(&mut features_bytes);
        result.append(&mut rest_bytes);
        Ok(result)
    }
}

impl std::fmt::Debug for TariAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TariAddress")
            .field("network", &self.network())
            .field("features", &self.features())
            .field("view_key", &self.view_key().map(|key| key.to_hex()))
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
        let address = TariAddress::new(Network::MainNet, Some(view_key), spend_key, None);

        assert_eq!(address.network(), Network::MainNet);
        assert_eq!(address.features(), AddressFeatures::ONE_SIDED);
        assert!(address.payment_id().is_none());
    }

    #[test]
    fn test_single_address() {
        let address = TariAddress::from_hex("00016c1b073261df680b5a95dbc8c559ed1eec8d31f66c90e9e2843d3376cb61425112").unwrap();
        assert_eq!(address.network(), Network::MainNet);
        assert_eq!(address.features(), AddressFeatures::ONE_SIDED);
        assert_eq!(address.spend_key().to_hex(), "6c1b073261df680b5a95dbc8c559ed1eec8d31f66c90e9e2843d3376cb614251");
        assert!(address.payment_id().is_none());
    }

    #[test]
    fn test_address_with_payment_id() {
        let (view_key, spend_key) = create_test_keys();
        let payment_id = b"test_payment_id".to_vec();
        let address = TariAddress::new(
            Network::MainNet,
            Some(view_key),
            spend_key,
            Some(payment_id.clone()),
        );

        assert!(address.features().has_payment_id());
        assert!(address.features().has_one_sided());
        assert_eq!(address.payment_id(), Some(payment_id.as_slice()));
        assert_eq!(
            address.payment_id_ascii(),
            Some("test_payment_id".to_string())
        );
    }

    #[test]
    fn test_address_encoding() {
        let (view_key, spend_key) = create_test_keys();
        let address = TariAddress::new(Network::MainNet, Some(view_key), spend_key, None);

        let base58 = address.to_base58();
        let emoji = address.to_emoji();

        assert!(!base58.is_empty());
        assert!(!emoji.is_empty());
        assert_ne!(base58, emoji);
    }

    #[test]
    fn test_address_roundtrip() {
        let (view_key, spend_key) = create_test_keys();
        let original = TariAddress::new(Network::MainNet, Some(view_key), spend_key, None);

        let bytes = original.to_bytes_with_checksum();
        let recovered = TariAddress::from_bytes_with_checksum(&bytes).unwrap();

        assert_eq!(original, recovered);
    }

    #[test]
    fn test_address_from_emoji() {
        let (view_key, spend_key) = create_test_keys();
        // let original = TariAddress::new(Network::MainNet, view_key, spend_key, None).with_payment_id(vec![1, 2, 3, 4, 5]).unwrap();
        let original = TariAddress::new(Network::MainNet, Some(view_key), spend_key, None);
        let emoji = original.to_emoji();
        let recovered = TariAddress::from_emoji(&emoji).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_address_from_base58() {
        let (view_key, spend_key) = create_test_keys();
        let original = TariAddress::new(Network::MainNet, Some(view_key), spend_key, None);
        let base58 = original.to_base58();
        let recovered = TariAddress::from_base58(&base58).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_address_from_hex() {
        let (view_key, spend_key) = create_test_keys();
        let original = TariAddress::new(Network::MainNet, Some(view_key), spend_key, None);
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
        let original = TariAddress::new(Network::MainNet, Some(view_key)   , spend_key, None)
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
        // Test individual features
        assert_eq!(AddressFeatures::ONE_SIDED.as_byte(), 0x01);
        assert_eq!(AddressFeatures::INTERACTIVE.as_byte(), 0x02);
        assert_eq!(AddressFeatures::PAYMENT_ID.as_byte(), 0x04);

        // Test feature combinations
        let combined = AddressFeatures::ONE_SIDED | AddressFeatures::PAYMENT_ID;
        assert_eq!(combined.as_byte(), 0x05);

        // Test feature detection
        let features = AddressFeatures::from_byte(0x05);
        assert!(features.has_one_sided());
        assert!(features.has_payment_id());
        assert!(!features.has_interactive());

        // Test Display implementation
        let features = AddressFeatures::ONE_SIDED | AddressFeatures::PAYMENT_ID;
        assert_eq!(features.to_string(), "One-sided,Payment-id,");
    }

    #[test]
    fn test_detailed_error_handling() {
        use crate::error::TariError;
        
        // Test various invalid addresses to ensure detailed error reporting
        let test_cases = vec![
            ("", "Address too short"),
            ("1", "Address too short"), 
            ("12345", "Invalid address size"),
            ("invalidaddress", "invalid character"),
            ("FF016c1b073261df680b5a95dbc8c559ed1eec8d31f66c90e9e2843d3376cb61425112", "Invalid network byte: 0xff"),
            ("16Yt2MgL51qYTXBGQ6tF1Z9thmcxLgWGoAXWEdQRJjGriQ38DvGhPFXzLEDF4XtE4yrdXBS3n7byoUbsN6QdCuXyTXgArdJG6ZtAtPGvZQ", "Invalid compressed point"),
        ];

        for (invalid_address, expected_error_fragment) in test_cases {
            let result = TariAddress::parse_with_detailed_errors(invalid_address);
            assert!(result.is_err(), "Address '{}' should be invalid", invalid_address);
            
            match result.unwrap_err() {
                TariError::DetailedAddressParsingError { summary: _, attempts } => {
                    assert!(
                        attempts.contains(expected_error_fragment),
                        "Expected error fragment '{}' not found in attempts: {}",
                        expected_error_fragment,
                        attempts
                    );
                }
                other => panic!("Expected DetailedAddressParsingError, got: {:?}", other),
            }
        }
    }

    #[test]
    fn test_detailed_error_handling_preserves_valid_parsing() {
        // Ensure valid addresses still work with the new detailed error handling
        let valid_hex = "00016c1b073261df680b5a95dbc8c559ed1eec8d31f66c90e9e2843d3376cb61425112";
        let address = TariAddress::parse_with_detailed_errors(valid_hex).unwrap();
        
        assert_eq!(address.network(), Network::MainNet);
        assert_eq!(address.spend_key().to_hex(), "6c1b073261df680b5a95dbc8c559ed1eec8d31f66c90e9e2843d3376cb614251");
        
        // Test round-trip
        let base58 = address.to_base58();
        let restored = TariAddress::parse_with_detailed_errors(&base58).unwrap();
        assert_eq!(address, restored);
    }

    #[test]
    fn test_component_breakdown() {
        use crate::error::TariError;
        
        // Test with invalid address
        let invalid_address = "16Yt2MgL51qYTXBGQ6tF1Z9thmcxLgWGoAXWEdQRJjGriQ38DvGhPFXzLEDF4XtE4yrdXBS3n7byoUbsN6QdCuXyTXgArdJG6ZtAtPGvZQ";
        let result = TariAddress::parse_with_component_breakdown(invalid_address);
        
        assert!(result.is_err(), "Address should be invalid");
        
        match result.unwrap_err() {
            TariError::AddressComponentError { breakdown } => {
                assert_eq!(breakdown.detected_format, "Base58");
                assert_eq!(breakdown.total_bytes, 79);
                assert!(breakdown.network_byte.is_some());
                assert!(breakdown.view_public_key.is_some());
                assert!(breakdown.spend_public_key.is_some());
                assert!(matches!(breakdown.view_key_validation, ComponentValidation::Invalid { .. }));
                assert!(matches!(breakdown.spend_key_validation, ComponentValidation::Invalid { .. }));
            }
            other => panic!("Expected AddressComponentError, got: {:?}", other),
        }
    }

    #[test] 
    fn test_component_breakdown_valid_address() {
        // Test with valid address
        let valid_hex = "00016c1b073261df680b5a95dbc8c559ed1eec8d31f66c90e9e2843d3376cb61425112";
        let result = TariAddress::parse_with_component_breakdown(valid_hex);
        
        assert!(result.is_ok(), "Valid address should parse successfully");
        let address = result.unwrap();
        assert_eq!(address.network(), Network::MainNet);
    }
}

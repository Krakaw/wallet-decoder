use thiserror::Error;

/// Result type for Tari address generator operations
pub type Result<T> = std::result::Result<T, TariError>;

/// Address parsing stage where validation failed
#[derive(Debug, Clone)]
pub enum AddressParsingStage {
    FormatDetection,
    Base58NetworkDecoding,
    Base58FeaturesDecoding,
    Base58PublicKeyDecoding,
    HexDecoding,
    EmojiDecoding,
    BytesValidation,
    ChecksumValidation,
    NetworkValidation,
    PublicKeyValidation,
    SizeValidation,
}

impl std::fmt::Display for AddressParsingStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddressParsingStage::FormatDetection => write!(f, "format detection"),
            AddressParsingStage::Base58NetworkDecoding => write!(f, "base58 network decoding"),
            AddressParsingStage::Base58FeaturesDecoding => write!(f, "base58 features decoding"),
            AddressParsingStage::Base58PublicKeyDecoding => write!(f, "base58 public key decoding"),
            AddressParsingStage::HexDecoding => write!(f, "hex decoding"),
            AddressParsingStage::EmojiDecoding => write!(f, "emoji decoding"),
            AddressParsingStage::BytesValidation => write!(f, "bytes validation"),
            AddressParsingStage::ChecksumValidation => write!(f, "checksum validation"),
            AddressParsingStage::NetworkValidation => write!(f, "network validation"),
            AddressParsingStage::PublicKeyValidation => write!(f, "public key validation"),
            AddressParsingStage::SizeValidation => write!(f, "size validation"),
        }
    }
}

/// Detailed information about an address parsing attempt
#[derive(Debug, Clone)]
pub struct AddressParsingAttempt {
    pub format: String,
    pub stage: AddressParsingStage,
    pub error: String,
}

/// Validation result for an address component
#[derive(Debug, Clone)]
pub enum ComponentValidation {
    Valid,
    Invalid { error: String },
    NotPresent,
}

impl std::fmt::Display for ComponentValidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentValidation::Valid => write!(f, "✓ Valid"),
            ComponentValidation::Invalid { error } => write!(f, "✗ Invalid: {}", error),
            ComponentValidation::NotPresent => write!(f, "- Not present"),
        }
    }
}

/// Detailed breakdown of address components with hex data and validation results
#[derive(Debug, Clone)]
pub struct AddressComponentBreakdown {
    pub original_input: String,
    pub detected_format: String,
    pub total_bytes: usize,
    pub network_byte: Option<String>,
    pub network_validation: ComponentValidation,
    pub features_byte: Option<String>,
    pub features_validation: ComponentValidation,
    pub view_public_key: Option<String>,
    pub view_key_validation: ComponentValidation,
    pub spend_public_key: Option<String>,
    pub spend_key_validation: ComponentValidation,
    pub payment_id: Option<String>,
    pub payment_id_validation: ComponentValidation,
    pub checksum_byte: Option<String>,
    pub checksum_validation: ComponentValidation,
    pub size_validation: ComponentValidation,
    pub raw_bytes: String,
}

impl std::fmt::Display for AddressComponentBreakdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Address Component Breakdown:")?;
        writeln!(f, "============================")?;
        writeln!(f, "Original Input: {}", self.original_input)?;
        writeln!(f, "Detected Format: {}", self.detected_format)?;
        writeln!(f, "Total Bytes: {} ({} expected for single address, {}-{} for dual address)", 
                 self.total_bytes, 35, 67, 323)?;
        writeln!(f, "Raw Bytes: {}", self.raw_bytes)?;
        writeln!(f)?;
        
        writeln!(f, "Component Analysis:")?;
        writeln!(f, "===================")?;
        
        if let Some(ref network) = self.network_byte {
            writeln!(f, "Network Byte:     {} | {}", network, self.network_validation)?;
        } else {
            writeln!(f, "Network Byte:     {} | {}", "N/A", self.network_validation)?;
        }
        
        if let Some(ref features) = self.features_byte {
            writeln!(f, "Features Byte:    {} | {}", features, self.features_validation)?;
        } else {
            writeln!(f, "Features Byte:    {} | {}", "N/A", self.features_validation)?;
        }
        
        if let Some(ref view_key) = self.view_public_key {
            writeln!(f, "View Public Key:  {} | {}", view_key, self.view_key_validation)?;
        } else {
            writeln!(f, "View Public Key:  {} | {}", "N/A", self.view_key_validation)?;
        }
        
        if let Some(ref spend_key) = self.spend_public_key {
            writeln!(f, "Spend Public Key: {} | {}", spend_key, self.spend_key_validation)?;
        } else {
            writeln!(f, "Spend Public Key: {} | {}", "N/A", self.spend_key_validation)?;
        }
        
        if let Some(ref payment_id) = self.payment_id {
            writeln!(f, "Payment ID:       {} | {}", payment_id, self.payment_id_validation)?;
        } else {
            writeln!(f, "Payment ID:       {} | {}", "N/A", self.payment_id_validation)?;
        }
        
        if let Some(ref checksum) = self.checksum_byte {
            writeln!(f, "Checksum Byte:    {} | {}", checksum, self.checksum_validation)?;
        } else {
            writeln!(f, "Checksum Byte:    {} | {}", "N/A", self.checksum_validation)?;
        }
        
        writeln!(f)?;
        writeln!(f, "Overall Size:     {} | {}", self.total_bytes, self.size_validation)?;
        
        Ok(())
    }
}

/// Error types for Tari address generation
#[derive(Error, Debug)]
pub enum TariError {
    /// Invalid time
    #[error("Invalid time: {0}")]
    InvalidTime(String),

    /// Invalid network identifier
    #[error("Invalid network: {0}")]
    InvalidNetwork(u8),

    /// Invalid network name
    #[error("Invalid network: {0}")]
    InvalidNetworkName(String),

    /// Invalid address format
    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    /// Detailed address parsing failure with information about all attempted formats
    #[error("Address parsing failed: {summary}\n\nAttempted formats:\n{attempts}")]
    DetailedAddressParsingError {
        summary: String,
        attempts: String,
    },

    /// Comprehensive address component breakdown showing each part and what went wrong
    #[error("Address validation failed:\n\n{breakdown}")]
    AddressComponentError {
        breakdown: AddressComponentBreakdown,
    },

    /// Invalid checksum
    #[error("Invalid address checksum")]
    InvalidChecksum,

    /// Invalid payment ID
    #[error("Invalid payment ID: {0}")]
    InvalidPaymentId(String),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Invalid seed phrase
    #[error("Invalid seed phrase: {0}")]
    InvalidSeedPhrase(String),

    /// Encoding/decoding error
    #[error("Encoding error: {0}")]
    EncodingError(String),

    /// Invalid key length
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// Blake2b hashing error
    #[error("Blake2b error: {0}")]
    Blake2bError(String),

    /// BIP39 mnemonic error
    #[error("BIP39 error: {0}")]
    Bip39Error(#[from] bip39::Error),

    /// Base58 decoding error
    #[error("Base58 decode error: {0}")]
    Base58Error(#[from] bs58::decode::Error),

    /// Hex decoding error
    #[error("Hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),

    /// Argon2 error
    #[error("Argon2 error: {0}")]
    Argon2Error(String),

    /// ChaCha20 encryption error
    #[error("ChaCha20 error: {0}")]
    ChaCha20Error(String),

    /// Internal error or invalid argument
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<blake2::digest::InvalidLength> for TariError {
    fn from(err: blake2::digest::InvalidLength) -> Self {
        TariError::Blake2bError(err.to_string())
    }
} 
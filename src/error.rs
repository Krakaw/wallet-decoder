use thiserror::Error;

/// Result type for Tari address generator operations
pub type Result<T> = std::result::Result<T, TariError>;

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

    /// Invalid key format
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

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
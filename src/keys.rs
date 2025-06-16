use crate::error::{TariError, Result};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};
use thiserror::Error;

/// Error type for key-related operations
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),
}

/// A private key wrapper that securely handles scalar values
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    scalar: Scalar,
}

impl PrivateKey {
    /// Create a new private key from a scalar
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self { scalar }
    }

    /// Create a new private key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(TariError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        let scalar = Scalar::from_bytes_mod_order(array);
        Ok(Self::from_scalar(scalar))
    }

    /// Generate a random private key
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order(bytes);
        Self::from_scalar(scalar)
    }

    /// Get the scalar value
    pub fn as_scalar(&self) -> Scalar {
        self.scalar
    }

    /// Get the private key as bytes
    pub fn as_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// Derive the corresponding public key
    pub fn public_key(&self) -> PublicKey {
        let point = RistrettoPoint::mul_base(&self.scalar);
        PublicKey::from_ristretto_point(point)
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey([REDACTED])")
    }
}

/// A public key wrapper for Ristretto points
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    point: RistrettoPoint,
}

impl PublicKey {
    /// Create a public key from a Ristretto point
    pub fn from_ristretto_point(point: RistrettoPoint) -> Self {
        Self { point }
    }

    /// Create a public key from compressed bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(TariError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);

        // Use the correct method for creating RistrettoPoint from compressed bytes
        let compressed = curve25519_dalek::ristretto::CompressedRistretto(array);
        let point = compressed.decompress()
            .ok_or_else(|| TariError::CryptoError("Invalid compressed point".to_string()))?;
        
        Ok(Self::from_ristretto_point(point))
    }

    /// Get the Ristretto point
    pub fn as_ristretto_point(&self) -> RistrettoPoint {
        self.point
    }

    /// Get the public key as compressed bytes
    pub fn as_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }
}

/// Key manager for deriving keys using domain separation
pub struct KeyManager {
    master_key: [u8; 16],
}

impl KeyManager {
    /// Create a new key manager with master key
    pub fn new(master_key: [u8; 16]) -> Self {
        Self { master_key }
    }

    /// Derive a key using domain-separated hashing
    pub fn derive_key(&self, branch_seed: &str, key_index: u64) -> Result<PrivateKey> {
        let hash = self.key_manager_domain_separated_hash("derive_key", branch_seed, key_index)?;
        let scalar = bytes_to_scalar(&hash);
        Ok(PrivateKey::from_scalar(scalar))
    }

    /// Domain-separated hash function for key derivation
    fn key_manager_domain_separated_hash(
        &self,
        label: &str,
        branch_seed: &str,
        key_index: u64,
    ) -> Result<[u8; 64]> {
        let domain = "com.tari.base_layer.key_manager";
        let version = 1u64;
        let domain_separation_tag = format!("{}.v{}.{}", domain, version, label);

        // Use Blake2b with variable output length
        use blake2::{Blake2bVar, digest::{Update, VariableOutput}};
        let mut hasher = Blake2bVar::new(64)
            .map_err(|e| TariError::Blake2bError(e.to_string()))?;

        // Add domain separation tag
        let tag_bytes = domain_separation_tag.as_bytes();
        hasher.update(&(tag_bytes.len() as u64).to_le_bytes());
        hasher.update(tag_bytes);

        // Add master key
        hasher.update(&(self.master_key.len() as u64).to_le_bytes());
        hasher.update(&self.master_key);

        // Add branch seed
        let branch_seed_bytes = branch_seed.as_bytes();
        hasher.update(&(branch_seed_bytes.len() as u64).to_le_bytes());
        hasher.update(branch_seed_bytes);

        // Add key index
        let key_index_bytes = key_index.to_le_bytes();
        hasher.update(&(key_index_bytes.len() as u64).to_le_bytes());
        hasher.update(&key_index_bytes);

        let mut hash = [0u8; 64];
        hasher.finalize_variable(&mut hash)
            .map_err(|e| TariError::Blake2bError(e.to_string()))?;
        Ok(hash)
    }
}

impl Drop for KeyManager {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

/// Convert bytes to scalar (modulo curve order)
fn bytes_to_scalar(bytes: &[u8]) -> Scalar {
    let mut scalar = Scalar::ZERO;
    for &byte in bytes.iter().rev() {
        scalar = scalar * Scalar::from(256u64) + Scalar::from(byte as u64);
    }
    scalar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_key_generation() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        
        // Ensure keys are valid
        assert_ne!(private_key.as_bytes(), [0u8; 32]);
        assert_ne!(public_key.as_bytes(), [0u8; 32]);
    }

    #[test]
    fn test_private_key_from_bytes() {
        let bytes = [1u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        let public_key = private_key.public_key();
        
        assert_eq!(private_key.as_bytes().len(), 32);
        assert_eq!(public_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_public_key_roundtrip() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();
        let bytes = public_key.as_bytes();
        let recovered_key = PublicKey::from_bytes(&bytes).unwrap();
        
        assert_eq!(public_key, recovered_key);
    }

    #[test]
    fn test_key_manager_derivation() {
        let master_key = [1u8; 16];
        let key_manager = KeyManager::new(master_key);
        
        let spend_key = key_manager.derive_key("comms", 0).unwrap();
        let view_key = key_manager.derive_key("data encryption", 0).unwrap();
        
        // Keys should be different
        assert_ne!(spend_key.as_bytes(), view_key.as_bytes());
        
        // Same derivation should produce same key
        let spend_key2 = key_manager.derive_key("comms", 0).unwrap();
        assert_eq!(spend_key.as_bytes(), spend_key2.as_bytes());
    }

    #[test]
    fn test_key_derivation_consistency() {
        let master_key = [42u8; 16];
        let key_manager = KeyManager::new(master_key);
        
        // Test that the same inputs always produce the same output
        let key1 = key_manager.derive_key("test", 123).unwrap();
        let key2 = key_manager.derive_key("test", 123).unwrap();
        
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        
        // Test that different inputs produce different outputs
        let key3 = key_manager.derive_key("test", 124).unwrap();
        let key4 = key_manager.derive_key("other", 123).unwrap();
        
        assert_ne!(key1.as_bytes(), key3.as_bytes());
        assert_ne!(key1.as_bytes(), key4.as_bytes());
    }
} 
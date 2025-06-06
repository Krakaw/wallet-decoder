use crate::error::{TariError, Result};
use crate::wordlist;
// Removed chacha20poly1305 imports as Aead and KeyInit are not directly used here.
// ChaCha20 specific imports are used locally in functions.
use rand::RngCore;
use blake2::{Blake2bVar, digest::{Update, VariableOutput}}; // Updated blake2 imports
use zeroize::ZeroizeOnDrop;
use rand::{ SeedableRng};
use rand_chacha::ChaCha20Rng;

#[cfg(target_arch = "wasm32")]
use js_sys::Date;

#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

/// CipherSeed version
const CIPHER_SEED_VERSION: u8 = 2u8;

// Domain separation labels (V2 Style)
const HASHER_LABEL_CIPHER_SEED_ENCRYPTION_NONCE: &str = "cipher_seed_encryption_nonce";
const HASHER_LABEL_CIPHER_SEED_MAC: &str = "cipher_seed_mac";
const HASHER_LABEL_CIPHER_SEED_PBKDF_SALT: &str = "cipher_seed_pbkdf_salt";

/// Genesis timestamp for birthday calculation
const BIRTHDAY_GENESIS_FROM_UNIX_EPOCH: u64 = 1640995200; // 2022-01-01

/// Seconds per day for birthday calculation
const SECONDS_PER_DAY: u64 = 86400;

/// Default cipher seed passphrase
pub const DEFAULT_CIPHER_SEED_PASSPHRASE: &str = "TARI_CIPHER_SEED";
// Fixed sizes (all in bytes)
pub const CIPHER_SEED_BIRTHDAY_BYTES: usize = 2;
pub const CIPHER_SEED_ENTROPY_BYTES: usize = 16;
pub const CIPHER_SEED_MAIN_SALT_BYTES: usize = 5;
pub const ARGON2_SALT_BYTES: usize = 16;
pub const CIPHER_SEED_MAC_BYTES: usize = 5;
pub const CIPHER_SEED_ENCRYPTION_KEY_BYTES: usize = 32;
pub const CIPHER_SEED_MAC_KEY_BYTES: usize = 32;
pub const CIPHER_SEED_CHECKSUM_BYTES: usize = 4;

/// Represents an encrypted seed with metadata
#[derive(Clone, ZeroizeOnDrop)]
pub struct CipherSeed {
    pub version: u8,
    pub birthday: u16,
    pub entropy: [u8; 16],
    pub salt: [u8; 5],
}


pub fn get_birthday_from_unix_epoch_in_seconds(birthday: u16, to_days: u16) -> u64 {
    u64::from(birthday.saturating_sub(to_days)) * SECONDS_PER_DAY + BIRTHDAY_GENESIS_FROM_UNIX_EPOCH
}

impl CipherSeed {
    /// Generate a new cipher seed with random entropy
    pub fn new() -> Result<Self> {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut entropy = [0u8; 16];
        let mut salt = [0u8; 5];
        
        rng.fill_bytes(&mut entropy);
        rng.fill_bytes(&mut salt);
        
        let birthday = Self::calculate_birthday()?;
        
        Ok(Self {
            version: CIPHER_SEED_VERSION,
            birthday,
            entropy,
            salt,
        })
    }

    /// Create cipher seed from components
    pub fn from_components(
        version: u8,
        birthday: u16,
        entropy: [u8; 16],
        salt: [u8; 5],
    ) -> Self {
        Self {
            version,
            birthday,
            entropy,
            salt,
        }
    }

    /// Calculate current birthday (days since genesis)
    fn calculate_birthday() -> Result<u16> {
        #[cfg(target_arch = "wasm32")]
        {
            let now = Date::now() / 1000.0; // Convert to seconds
            let days = ((now as u64 - BIRTHDAY_GENESIS_FROM_UNIX_EPOCH) / SECONDS_PER_DAY) as u16;
            Ok(days)
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| TariError::InvalidTime(e.to_string()))?;
            let days = ((now.as_secs() - BIRTHDAY_GENESIS_FROM_UNIX_EPOCH) / SECONDS_PER_DAY) as u16;
            Ok(days)
        }
    }

    /// Convert cipher seed to mnemonic phrase
    pub fn to_mnemonic(&self, passphrase: Option<String>) -> Result<String> {
        // Encrypt the cipher seed
        let encrypted = self.encrypt(passphrase)?;
        
        // Convert bytes to bits using LSB-first ordering
        let mut bits_vec = Vec::with_capacity(264);
        for &byte_val in encrypted.iter() {
            for i in 0..8 { // LSB of byte first
                bits_vec.push((byte_val >> i) & 1);
            }
        }
        
        if bits_vec.len() != 264 {
             return Err(TariError::InternalError(format!(
                "Mnemonic generation: Expected 264 bits, got {}",
                bits_vec.len()
            )));
        }

        let mut words_list = Vec::with_capacity(24);
        for chunk in bits_vec.chunks(11) {
            if chunk.len() != 11 {
                 return Err(TariError::InternalError(format!(
                    "Mnemonic generation: Expected 11 bits per chunk, got {}",
                    chunk.len()
                )));
            }
            let mut index = 0u16;
            // Convert bits to word index using LSB-first ordering
            for (i, &bit_val) in chunk.iter().enumerate() {
                if bit_val != 0 {
                    index |= 1 << i; // LSB of chunk becomes LSB of 11-bit index
                }
            }
            if index >= 2048 {
                 return Err(TariError::InternalError(format!(
                    "Mnemonic generation: Invalid word index {} (must be < 2048)",
                    index
                )));
            }
            words_list.push(wordlist::get_word(index as usize)
                .ok_or_else(|| TariError::ChaCha20Error(format!("Mnemonic generation: Invalid word index {}", index)))?.to_string());
        }
        
        if words_list.len() != 24 {
             return Err(TariError::InternalError(format!(
                "Mnemonic generation: Expected 24 words, got {}",
                words_list.len()
            )));
        }
        
        Ok(words_list.join(" "))
    }

    /// Convert mnemonic phrase back to cipher seed
    pub fn from_mnemonic(mnemonic: &str, passphrase: Option<String>) -> Result<Self> {
        // Split into words and validate length
        let words_vec: Vec<&str> = mnemonic.split_whitespace().collect();
        if words_vec.len() != 24 {
            return Err(TariError::ChaCha20Error(format!(
                "Invalid mnemonic length: expected 24 words, got {}",
                words_vec.len()
            )));
        }

        // Convert words to bits
        let mut bits = Vec::with_capacity(264);
        for word_str in words_vec.iter() {
            let index = wordlist::get_index(word_str)
                .ok_or_else(|| TariError::ChaCha20Error(format!("Invalid word: {}", word_str)))?;
            // Convert index to bits, LSB first
            for i in 0..11 {
                bits.push(((index >> i) & 1) as u8);
            }
        }

        if bits.len() != 264 {
            return Err(TariError::InternalError(format!(
                "Mnemonic processing: Expected 264 bits, got {}",
                bits.len()
            )));
        }

        let mut payload_bytes = [0u8; 33];
        for (byte_idx, chunk) in bits.chunks(8).enumerate() {
            if chunk.len() != 8 {
                return Err(TariError::InternalError(format!(
                    "Mnemonic processing: Expected 8 bits per byte chunk, got {}",
                    chunk.len()
                )));
            }
            let mut byte = 0u8;
            // Convert bits to byte, LSB first
            for (bit_idx, &bit_val) in chunk.iter().enumerate() {
                if bit_val != 0 {
                    byte |= 1 << bit_idx;
                }
            }
            if byte_idx < 33 {
                payload_bytes[byte_idx] = byte;
            } else {
                return Err(TariError::InternalError("Mnemonic processing: More than 33 bytes generated".to_string()));
            }
        }

        Self::decrypt(&payload_bytes, passphrase)
    }

    /// Encrypt the cipher seed to a 33-byte array
    pub fn encrypt(&self, passphrase: Option<String>) -> Result<[u8; 33]> {
        let birthday_bytes = self.birthday.to_le_bytes();

        // Derive encryption key using Argon2
        let (encryption_key, mac_key) = self.derive_cipher_seed_keys(passphrase)?;
        
        // Calculate MAC first (MAC-then-Encrypt)
        let mac = self.calculate_mac(&mac_key)?;
        
        // Prepare plaintext: birthday(2) + entropy(16) + mac(5) = 23 bytes
        let mut plaintext = Vec::with_capacity(23);
        plaintext.extend_from_slice(&birthday_bytes);  // Use the stored bytes
        plaintext.extend_from_slice(&self.entropy);
        plaintext.extend_from_slice(&mac);

        // Generate nonce using domain-separated hash
        let nonce_full = self.domain_separated_hash(32, HASHER_LABEL_CIPHER_SEED_ENCRYPTION_NONCE, &[&self.salt])?;
        let nonce = &nonce_full[..12];

        // Use ChaCha20 to encrypt plaintext
        use chacha20::{
            cipher::{KeyIvInit, StreamCipher},
            ChaCha20,
        };
        let mut cipher = ChaCha20::new_from_slices(&encryption_key[..32], nonce)
            .map_err(|e| TariError::ChaCha20Error(e.to_string()))?;
        
        let mut ciphertext = plaintext.clone();
        cipher.apply_keystream(&mut ciphertext);

        // Prepare final payload: version(1) + ciphertext(23) + salt(5) + crc(4)
        let mut payload = Vec::with_capacity(33);
        payload.push(CIPHER_SEED_VERSION);
        payload.extend_from_slice(&ciphertext[..23]);
        payload.extend_from_slice(&self.salt);

        // Calculate CRC32 over the first 29 bytes (version + ciphertext + salt)
        let crc = crc32fast::hash(&payload);
        payload.extend_from_slice(&crc.to_le_bytes());

        let mut result = [0u8; 33];
        result.copy_from_slice(&payload);
        Ok(result)
    }

    /// Apply ChaCha20 stream cipher to data using key and salt
    fn apply_cipher_seed_stream_cipher(data: &mut [u8], key: &[u8], salt: &[u8]) -> Result<()> {
        // Generate nonce using domain-separated hash
        let nonce_full = Self::domain_separated_hash_static(32, HASHER_LABEL_CIPHER_SEED_ENCRYPTION_NONCE, &[salt])?;
        let nonce = &nonce_full[..12]; // ChaCha20 uses 12-byte nonce

        // Use ChaCha20
        use chacha20::{
            cipher::{KeyIvInit, StreamCipher},
            ChaCha20,
        };
        let mut cipher = ChaCha20::new_from_slices(&key[..32], nonce)
            .map_err(|e| TariError::ChaCha20Error(e.to_string()))?;
        
        cipher.apply_keystream(data);
        Ok(())
    }

    /// Decrypt a 33-byte encrypted cipher seed
    pub fn decrypt(encrypted_data: &[u8; 33], passphrase: Option<String>) -> Result<Self> {
        // Check the length: version, ciphertext, salt, checksum
        if encrypted_data.len() != 33 {
            return Err(TariError::ChaCha20Error("Invalid seed length".to_string()));
        }

        // We only support one version right now
        let version = encrypted_data[0];
        if version != CIPHER_SEED_VERSION {
            return Err(TariError::ChaCha20Error("Version mismatch".to_string()));
        }

        let mut encrypted_data = encrypted_data.to_vec();

        // Verify the checksum first, to detect obvious errors
        let checksum = encrypted_data.split_off(
            1 + CIPHER_SEED_BIRTHDAY_BYTES +
                CIPHER_SEED_ENTROPY_BYTES +
                CIPHER_SEED_MAC_BYTES +
                CIPHER_SEED_MAIN_SALT_BYTES,
        );

        // Verify the checksum first, to detect obvious errors
        let mut crc_hasher = crc32fast::Hasher::new();
        crc_hasher.update(encrypted_data.as_slice());
        let expected_checksum = crc_hasher.finalize().to_le_bytes();
        if !Self::timing_safe_equal(&checksum, &expected_checksum) {
            return Err(TariError::ChaCha20Error("CRC failed".to_string()));
        }

        let salt: [u8; CIPHER_SEED_MAIN_SALT_BYTES] = encrypted_data
        .split_off(1 + CIPHER_SEED_BIRTHDAY_BYTES + CIPHER_SEED_ENTROPY_BYTES + CIPHER_SEED_MAC_BYTES)
        .try_into()
        .unwrap();

        // Original key derivation (for actual decryption)
        // 'salt' here is the original salt from payload
        let (encryption_key_for_decryption, _mac_key_original_salt) = Self::derive_cipher_seed_keys_static(passphrase.clone(), &salt)?; // Clone passphrase

        // Decrypt the ciphertext: birthday + entropy + MAC
        let mut ciphertext = encrypted_data.split_off(1); // Remove version byte
        Self::apply_cipher_seed_stream_cipher(&mut ciphertext, &encryption_key_for_decryption, &salt)?; // Use encryption_key_for_decryption

       
        // Parse decrypted data
        let mac = ciphertext.split_off(CIPHER_SEED_BIRTHDAY_BYTES + CIPHER_SEED_ENTROPY_BYTES);
        let entropy = ciphertext.split_off(CIPHER_SEED_BIRTHDAY_BYTES);
        let mut birthday_bytes = [0u8; CIPHER_SEED_BIRTHDAY_BYTES];
        birthday_bytes.copy_from_slice(&ciphertext); // These are original LE birthday_bytes

        // Use original, non-reversed birthday and entropy for MAC check and struct population
        let birthday_val = u16::from_le_bytes(birthday_bytes); // birthday_val from original LE bytes

        // Verify MAC using ORIGINAL birthday, ORIGINAL entropy,
        // original salt, and mac_key derived from original salt.
        // Hashing logic in calculate_mac_static is direct concat for MACs.
        // Domain prefix for all hashes is now "com.tari.base_layer.key_manager."
        let expected_mac = Self::calculate_mac_static(version, &birthday_bytes, &entropy, &salt, &_mac_key_original_salt)?;
        if !Self::timing_safe_equal(&mac, &expected_mac[..5]) {
            return Err(TariError::ChaCha20Error("MAC failed".to_string()));
        }

        Ok(Self {
            version,
            birthday: birthday_val, // Use birthday from original LE bytes
            entropy: entropy.try_into().unwrap(), // Use original entropy
            salt,
        })
    }

    /// Derive cipher seed encryption keys using domain-separated hash
    fn derive_cipher_seed_keys(&self, passphrase: Option<String>) -> Result<([u8; 32], [u8; 32])> {
        let passphrase = passphrase.unwrap_or(DEFAULT_CIPHER_SEED_PASSPHRASE.to_string());
        let salt_hash = self.domain_separated_hash(32, HASHER_LABEL_CIPHER_SEED_PBKDF_SALT, &[&self.salt])?;
        let argon_salt = &salt_hash[..16];
        
        // Use Argon2 for key derivation
        use argon2::{Argon2, Params};
        let params = Params::new(46 * 1024, 1, 1, Some(64))
            .map_err(|e| TariError::Argon2Error(e.to_string()))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2d, argon2::Version::V0x13, params); // Reverted to V0x13
        
        let mut output = [0u8; 64];
        argon2
            .hash_password_into(passphrase.as_bytes(), argon_salt, &mut output)
            .map_err(|e| TariError::Argon2Error(e.to_string()))?;
        
        let mut encryption_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        encryption_key.copy_from_slice(&output[..32]);
        mac_key.copy_from_slice(&output[32..]);
        
        Ok((encryption_key, mac_key))
    }

    /// Calculate MAC using Blake2b with key (via domain_separated_hash)
    fn calculate_mac(&self, mac_key: &[u8; 32]) -> Result<[u8; 5]> {
        let result = self.domain_separated_hash(
            32,
            HASHER_LABEL_CIPHER_SEED_MAC,
            &[
                &[self.version],                   // version first
                &self.birthday.to_le_bytes()[..2], // then birthday
                &self.entropy,                     // then entropy
                &self.salt,                        // then salt
                mac_key,                          // then mac_key
            ]
        )?;

        let mut mac = [0u8; 5];
        mac.copy_from_slice(&result[..5]);

        Ok(mac)
    }

    /// Domain-separated hash function
    fn domain_separated_hash(
        &self,
        hash_size: usize,
        label: &str, // V2 style label
        data: &[&[u8]],
    ) -> Result<Vec<u8>> {
        // Call the static version to ensure logic is identical and centralized
        Self::domain_separated_hash_static(hash_size, label, data)
    }

    /// Get the master key (entropy) for key derivation
    pub fn master_key(&self) -> [u8; 16] {
        self.entropy
    }

    // Helper functions for static methods
    fn derive_cipher_seed_keys_static(passphrase: Option<String>, salt: &[u8; 5]) -> Result<([u8; 32], [u8; 32])> {
        let passphrase = passphrase.unwrap_or(DEFAULT_CIPHER_SEED_PASSPHRASE.to_string());
        let salt_hash = Self::domain_separated_hash_static(32, HASHER_LABEL_CIPHER_SEED_PBKDF_SALT, &[salt])?;
        let argon_salt = &salt_hash[..16];
        
        use argon2::{Argon2, Params};
        let params = Params::new(46 * 1024, 1, 1, Some(64))
            .map_err(|e| TariError::Argon2Error(e.to_string()))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2d, argon2::Version::V0x13, params); // Reverted to V0x13
        
        let mut output = [0u8; 64];
        argon2
            .hash_password_into(passphrase.as_bytes(), argon_salt, &mut output)
            .map_err(|e| TariError::Argon2Error(e.to_string()))?;
        
        let mut encryption_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        encryption_key.copy_from_slice(&output[..32]);
        mac_key.copy_from_slice(&output[32..]);
        
        Ok((encryption_key, mac_key))
    }

    // V2 domain_separated_hash_static logic
    fn domain_separated_hash_static(hash_size: usize, label: &str, data: &[&[u8]]) -> Result<Vec<u8>> {
        let mut hasher = Blake2bVar::new(hash_size)
            .map_err(|e| TariError::Blake2bError(e.to_string()))?;

        // let domain_prefix = "com.tari.base_layer.key_manager."; // Keep this commented or remove
        let full_domain_tag = format!("com.tari.base_layer.key_manager.v1.{}", label); // Changed to v1

        hasher.update(&(full_domain_tag.as_bytes().len() as u64).to_le_bytes());
        hasher.update(full_domain_tag.as_bytes());

        // Revert to always using length-prefixing for all components
        for component_slice in data.iter() {
            let actual_slice: &[u8] = *component_slice;
            hasher.update(&(actual_slice.len() as u64).to_le_bytes());
            hasher.update(actual_slice);
        }

        let mut result = vec![0u8; hash_size];
        hasher.finalize_variable(&mut result)
            .map_err(|e| TariError::Blake2bError(e.to_string()))?;
        Ok(result)
    }

    fn calculate_mac_static(version: u8, birthday_bytes: &[u8], entropy: &[u8], salt: &[u8], mac_key: &[u8]) -> Result<[u8; 5]> {
        if birthday_bytes.len() != 2 {
            return Err(TariError::InternalError("Birthday bytes must be 2 bytes long for MAC calculation".to_string()));
        }
        
        let result = Self::domain_separated_hash_static(
            32,
            HASHER_LABEL_CIPHER_SEED_MAC,
            &[
                &[version],      // version first
                birthday_bytes,  // then birthday
                entropy,         // then entropy
                salt,           // then salt
                mac_key,        // then mac_key
            ]
        )?;
        
        let mut mac = [0u8; 5];
        mac.copy_from_slice(&result[..5]);
        
        Ok(mac)
    }

    // Helper function for constant-time comparison
    fn timing_safe_equal(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }
}

impl Default for CipherSeed {
    fn default() -> Self {
        Self::new().expect("Failed to generate default cipher seed")
    }
}

impl std::fmt::Debug for CipherSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherSeed")
            .field("version", &self.version)
            .field("birthday", &self.birthday)
            .field("entropy", &"[REDACTED]")
            .field("salt", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_seed_creation() {
        let seed = CipherSeed::new().unwrap();
        assert_eq!(seed.version, CIPHER_SEED_VERSION);
        assert_ne!(seed.entropy, [0u8; 16]);
        assert_ne!(seed.salt, [0u8; 5]);
    }

    #[test]
    fn test_cipher_seed_encryption() {
        let seed = CipherSeed::new().unwrap();
        let encrypted = seed.encrypt(None).unwrap();
        assert_eq!(encrypted.len(), 33);
    }

    #[test]
    fn test_master_key() {
        let seed = CipherSeed::new().unwrap();
        let master_key = seed.master_key();
        assert_eq!(master_key, seed.entropy);
    }

    #[test]
    fn test_mnemonic_conversion() {
        let seed = CipherSeed::new().unwrap();
        let mnemonic = seed.to_mnemonic(None).unwrap();
        let mnemonic_vec = mnemonic.split_whitespace().collect::<Vec<&str>>();

        // Should generate 24 words
        assert_eq!(mnemonic_vec.len(), 24);
    }
}
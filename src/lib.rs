//! # Tari Address Generator
//!
//! A Rust library for generating and managing Tari wallet addresses with support for:
//! - Multiple networks (MainNet, NextNet, Esmeralda)
//! - Multiple address formats (Base58, Emoji)
//! - Seed phrase generation and restoration
//! - Payment ID integration
//! - RFC-0155 TariAddress specification compliance
//!
//! ## Example
//!
//! ```rust
//! use tari_address_generator::{TariAddressGenerator, Network};
//!
//! // Generate a new address
//! let generator = TariAddressGenerator::new();
//! let wallet = generator.generate_new_wallet(Network::MainNet).unwrap();
//! 
//! println!("Address: {}", wallet.address_base58());
//! println!("Emoji: {}", wallet.address_emoji());
//! println!("Seed: {}", wallet.seed_phrase());
//! ```

pub mod address;
pub mod checksum;
pub mod cipher_seed;
pub mod emoji;
pub mod error;
pub mod keys;
pub mod network;
pub mod wallet;
pub mod wordlist;
pub mod utils;

#[cfg(feature = "wasm-bindgen")]
pub mod wasm;

pub use address::{TariAddress, AddressFeatures};
pub use cipher_seed::CipherSeed;
pub use error::{TariError, Result};
pub use keys::{PrivateKey, PublicKey, KeyManager};
pub use network::Network;
pub use wallet::{TariWallet, TariAddressGenerator};
pub use utils::bytes_to_ascii_string;

// Re-export commonly used types
pub use bip39::Mnemonic;
pub use curve25519_dalek::ristretto::RistrettoPoint;
pub use curve25519_dalek::scalar::Scalar; 
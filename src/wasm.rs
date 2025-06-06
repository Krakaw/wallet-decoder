use wasm_bindgen::prelude::*;
use crate::{TariAddressGenerator, Network, TariWallet, TariAddress};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::cell::RefCell;

thread_local! {
    static RNG: RefCell<Option<ChaCha20Rng>> = RefCell::new(None);
}

#[wasm_bindgen]
pub fn init() {
    // Initialize panic hook for better error messages
    console_error_panic_hook::set_once();
    
    // Initialize random number generator with a fixed seed for WASM
    let rng = ChaCha20Rng::seed_from_u64(0x1234567890abcdef);
    RNG.with(|r| *r.borrow_mut() = Some(rng));
}

#[wasm_bindgen]
pub struct WasmTariAddressGenerator {
    generator: TariAddressGenerator,
}

#[wasm_bindgen]
impl WasmTariAddressGenerator {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmTariAddressGenerator, JsValue> {
        init();
        Ok(WasmTariAddressGenerator {
            generator: TariAddressGenerator::new(),
        })
    }

    /// Generate a new wallet for the specified network
    #[wasm_bindgen]
    pub fn generate_new_wallet(&self, network: &str) -> Result<WasmTariWallet, JsValue> {
        let network = match network {
            "mainnet" => Network::MainNet,
            "nextnet" => Network::NextNet,
            "esmeralda" => Network::Esmeralda,
            _ => return Err(JsValue::from_str("Invalid network. Must be 'mainnet', 'nextnet', or 'esmeralda'")),
        };

        let wallet = self.generator.generate_new_wallet(network)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(WasmTariWallet { wallet })
    }

    /// Restore a wallet from a seed phrase
    #[wasm_bindgen]
    pub fn restore_from_seed_phrase(&self, seed_phrase: &str, network: &str) -> Result<WasmTariWallet, JsValue> {
        let network = match network {
            "mainnet" => Network::MainNet,
            "nextnet" => Network::NextNet,
            "esmeralda" => Network::Esmeralda,
            _ => return Err(JsValue::from_str("Invalid network. Must be 'mainnet', 'nextnet', or 'esmeralda'")),
        };

        let wallet = self.generator.restore_from_seed_phrase(seed_phrase, network)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(WasmTariWallet { wallet })
    }

    /// Parse an address from string (auto-detects format)
    #[wasm_bindgen]
    pub fn parse_address(&self, address: &str) -> Result<WasmTariAddress, JsValue> {
        let address = self.generator.parse_address(address)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(WasmTariAddress { address })
    }

    /// Validate a seed phrase
    #[wasm_bindgen]
    pub fn validate_seed_phrase(&self, seed_phrase: &str) -> bool {
        self.generator.validate_seed_phrase(seed_phrase)
    }
}

#[wasm_bindgen]
pub struct WasmTariWallet {
    wallet: TariWallet,
}

#[wasm_bindgen]
impl WasmTariWallet {
    fn new(wallet: TariWallet) -> Self {
        Self { wallet }
    }

    /// Get the address in Base58 format
    #[wasm_bindgen]
    pub fn address_base58(&self) -> String {
        self.wallet.address_base58()
    }

    /// Get the address in emoji format
    #[wasm_bindgen]
    pub fn address_emoji(&self) -> String {
        self.wallet.address_emoji()
    }

    /// Get the seed phrase
    #[wasm_bindgen]
    pub fn seed_phrase(&self) -> String {
        self.wallet.seed_phrase().to_string()
    }

    /// Get the network as a string
    #[wasm_bindgen]
    pub fn network(&self) -> String {
        match self.wallet.network() {
            Network::MainNet => "mainnet",
            Network::NextNet => "nextnet",
            Network::Esmeralda => "esmeralda",
        }.to_string()
    }

    #[wasm_bindgen]
    pub fn new_address_with_payment_id(&self, payment_id: &str) -> Result<WasmTariAddress, JsValue> {
        let address = self.wallet.create_integrated_address(payment_id.as_bytes().to_vec())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(WasmTariAddress { address })
    }

    /// Get the view private key as hex string
    #[wasm_bindgen]
    pub fn view_private_key_hex(&self) -> String {
        self.wallet.view_private_key_hex()
    }

    /// Get the spend private key as hex string
    #[wasm_bindgen]
    pub fn spend_private_key_hex(&self) -> String {
        self.wallet.spend_private_key_hex()
    }

    /// Get the view public key as hex string
    #[wasm_bindgen]
    pub fn view_public_key_hex(&self) -> String {
        self.wallet.view_public_key_hex()
    }

    /// Get the spend public key as hex string
    #[wasm_bindgen]
    pub fn spend_public_key_hex(&self) -> String {
        self.wallet.spend_public_key_hex()
    }
}

#[wasm_bindgen]
pub struct WasmTariAddress {
    address: TariAddress,
}

#[wasm_bindgen]
impl WasmTariAddress {
    fn new(address: TariAddress) -> Self {
        Self { address }
    }

    /// Get the address in Base58 format
    #[wasm_bindgen]
    pub fn to_base58(&self) -> String {
        self.address.to_base58()
    }

    /// Get the address in emoji format
    #[wasm_bindgen]
    pub fn to_emoji(&self) -> String {
        self.address.to_emoji()
    }

    /// Get the network as a string
    #[wasm_bindgen]
    pub fn network(&self) -> String {
        match self.address.network() {
            Network::MainNet => "mainnet",
            Network::NextNet => "nextnet",
            Network::Esmeralda => "esmeralda",
        }.to_string()
    }

    /// Check if the address has a payment ID
    #[wasm_bindgen]
    pub fn has_payment_id(&self) -> bool {
        self.address.features().has_payment_id()
    }

    /// Get the payment ID if present
    #[wasm_bindgen]
    pub fn payment_id(&self) -> Option<Vec<u8>> {
        self.address.payment_id().map(|id| id.to_vec())
    }
}

// Enable console logging in WASM
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
} 
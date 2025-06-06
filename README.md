# Tari Address Generator

A powerful tool for generating and managing Tari wallet addresses with support for multiple networks and formats. This project provides both a command-line interface and a web interface for generating, decoding, and managing Tari addresses.

## Demo

[https://krakaw.github.io/wallet-decoder](https://krakaw.github.io/wallet-decoder)

[https://krakaw.github.io/wallet-decoder?address=16Fkc9oBPMMFFHwFoGnFPsK5gWqtZUbtrg8hrHX7K32sy4J1kTbTsV3SuYDeCVJvMRb3Ko1yXu2zSHMpEV54XuKjnC5YA8rGEWDTNJ7jCdDENGifpoLnk](https://krakaw.github.io/wallet-decoder?address=16Fkc9oBPMMFFHwFoGnFPsK5gWqtZUbtrg8hrHX7K32sy4J1kTbTsV3SuYDeCVJvMRb3Ko1yXu2zSHMpEV54XuKjnC5YA8rGEWDTNJ7jCdDENGifpoLnk)


[https://krakaw.github.io/wallet-decoder?tab=generate](https://krakaw.github.io/wallet-decoder?tab=generate)


## Features

- Generate new Tari wallets
- Restore wallets from seed phrases
- Support for multiple networks:
  - MainNet
  - NextNet
  - Esmeralda
- Multiple address formats:
  - Base58
  - Emoji
- Payment ID integration
- RFC-0155 TariAddress specification compliance
- Web interface for easy address management
- Command-line interface for automation

## Web Interface

The web interface provides an intuitive way to:
- Decode Tari addresses
- Generate new wallets
- Restore wallets from seed phrases
- Add payment IDs to addresses
- View wallet details including:
  - Base58 and Emoji addresses
  - Seed phrases
  - Private and public keys
  - Network information

## Command Line Interface

The CLI provides the following commands:

```bash
# Generate a new wallet
wallet-decoder generate [--network NETWORK] [--password PASSWORD] [--payment-id PAYMENT_ID]

# Decode a Tari address
wallet-decoder decode <ADDRESS>

# Load a wallet from seed phrase
wallet-decoder load <SEED_PHRASE> [--network NETWORK] [--password PASSWORD] [--payment-id PAYMENT_ID]
```

### Options

- `--network`: Network to use (mainnet, nextnet, esmeralda) [default: mainnet]
- `--password`: Optional password for the wallet
- `--payment-id`: Optional payment ID to include in the address

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/Krakaw/wallet-decoder.git
cd wallet-decoder

# Build the project
cargo build --release

# Install the binary
cargo install --path .
```

### Web Interface

To run the web interface locally:

1. Build the WASM module:
```bash
wasm-pack build --target web
```

2. Serve the web interface:
```bash
cd examples/web
python3 -m http.server 8080
```

Then open `http://localhost:8080` in your browser.

## Usage Examples

### Generate a New Wallet

```rust
use tari_address_generator::{TariAddressGenerator, Network};

let generator = TariAddressGenerator::new();
let wallet = generator.generate_new_wallet(Network::MainNet)?;

println!("Address: {}", wallet.address_base58());
println!("Emoji: {}", wallet.address_emoji());
println!("Seed: {}", wallet.seed_phrase());
```

### Restore from Seed Phrase

```rust
let wallet = generator.restore_from_seed_phrase("your seed phrase here", Network::MainNet)?;
```

### Parse an Address

```rust
let address = generator.parse_address("your address here")?;
println!("Network: {}", address.network());
println!("Base58: {}", address.to_base58());
println!("Emoji: {}", address.to_emoji());
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security

This project is for educational and development purposes. Always use official Tari tools for production use. 
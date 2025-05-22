# Tari Wallet Decoder

A WebAssembly-based tool for decoding Tari wallet addresses and managing Tari wallets. This project provides both web and Node.js examples of how to use the decoder.

## Features

- Generate new Tari wallets
- Load existing wallets from seed phrases
- Decode Tari addresses
- Support for multiple networks (mainnet, nextnet, esmeralda)
- Password protection for wallets

## Building

First, build the WebAssembly package for both web and Node.js targets:

```bash
# Build for web
wasm-pack build --target web

# Build for Node.js
wasm-pack build --target nodejs
```

## Usage

### Command Line Interface

The tool provides a command-line interface with the following commands:

1. Generate a new wallet:
```bash
wallet-decoder generate-wallet [--password <PASSWORD>] [--network <NETWORK>]
```

2. Load a wallet from seed phrase:
```bash
wallet-decoder load-seed-phrase <SEED_PHRASE> [--password <PASSWORD>] [--network <NETWORK>]
```

3. Decode a Tari address:
```bash
wallet-decoder decode-address <ADDRESS>
```

Options:
- `--password`: Optional password for wallet encryption
- `--network`: Network to use (mainnet, nextnet, esmeralda). Defaults to mainnet

### Examples

Generate a new wallet:
```bash
wallet-decoder generate-wallet --network mainnet
```

Load a wallet from seed phrase:
```bash
wallet-decoder load-seed-phrase "your seed phrase here" --network mainnet
```

Decode an address:
```bash
wallet-decoder decode-address "143BKvG9pF8uSpB2JrB6myLMJLjjjrAPzcUyaBWpWoYW3x3Vv1EncTVTSGpdRhvucBzGisRj17tQyfg6vkGWKGjvUxZ"
```

### Web Example

The web example provides a user-friendly interface to decode Tari addresses.

1. Navigate to the web example directory:
```bash
cd examples/web
```

2. Start a local web server (using Python as an example):
```bash
python3 -m http.server 8080
```

3. Open your browser and navigate to `http://localhost:8080`

The web interface allows you to:
- Input a Tari address
- View the decoded information including:
  - Base58 representation
  - Emoji representation
  - Hex representation
  - Network information
  - Features
  - Public keys
  - Address type
  - Payment ID (if present)

You can also pre-fill addresses using URL query parameters. For example:
```
http://localhost:8080?address=addr1&address=addr2&address=addr3
```
This will automatically decode and display multiple addresses on the page. Each address will be shown in its own card with selectable values.

### Node.js Example

The Node.js example demonstrates how to use the decoder programmatically.

1. Navigate to the Node.js example directory:
```bash
cd examples/node
```

2. Run the example:
```bash
node index.js
```

The example will decode a sample Tari address and display the decoded information in a formatted JSON structure.

## Requirements

- Rust and wasm-pack for building
- Node.js 14+ for the Node.js example
- A modern web browser with WebAssembly support for the web example
- Python 3+ (or any web server) for serving the web example

## Project Structure

```
.
├── src/
│   ├── lib.rs           # Core Rust implementation
│   ├── wallet.rs        # Wallet management functionality
│   ├── address.rs       # Address decoding functionality
│   └── utils.rs         # Utility functions
├── examples/
│   ├── web/            # Web example
│   │   ├── index.html  # Web interface
│   │   └── index.js    # Web JavaScript implementation
│   └── node/           # Node.js example
│       └── index.js    # Node.js implementation
└── pkg/                # Generated WebAssembly package
```

## Live Demo

Visit the [live demo](https://krakaw.github.io/wallet-decoder/) to try out the decoder.

## Prerequisites

- Rust and Cargo
- wasm-pack (`cargo install wasm-pack`)
- A web server (for local testing)

## Local Development

1. Install the required tools:
```bash
cargo install wasm-pack
```

2. Build the WebAssembly module:
```bash
wasm-pack build --target web
```

3. Copy the built files to the docs directory:
```bash
mkdir -p docs
cp -r pkg/* docs/
cp index.html docs/
```

4. Serve the files using a web server. For example, using Python:
```bash
cd docs
python3 -m http.server
```

5. Open `http://localhost:8000` in your web browser.

## License

This project is licensed under the MIT License. 
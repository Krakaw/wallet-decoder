# Tari Wallet Decoder

A WebAssembly-based tool for decoding Tari wallet addresses. This project provides both web and Node.js examples of how to use the decoder.

## Building

First, build the WebAssembly package for both web and Node.js targets:

```bash
# Build for web
wasm-pack build --target web

# Build for Node.js
wasm-pack build --target nodejs
```

## Examples

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
│   └── lib.rs           # Core Rust implementation
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

## Deployment

The project is automatically deployed to GitHub Pages when changes are pushed to the main branch. The deployment process:

1. Builds the WASM module
2. Copies the built files to the docs directory
3. Deploys the contents to the gh-pages branch

To enable GitHub Pages:
1. Go to your repository settings
2. Navigate to "Pages" in the sidebar
3. Select "Deploy from a branch" as the source
4. Select the "gh-pages" branch and "/docs (docs)" folder
5. Click Save

## Usage

The module exposes a single function `decode_tari_address` that takes a Tari address string and returns a JSON object with the following information:

- `base58`: The address in base58 format
- `emoji`: The address in emoji format
- `hex`: The address in hexadecimal format
- `raw_bytes`: The raw bytes of the address
- `network`: The network type
- `network_byte`: The network byte
- `features`: Object containing address features
  - `features_byte`: The features byte
  - `one_sided`: Whether it's a one-sided address
  - `interactive`: Whether it's an interactive address
  - `payment_id`: Whether it has a payment ID
- `public_spend_key`: The public spend key in hex
- `public_view_key`: The public view key in hex (if present)
- `address_type`: The type of address (Single or Dual)
- `payment_id`: The payment ID in hex (if present)

### JavaScript Example

```javascript
import init, { decode_tari_address } from './wallet_decoder.js';

async function decodeAddress(address) {
    try {
        await init();
        const info = await decode_tari_address(address);
        console.log(info);
    } catch (error) {
        console.error('Error:', error);
    }
}
```

## Development

The project is structured as follows:

- `src/lib.rs`: Contains the main WASM module code
- `index.html`: A simple web interface for testing the decoder
- `Cargo.toml`: Project dependencies and configuration
- `.github/workflows/deploy.yml`: GitHub Actions workflow for automatic deployment
- `docs/`: Directory containing the built files for deployment

## License

This project is licensed under the MIT License. 
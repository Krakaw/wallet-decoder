# Tari Wallet Decoder

A WebAssembly module for decoding Tari wallet addresses and extracting their information.

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
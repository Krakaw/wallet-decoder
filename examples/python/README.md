# Tari Address Decoder

A standalone Python script that decodes Tari addresses in various formats (Base58, emoji, hex) and outputs detailed information in JSON format.

## Features

- **Multi-format support**: Decodes Base58, emoji, and hex encoded Tari addresses
- **Comprehensive output**: Provides detailed information about network, features, keys, and payment IDs
- **Checksum validation**: Verifies address integrity using the Damm checksum algorithm
- **JSON output**: Structured output for easy integration with other tools
- **Cross-format conversion**: Shows the same address in all supported formats

## Installation

1. Ensure you have Python 3.6+ installed
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

```bash
python3 tari_address_decoder.py <address>
```

### Examples

**Hex address:**
```bash
python3 tari_address_decoder.py "0001fc9e9cb2bd8f1e4cf70c1104545622cb84a9b2dd19735d20575d761d6ba9936280dd789fee2ae68aa63f09a78ccc2938cdaec33ecc909c1f86a9f654bdf15538d5"
```

**Base58 address:**
```bash
python3 tari_address_decoder.py "12PHyR5CePL5jyoevS6BbSjV2WnNgVcmaqgZA9NqPJd3894YFzCCSHn9Auvpai1LT4LKJxH2c7yyiwuxqdkxYjACrPn"
```

**Emoji address:**
```bash
python3 tari_address_decoder.py "🐢📟🚲💃👘💍💩🐻🍍🎧🚦🌴🌻🎯🎱🎳🍒📿🐮👾💍🔭🍈🐔🎼🍐🎵🎼🐘🍌🐀👾👀🏁🦀🔭🐚👛🚂🥝😎🐵🤡🎂⭐👻🐷📡🍟🍷⏰💉💺🎁📡🐼👘🍎🐰👾🚢🎱💩🚒🎲🍷🔥"
```

## Output Format

The script outputs a JSON object with the following structure:

```json
{
  "input": {
    "address": "original_input_address",
    "format": "detected_format"
  },
  "valid": true,
  "error": null,
  "decoded": {
    "network": {
      "name": "MainNet",
      "byte_value": "0x00",
      "base58_prefix": "T",
      "emoji_prefix": "🐢"
    },
    "features": {
      "byte_value": "0x01",
      "active_features": ["ONE_SIDED"],
      "details": {
        "one_sided": true,
        "interactive": false,
        "payment_id": false
      }
    },
    "address_type": "Dual Address",
    "keys": {
      "spend_key": {
        "hex": "hex_representation",
        "bytes": [array_of_bytes]
      },
      "view_key": {
        "hex": "hex_representation",
        "bytes": [array_of_bytes]
      }
    },
    "payment_id": {
      "hex": "hex_representation",
      "bytes": [array_of_bytes],
      "ascii": "ascii_string",
      "length": 123
    },
    "size": {
      "total_bytes": 67,
      "is_single_address": false
    },
    "encodings": {
      "hex": "hex_format",
      "base58": "base58_format",
      "emoji": "emoji_format"
    }
  }
}
```

## Supported Networks

- **MainNet** (0x00): Base58 prefix 'T', Emoji prefix 🐢
- **NextNet** (0x02): Base58 prefix 't', Emoji prefix ⏩
- **Esmeralda** (0x26): Base58 prefix 'e', Emoji prefix 💎

## Address Types

- **Single Address**: Contains only a spend key (35 bytes)
- **Dual Address**: Contains both view and spend keys (67+ bytes)

## Address Features

- **ONE_SIDED** (0x01): One-sided payment support
- **INTERACTIVE** (0x02): Interactive payment support
- **PAYMENT_ID** (0x04): Contains payment ID data

## Error Handling

If the address is invalid, the script returns:

```json
{
  "input": {
    "address": "invalid_address",
    "format": "detected_format"
  },
  "valid": false,
  "error": "Error description",
  "decoded": {}
}
```

## Dependencies

- `base58==2.1.1`: For Base58 encoding/decoding

## Implementation Details

- **Checksum Algorithm**: Uses the Damm algorithm with polynomial coefficients [4, 3, 1]
- **Emoji Mapping**: Maps byte values 0-255 to specific emoji characters
- **Address Structure**: Follows the Tari protocol specification for address encoding

## License

This script is part of the Tari wallet decoder project and follows the same licensing terms. 
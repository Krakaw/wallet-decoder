# Tari Wallet Decoder

A command-line tool for decoding and analyzing Tari cryptocurrency addresses. This tool provides detailed information about Tari addresses including their binary representation, network information, features, and key details.

## Features

- Decode Tari addresses in Base58 format
- Display address in multiple formats (Base58, Emoji, Hex)
- Show binary representation and length
- Display network information
- List address features (One-sided, Interactive, Payment ID)
- Show public spend and view keys
- Identify address type (Single or Dual)
- Display payment ID data if present

## Installation

```bash
git clone https://github.com/yourusername/wallet-decoder.git
cd wallet-decoder
cargo build --release
```

## Usage

```bash
cargo run -- <tari_address>
```

### Example

```bash
cargo run -- "143BKvG9pF8uSpB2JrB6myLMJLjjjrAPzcUyaBWpWoYW3x3Vv1EncTVTSGpdRhvucBzGisRj17tQyfg6vkGWKGjvUxZ"
```

### Example Output

```
=== Tari Address Details ===
Base58: 143BKvG9pF8uSpB2JrB6myLMJLjjjrAPzcUyaBWpWoYW3x3Vv1EncTVTSGpdRhvucBzGisRj17tQyfg6vkGWKGjvUxZ
Emoji: 🐢🌊🍇💉🙈📖💋🎠🔦💉🦁👣🚫🍊🎂🚨🏠🐜📿🌽💯🐭🚫🚨🍁🍦🍭🐘🐸👂🚓💻🎯🎺🎤💨🚦🐬🎁🧲💼🐙🐬🍪🐔👾📜🌹🍞👟👶👣🚓🐬🏠🍊💻🎷🌕🚀🎬👞👞🌙🍵🍋🤠
Hex: 000318ae74cab046d6ae70a5fb1b3ff9667acb12bf83fbf9142c31768db1f2c4045b4abcf7823effc577822e73a9c71028a1eba5f282661bc45808ec50a0a006361caa

=== Binary Representation ===
Raw bytes: [00, 03, 18, ae, 74, ca, b0, 46, d6, ae, 70, a5, fb, 1b, 3f, f9, 66, 7a, cb, 12, bf, 83, fb, f9, 14, 2c, 31, 76, 8d, b1, f2, c4, 04, 5b, 4a, bc, f7, 82, 3e, ff, c5, 77, 82, 2e, 73, a9, c7, 10, 28, a1, eb, a5, f2, 82, 66, 1b, c4, 58, 08, ec, 50, a0, a0, 06, 36, 1c, aa]
Length: 67 bytes

=== Network Information ===
Network: MainNet
Network byte: 0x00

=== Features ===
Features byte: 0x03
One-sided: true
Interactive: true
Payment ID: false

=== Key Information ===
Public Spend Key: 4abcf7823effc577822e73a9c71028a1eba5f282661bc45808ec50a0a006361c
Public View Key: 18ae74cab046d6ae70a5fb1b3ff9667acb12bf83fbf9142c31768db1f2c4045b

=== Address Type ===
Type: Dual Address
```

## Output Explanation

The tool provides several sections of information:

1. **Tari Address Details**: Shows the address in Base58, Emoji, and Hex formats
2. **Binary Representation**: Displays the raw bytes and total length
3. **Network Information**: Shows the network type (MainNet/TestNet) and network byte
4. **Features**: Lists enabled features (One-sided, Interactive, Payment ID)
5. **Key Information**: Shows the public spend and view keys
6. **Address Type**: Indicates whether it's a Single or Dual address
7. **Payment ID Data**: (Optional) Shows payment ID data if present

## Requirements

- Rust 1.56.0 or later
- Cargo package manager

## License

[Add your license here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 
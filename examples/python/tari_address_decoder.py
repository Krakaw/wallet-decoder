#!/usr/bin/env python3
"""
Tari Address Decoder

A standalone Python script to decode Tari addresses in various formats
(Base58, emoji, hex) and output detailed information in JSON format.

Usage:
    python tari_address_decoder.py <address>

Examples:
    python tari_address_decoder.py "12PHyR5CePL5jyoevS6BbSjV2WnNgVcmaqgZA9NqPJd3894YFzCCSHn9Auvpai1LT4LKJxH2c7yyiwuxqdkxYjACrPn"
    python tari_address_decoder.py "🐢📟⭐🌙🤔🌕⭐🎋🌰🌴🌵🌲🌸🌹🌻🌽🍀🍁🍄🥑🍆🍇🍈🍉🍊🍋🍌🍍🍎🍐🍑🍒🍓🍔🍕🍗🍚🍞🍟🥝🍣🍦🍩🍪🍫🍬🍭🍯🥐🍳🥄🍵🍶🍷🍸🍾🍺🍼🎀🎁🎂🎃🤖"
    python tari_address_decoder.py "0001fc9e9cb2bd8f1e4cf70c1104545622cb84a9b2dd19735d20575d761d6ba9936280dd789fee2ae68aa63f09a78ccc2938cdaec33ecc909c1f86a9f654bdf15538d5"
"""

import sys
import json
import base58
import binascii
from typing import Optional, Dict, Any, List, Tuple


class TariAddressDecoder:
    # Network definitions
    NETWORKS = {
        0x00: {"name": "MainNet", "prefix": "T", "emoji": "🐢"},
        0x02: {"name": "NextNet", "prefix": "t", "emoji": "⏩"},
        0x26: {"name": "Esmeralda", "prefix": "e", "emoji": "💎"},
    }
    
    # Address features
    FEATURES = {
        0x01: "ONE_SIDED",
        0x02: "INTERACTIVE", 
        0x04: "PAYMENT_ID",
    }
    
    # Address size constants
    SINGLE_ADDRESS_SIZE = 35
    DUAL_ADDRESS_SIZE = 67
    MAX_ENCRYPTED_DATA_SIZE = 256
    
    # Emoji mapping for byte values 0-255
    EMOJI_MAP = [
        '🐢', '📟', '🌈', '🌊', '🎯', '🐋', '🌙', '🤔', '🌕', '⭐', '🎋', '🌰', '🌴', '🌵', '🌲', '🌸', '🌹', '🌻', '🌽',
        '🍀', '🍁', '🍄', '🥑', '🍆', '🍇', '🍈', '🍉', '🍊', '🍋', '🍌', '🍍', '🍎', '🍐', '🍑', '🍒', '🍓', '🍔', '🍕',
        '🍗', '🍚', '🍞', '🍟', '🥝', '🍣', '🍦', '🍩', '🍪', '🍫', '🍬', '🍭', '🍯', '🥐', '🍳', '🥄', '🍵', '🍶', '🍷',
        '🍸', '🍾', '🍺', '🍼', '🎀', '🎁', '🎂', '🎃', '🤖', '🎈', '🎉', '🎒', '🎓', '🎠', '🎡', '🎢', '🎣', '🎤', '🎥',
        '🎧', '🎨', '🎩', '🎪', '🎬', '🎭', '🎮', '🎰', '🎱', '🎲', '🎳', '🎵', '🎷', '🎸', '🎹', '🎺', '🎻', '🎼', '🎽',
        '🎾', '🎿', '🏀', '🏁', '🏆', '🏈', '⚽', '🏠', '🏥', '🏦', '🏭', '🏰', '🐀', '🐉', '🐊', '🐌', '🐍', '🦁', '🐐',
        '🐑', '🐔', '🙈', '🐗', '🐘', '🐙', '🐚', '🐛', '🐜', '🐝', '🐞', '🦋', '🐣', '🐨', '🦀', '🐪', '🐬', '🐭', '🐮',
        '🐯', '🐰', '🦆', '🦂', '🐴', '🐵', '🐶', '🐷', '🐸', '🐺', '🐻', '🐼', '🐽', '🐾', '👀', '👅', '👑', '👒', '🧢',
        '💅', '👕', '👖', '👗', '👘', '👙', '💃', '👛', '👞', '👟', '👠', '🥊', '👢', '👣', '🤡', '👻', '👽', '👾', '🤠',
        '👃', '💄', '💈', '💉', '💊', '💋', '👂', '💍', '💎', '💐', '💔', '🔒', '🧩', '💡', '💣', '💤', '💦', '💨', '💩',
        '➕', '💯', '💰', '💳', '💵', '💺', '💻', '💼', '📈', '📜', '📌', '📎', '📖', '📿', '📡', '⏰', '📱', '📷', '🔋',
        '🔌', '🚰', '🔑', '🔔', '🔥', '🔦', '🔧', '🔨', '🔩', '🔪', '🔫', '🔬', '🔭', '🔮', '🔱', '🗽', '😂', '😇', '😈',
        '🤑', '😍', '😎', '😱', '😷', '🤢', '👍', '👶', '🚀', '🚁', '🚂', '🚚', '🚑', '🚒', '🚓', '🛵', '🚗', '🚜', '🚢',
        '🚦', '🚧', '🚨', '🚪', '🚫', '🚲', '🚽', '🚿', '🧲',
    ]
    
    def __init__(self):
        # Create reverse emoji mapping
        self.emoji_to_byte = {emoji: i for i, emoji in enumerate(self.EMOJI_MAP)}
    
    def compute_damm_checksum(self, data: bytes) -> int:
        """Compute Damm checksum using the polynomial coefficients [4, 3, 1]"""
        # Calculate mask from coefficients [4, 3, 1] as: 1 + (1 << 4) + (1 << 3) + (1 << 1)
        mask = 1 + (1 << 4) + (1 << 3) + (1 << 1)  # = 0x1B
        
        result = 0
        for byte in data:
            result ^= byte  # add
            overflow = (result & (1 << 7)) != 0
            result <<= 1  # double
            result &= 0xFF  # keep it as a byte
            if overflow:
                result ^= mask  # reduce
        
        return result & 0xFF
    
    def verify_checksum(self, data_with_checksum: bytes) -> bool:
        """Verify the Damm checksum of data with appended checksum"""
        if len(data_with_checksum) == 0:
            return False
        
        data = data_with_checksum[:-1]
        checksum = data_with_checksum[-1]
        
        return self.compute_damm_checksum(data) == checksum
    
    def detect_address_format(self, address: str) -> str:
        """Detect if address is Base58, emoji, or hex format"""
        # Check if it's hex (all hex characters)
        try:
            bytes.fromhex(address)
            return "hex"
        except ValueError:
            pass
        
        # Check if it contains emoji characters
        for char in address:
            if char in self.emoji_to_byte:
                return "emoji"
        
        # Default to Base58
        return "base58"
    
    def decode_base58_address(self, address: str) -> bytes:
        """Decode Base58 address to bytes"""
        if len(address) < 2:
            raise ValueError("Address too short")
        
        # Split the address as per Rust implementation
        network_part = address[0]
        features_part = address[1] 
        rest = address[2:]
        
        # Decode each part
        network_bytes = base58.b58decode(network_part)
        features_bytes = base58.b58decode(features_part)
        rest_bytes = base58.b58decode(rest)
        
        # Combine all parts
        return network_bytes + features_bytes + rest_bytes
    
    def decode_emoji_address(self, address: str) -> bytes:
        """Decode emoji address to bytes"""
        result = []
        for char in address:
            if char in self.emoji_to_byte:
                result.append(self.emoji_to_byte[char])
            else:
                raise ValueError(f"Invalid emoji character: {char}")
        return bytes(result)
    
    def decode_hex_address(self, address: str) -> bytes:
        """Decode hex address to bytes"""
        return bytes.fromhex(address)
    
    def parse_features(self, features_byte: int) -> Dict[str, Any]:
        """Parse feature flags from byte value"""
        active_features = []
        feature_details = {}
        
        for flag, name in self.FEATURES.items():
            if features_byte & flag:
                active_features.append(name)
                feature_details[name.lower()] = True
            else:
                feature_details[name.lower()] = False
        
        return {
            "byte_value": f"0x{features_byte:02x}",
            "active_features": active_features,
            "details": feature_details
        }
    
    def bytes_to_ascii_string(self, data: bytes) -> str:
        """Convert bytes to ASCII string, replacing non-ASCII with spaces"""
        return ''.join(chr(b) if 32 <= b <= 126 else ' ' for b in data)
    
    def decode_address(self, address: str) -> Dict[str, Any]:
        """Main function to decode a Tari address and return detailed information"""
        result = {
            "input": {
                "address": address,
                "format": self.detect_address_format(address),
            },
            "valid": False,
            "error": None,
            "decoded": {}
        }
        
        try:
            # Decode based on format
            format_type = result["input"]["format"]
            if format_type == "base58":
                address_bytes = self.decode_base58_address(address)
            elif format_type == "emoji":
                address_bytes = self.decode_emoji_address(address)
            elif format_type == "hex":
                address_bytes = self.decode_hex_address(address)
            else:
                raise ValueError(f"Unknown format: {format_type}")
            
            # Verify checksum
            if not self.verify_checksum(address_bytes):
                raise ValueError("Invalid checksum")
            
            # Parse address components
            length = len(address_bytes)
            
            # Validate size
            if (length != self.SINGLE_ADDRESS_SIZE and 
                not (self.DUAL_ADDRESS_SIZE <= length <= self.DUAL_ADDRESS_SIZE + self.MAX_ENCRYPTED_DATA_SIZE)):
                raise ValueError(f"Invalid address size: {length}")
            
            # Extract network
            network_byte = address_bytes[0]
            if network_byte not in self.NETWORKS:
                raise ValueError(f"Unknown network: 0x{network_byte:02x}")
            
            network_info = self.NETWORKS[network_byte]
            
            # Extract features
            features_byte = address_bytes[1]
            features_info = self.parse_features(features_byte)
            
            # Determine address type and extract keys
            is_single_address = length == self.SINGLE_ADDRESS_SIZE
            
            if is_single_address:
                # Single address: no view key
                spend_key = address_bytes[2:34]
                view_key = None
                payment_id = None
                address_type = "Single Address"
            else:
                # Dual address: has view key
                view_key = address_bytes[2:34]
                spend_key = address_bytes[34:66]
                address_type = "Dual Address"
                
                # Extract payment ID if present
                if length > self.DUAL_ADDRESS_SIZE:
                    payment_id = address_bytes[66:-1]  # Exclude checksum
                else:
                    payment_id = None
            
            # Build result
            result["valid"] = True
            result["decoded"] = {
                "network": {
                    "name": network_info["name"],
                    "byte_value": f"0x{network_byte:02x}",
                    "base58_prefix": network_info["prefix"],
                    "emoji_prefix": network_info["emoji"]
                },
                "features": features_info,
                "address_type": address_type,
                "keys": {
                    "spend_key": {
                        "hex": spend_key.hex(),
                        "bytes": list(spend_key)
                    }
                },
                "size": {
                    "total_bytes": length,
                    "is_single_address": is_single_address
                }
            }
            
            # Add view key if present
            if view_key is not None:
                result["decoded"]["keys"]["view_key"] = {
                    "hex": view_key.hex(),
                    "bytes": list(view_key)
                }
            
            # Add payment ID if present
            if payment_id is not None and len(payment_id) > 0:
                result["decoded"]["payment_id"] = {
                    "hex": payment_id.hex(),
                    "bytes": list(payment_id),
                    "ascii": self.bytes_to_ascii_string(payment_id),
                    "length": len(payment_id)
                }
            
            # Add alternative encodings
            result["decoded"]["encodings"] = {
                "hex": address_bytes.hex(),
                "base58": self._to_base58(address_bytes),
                "emoji": self._to_emoji(address_bytes)
            }
            
        except Exception as e:
            result["error"] = str(e)
            result["valid"] = False
        
        return result
    
    def _to_base58(self, address_bytes: bytes) -> str:
        """Convert address bytes to Base58 format"""
        # Split into network, features, and rest as per Rust implementation
        network = base58.b58encode(address_bytes[0:1]).decode()
        features = base58.b58encode(address_bytes[1:2]).decode()
        rest = base58.b58encode(address_bytes[2:]).decode()
        return network + features + rest
    
    def _to_emoji(self, address_bytes: bytes) -> str:
        """Convert address bytes to emoji format"""
        return ''.join(self.EMOJI_MAP[b] for b in address_bytes)


def main():
    if len(sys.argv) != 2:
        print("Usage: python tari_address_decoder.py <address>")
        print("\nExamples:")
        print("  Base58: python tari_address_decoder.py \"12PHyR5CePL5jyoevS6BbSjV2WnNgVcmaqgZA9NqPJd3894YFzCCSHn9Auvpai1LT4LKJxH2c7yyiwuxqdkxYjACrPn\"")
        print("  Emoji:  python tari_address_decoder.py \"🐢📟⭐🌙🤔🌕⭐🎋🌰🌴🌵🌲🌸🌹🌻🌽🍀🍁🍄🥑🍆🍇🍈🍉🍊🍋🍌🍍🍎🍐🍑🍒🍓🍔🍕🍗🍚🍞🍟🥝🍣🍦🍩🍪🍫🍬🍭🍯🥐🍳🥄🍵🍶🍷🍸🍾🍺🍼🎀🎁🎂🎃🤖\"")
        print("  Hex:    python tari_address_decoder.py \"0001fc9e9cb2bd8f1e4cf70c1104545622cb84a9b2dd19735d20575d761d6ba9936280dd789fee2ae68aa63f09a78ccc2938cdaec33ecc909c1f86a9f654bdf15538d5\"")
        sys.exit(1)
    
    address = sys.argv[1]
    decoder = TariAddressDecoder()
    
    try:
        result = decoder.decode_address(address)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        error_result = {
            "input": {"address": address, "format": "unknown"},
            "valid": False,
            "error": f"Unexpected error: {str(e)}",
            "decoded": {}
        }
        print(json.dumps(error_result, indent=2, ensure_ascii=False))
        sys.exit(1)


if __name__ == "__main__":
    main() 